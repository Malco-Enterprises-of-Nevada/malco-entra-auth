'use strict';

/**
 * @malco/entra-auth — shared Microsoft Entra ID (Azure AD) OIDC auth for the Budget LV fleet.
 *
 * Born in malco-portal; written with ZERO portal-specific imports so it can be
 * extracted to its own package and vendored verbatim by the other apps.
 *
 * Contract (SSO_MASTER_PLAN.md §B) — enforced here so every vendored copy inherits it:
 *   1. State check fails CLOSED (rejects when no pending auth / missing state / missing code).
 *   2. Session regenerated BEFORE onUser grants identity (anti session-fixation).
 *   3. oid is the primary identity key (onUser binds it); email is a match hint only.
 *   4. JIT guest/domain guard — reject #EXT# UPNs and non-allowed email domains.
 *   5. returnTo open-redirect sanitizer (same-origin relative paths only).
 *   6. POST logout with id_token_hint + post_logout_redirect_uri.
 *   7. response_mode=query + PKCE S256 (avoids form_post vs global-CSRF 403s).
 *   8. State is single-use (deleted before token exchange).
 *   9. claims shape: { oid, email(lowercased), name, roles }.
 *  10. onUser may throw to deny (e.g. empty roles) -> rendered 403.
 *
 * Stateless apps (no express-session) pass a custom `stateStore` (see signedCookieStateStore).
 * Apps put `autoSignIn()` on their login page route so employees moving between fleet
 * apps are signed in automatically instead of seeing a "Sign in with Microsoft" button.
 *
 * Usage:
 *   const { createEntraAuth } = require('malco-entra-auth');
 *   app.use('/auth/microsoft', createEntraAuth({
 *     tenantId, clientId, clientSecret, redirectUri,
 *     postLogoutRedirectUri, allowedDomains: ['budgetlasvegas.com'],
 *     onUser: async (claims, req, res) => { ... establish the app's native session/JWT ... },
 *       (res is passed so JWT-cookie apps can res.cookie(...); session apps ignore it.)
 *   }));
 */

const express = require('express');
const msal = require('@azure/msal-node');
const { ssoEnabled } = require('./flags');

const MS_LOGIN = 'https://login.microsoftonline.com';

// Fixed structured event codes on the auth paths. Emitted as a `event` field so
// the observability layer (Loki rules + the Grafana auth dashboard) can match
// them by name across the fleet, independent of each app's log message text.
const SsoDeniedEvent = {
  STATE: 'SSO_LOGIN_DENIED_STATE',
  ENTRA_ERROR: 'SSO_LOGIN_DENIED_ENTRA_ERROR',
  TOKEN_EXCHANGE: 'SSO_LOGIN_DENIED_TOKEN_EXCHANGE',
  GUEST_OR_DOMAIN: 'SSO_LOGIN_DENIED_GUEST',
  ON_USER: 'SSO_LOGIN_DENIED',
};
const SSO_LOGIN_SUCCESS = 'SSO_LOGIN_SUCCESS';

/** Same-origin relative paths only. Blocks //evil.com, /\evil, absolute URLs. */
function sanitizeReturnTo(value) {
  if (typeof value !== 'string' || value.length === 0) return '/';
  if (!/^\/(?!\/)/.test(value)) return '/'; // must start with exactly one '/'
  if (value.includes('\\')) return '/';
  // URL parsers strip tab/CR/LF, so '/\t/evil.com' would resolve as '//evil.com'
  if (/[\u0000- \u007f]/.test(value)) return '/';
  return value;
}

function hasCookie(req, name) {
  const header = req.headers && req.headers.cookie;
  if (typeof header !== 'string') return false;
  return header.split(';').some((part) => part.trim().startsWith(`${name}=`));
}

const AUTO_SIGN_IN_COOKIE = 'entra_auto';
const LOCAL_LOGIN_COOKIE = 'entra_local';
const AUTO_SIGN_IN_GUARD_MS = 60 * 1000;
const LOCAL_LOGIN_STICKY_MS = 15 * 60 * 1000;

/**
 * Login-page middleware: when SSO is on, skip the app's login page and go straight to
 * `<basePath>/login`. Entra still holds the browser session from whichever fleet app the
 * employee signed in to first, so the hop completes without a prompt and they arrive
 * signed in. Falls through to the app's own login page (next()) when:
 *   - SSO is off, or the request isn't a top-level navigation (fetch, service-worker precache,
 *     or a page loading in an iframe: `Sec-Fetch-Dest` other than `document`)
 *   - `isSignedIn(req)` is true (the app's handler already forwards signed-in users)
 *   - `?local` is present (break-glass). Sticks for 15 min via a cookie so a failed local
 *     login that redirects back to the bare login page keeps showing the form.
 *   - any `skipParams` query param is present (e.g. `?signedOut=1` after an app logout)
 *   - this app already auto-redirected in the last 60s. Loop guard: a deny page that links
 *     back to a gated page, or a session cookie that didn't stick, lands on the login page.
 *
 * @param {object} [opts]
 * @param {string} [opts.basePath='/auth/microsoft']  where createEntraAuth is mounted
 * @param {function} [opts.enabled=ssoEnabled]  must only be true when the router is mounted
 * @param {function} [opts.getReturnTo]  (req) => path to land on; sanitized. Default: ?returnTo
 * @param {function} [opts.isSignedIn]  (req) => true when the app already has a session
 * @param {string[]} [opts.skipParams=['signedOut']]
 */
function autoSignIn({
  basePath = '/auth/microsoft',
  enabled = ssoEnabled,
  getReturnTo = (req) => req.query && req.query.returnTo,
  isSignedIn = () => false,
  skipParams = ['signedOut'],
} = {}) {
  // basePath '/' would otherwise give '//login', a protocol-relative URL to the host 'login'.
  // A loop, not /\/+$/: that regex is quadratic on a long run of slashes (CodeQL js/polynomial-redos).
  let base = basePath;
  while (base.endsWith('/')) base = base.slice(0, -1);
  const loginPath = `${base}/login`;
  return (req, res, next) => {
    if (req.method !== 'GET' && req.method !== 'HEAD') return next();
    if (!enabled()) return next();
    const fetchMode = req.headers && req.headers['sec-fetch-mode'];
    if (fetchMode && fetchMode !== 'navigate') return next();
    // iframes navigate too; forwarding one would set the loop guard and block the next real visit
    const fetchDest = req.headers && req.headers['sec-fetch-dest'];
    if (fetchDest && fetchDest !== 'document') return next();
    if (isSignedIn(req)) return next();

    const query = req.query || {};
    const cookieOpts = { httpOnly: true, sameSite: 'lax', secure: Boolean(req.secure), path: '/' };
    if (query.local !== undefined) {
      res.cookie(LOCAL_LOGIN_COOKIE, '1', { ...cookieOpts, maxAge: LOCAL_LOGIN_STICKY_MS });
      return next();
    }
    if (skipParams.some((p) => query[p] !== undefined)) return next();
    if (hasCookie(req, LOCAL_LOGIN_COOKIE) || hasCookie(req, AUTO_SIGN_IN_COOKIE)) return next();

    let returnTo;
    try {
      returnTo = getReturnTo(req);
    } catch {
      returnTo = '/';
    }
    res.cookie(AUTO_SIGN_IN_COOKIE, '1', { ...cookieOpts, maxAge: AUTO_SIGN_IN_GUARD_MS });
    return res.redirect(`${loginPath}?returnTo=${encodeURIComponent(sanitizeReturnTo(returnTo))}`);
  };
}

function domainAllowed(email, allowedDomains) {
  if (!allowedDomains || allowedDomains.length === 0) return true; // guard disabled
  const at = email.lastIndexOf('@');
  if (at === -1) return false;
  const domain = email.slice(at + 1).toLowerCase();
  return allowedDomains.some((d) => domain === String(d).toLowerCase());
}

/**
 * Default state store backed by express-session.
 * `data` = { state, verifier, returnTo }.
 */
const sessionStateStore = {
  async save(req, res, data) {
    req.session.entraAuth = data;
    await new Promise((resolve, reject) =>
      req.session.save((err) => (err ? reject(err) : resolve()))
    );
  },
  // Single-use: returns the pending data and removes it.
  async take(req, res) {
    const data = req.session && req.session.entraAuth;
    if (data && req.session) delete req.session.entraAuth;
    return data || null;
  },
};

/**
 * State store for STATELESS apps (JWT-only, no express-session).
 * Stores {state, verifier, returnTo} in a short-lived, signed, single-use cookie.
 * Requires cookie-parser mounted with the same `secret`.
 *
 * @param {object} opts
 * @param {string} opts.secret  signing secret (distinct from JWT bearer secret)
 * @param {boolean} [opts.secure=true]
 * @param {number} [opts.maxAgeMs=600000]  10 minutes
 * @param {string} [opts.cookieName='oidc_state']
 */
function signedCookieStateStore({ secret, secure = true, maxAgeMs = 600000, cookieName = 'oidc_state' }) {
  const crypto = require('crypto');
  const sign = (payload) => {
    const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const ts = Date.now();
    // typed so it can never be replayed as a bearer token
    const mac = crypto.createHmac('sha256', secret).update(`oidc-state.${body}.${ts}`).digest('base64url');
    return `${body}.${ts}.${mac}`;
  };
  const verify = (token) => {
    if (typeof token !== 'string') return null;
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const [body, ts, mac] = parts;
    const expected = crypto.createHmac('sha256', secret).update(`oidc-state.${body}.${ts}`).digest('base64url');
    const a = Buffer.from(mac);
    const b = Buffer.from(expected);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
    if (Date.now() - Number(ts) > maxAgeMs) return null;
    try {
      return JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    } catch {
      return null;
    }
  };
  return {
    async save(req, res, data) {
      res.cookie(cookieName, sign(data), {
        httpOnly: true,
        sameSite: 'lax',
        secure,
        maxAge: maxAgeMs,
        signed: false,
      });
    },
    async take(req, res) {
      const token = req.cookies ? req.cookies[cookieName] : undefined;
      res.clearCookie(cookieName);
      return verify(token);
    },
  };
}

function createEntraAuth(opts) {
  const {
    tenantId,
    clientId,
    clientSecret,
    redirectUri,
    scopes = ['openid', 'profile', 'email'],
    postLogoutRedirectUri,
    allowedDomains = ['budgetlasvegas.com'],
    stateStore = sessionStateStore,
    sessionCookieName = 'connect.sid',
    onUser,
    logger = console,
  } = opts || {};

  if (!tenantId || !clientId || !clientSecret || !redirectUri) {
    throw new Error('createEntraAuth: tenantId, clientId, clientSecret, redirectUri are required');
  }
  if (typeof onUser !== 'function') {
    throw new Error('createEntraAuth: onUser callback is required');
  }

  const cca = new msal.ConfidentialClientApplication({
    auth: {
      clientId,
      clientSecret,
      authority: `${MS_LOGIN}/${tenantId}`,
    },
  });
  const cryptoProvider = new msal.CryptoProvider();
  const router = express.Router();

  const denyError = (res, status, message) => {
    // Render an app-provided 'error' view if it exists; fall back to plain text
    // if the app has no such view (so a deny is always a clean status, never a
    // 500). `title` is passed for layout-based (express-ejs-layouts) apps.
    if (typeof res.render === 'function' && res.app && res.app.get('views')) {
      return res.status(status).render('error', { message, error: {}, title: 'Sign-in error' }, (err, html) => {
        if (err || typeof html !== 'string') {
          return res.type('text/plain').send(message);
        }
        return res.send(html);
      });
    }
    return res.status(status).type('text/plain').send(message);
  };

  // GET <base>/login
  router.get('/login', async (req, res, next) => {
    try {
      const { verifier, challenge } = await cryptoProvider.generatePkceCodes();
      const state = cryptoProvider.createNewGuid();
      const returnTo = sanitizeReturnTo(req.query && req.query.returnTo);
      await stateStore.save(req, res, { state, verifier, returnTo });
      const url = await cca.getAuthCodeUrl({
        scopes,
        redirectUri,
        responseMode: 'query',
        codeChallenge: challenge,
        codeChallengeMethod: 'S256',
        state,
      });
      res.redirect(url);
    } catch (err) {
      next(err);
    }
  });

  // GET <base>/callback
  router.get('/callback', async (req, res, next) => {
    let pending;
    try {
      pending = await stateStore.take(req, res); // single-use
    } catch (err) {
      return next(err);
    }

    const q = req.query || {};

    // Entra returned an explicit error (e.g. consent denied)
    if (q.error) {
      logger.warn(
        { event: SsoDeniedEvent.ENTRA_ERROR, error: q.error, desc: q.error_description },
        'Entra returned an auth error'
      );
      return denyError(res, 403, 'Sign-in was cancelled or denied.');
    }

    // (1)(8) State check fails CLOSED.
    if (
      !pending ||
      typeof q.state !== 'string' ||
      q.state.length === 0 ||
      q.state !== pending.state ||
      typeof q.code !== 'string' ||
      q.code.length === 0
    ) {
      logger.warn(
        {
          event: SsoDeniedEvent.STATE,
          hasPending: Boolean(pending),
          hasState: Boolean(q.state),
          hasCode: Boolean(q.code),
        },
        'OIDC callback rejected: state/code validation failed'
      );
      return denyError(res, 403, 'Sign-in could not be verified. Please try signing in again.');
    }

    const { verifier, returnTo } = pending;

    let tokenResponse;
    try {
      tokenResponse = await cca.acquireTokenByCode({
        code: q.code,
        scopes,
        redirectUri,
        codeVerifier: verifier,
      });
    } catch (err) {
      logger.error(
        { event: SsoDeniedEvent.TOKEN_EXCHANGE, err: err && err.message },
        'Token exchange failed'
      );
      return denyError(res, 403, 'Sign-in failed during token exchange. Please try again.');
    }

    const c = tokenResponse.idTokenClaims || {};
    const email = String(c.preferred_username || c.email || '').toLowerCase();
    const claims = {
      oid: c.oid,
      email,
      name: c.name,
      roles: Array.isArray(c.roles) ? c.roles : [],
    };

    // (4) JIT guest / domain guard.
    if (email.includes('#ext#') || !domainAllowed(email, allowedDomains)) {
      logger.warn(
        { event: SsoDeniedEvent.GUEST_OR_DOMAIN, email },
        'Denied sign-in: guest account or disallowed email domain'
      );
      return denyError(res, 403, 'This account is not permitted to sign in.');
    }

    const finish = () => {
      Promise.resolve()
        .then(() => onUser(claims, req, res, tokenResponse)) // (3)(9)(10) app establishes native session/JWT
        .then(() => {
          // (6) keep the id_token for a clean front-channel logout
          if (req.session) req.session.idTokenHint = tokenResponse.idToken;
          if (logger.info) logger.info({ event: SSO_LOGIN_SUCCESS, email }, 'SSO login succeeded');
          if (req.session && typeof req.session.save === 'function') {
            req.session.save((err) => (err ? next(err) : res.redirect(returnTo || '/')));
          } else {
            res.redirect(returnTo || '/');
          }
        })
        .catch((err) => {
          // onUser throws to deny (e.g. empty roles / not provisioned)
          logger.warn(
            { event: SsoDeniedEvent.ON_USER, err: err && err.message, email },
            'onUser denied sign-in'
          );
          return denyError(res, 403, (err && err.publicMessage) || 'Access denied.');
        });
    };

    // (2) Regenerate the session before granting privileges (anti-fixation).
    if (req.session && typeof req.session.regenerate === 'function') {
      req.session.regenerate((err) => (err ? next(err) : finish()));
    } else {
      finish();
    }
  });

  // POST <base>/logout  (POST so third parties can't force-logout)
  router.post('/logout', (req, res, next) => {
    const idTokenHint = req.session && req.session.idTokenHint;
    const params = new URLSearchParams();
    if (postLogoutRedirectUri) params.set('post_logout_redirect_uri', postLogoutRedirectUri);
    if (idTokenHint) params.set('id_token_hint', idTokenHint);
    const dest = `${MS_LOGIN}/${tenantId}/oauth2/v2.0/logout?${params.toString()}`;

    if (req.session && typeof req.session.destroy === 'function') {
      req.session.destroy((err) => {
        if (err) return next(err);
        res.clearCookie(sessionCookieName);
        res.redirect(dest);
      });
    } else {
      res.redirect(dest);
    }
  });

  return router;
}

module.exports = {
  createEntraAuth,
  autoSignIn,
  sanitizeReturnTo,
  domainAllowed,
  sessionStateStore,
  signedCookieStateStore,
  SsoDeniedEvent,
  SSO_LOGIN_SUCCESS,
};

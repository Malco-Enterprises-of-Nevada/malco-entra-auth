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
 *
 * Usage:
 *   const { createEntraAuth } = require('../lib/entra-auth');
 *   app.use('/auth/microsoft', createEntraAuth({
 *     tenantId, clientId, clientSecret, redirectUri,
 *     postLogoutRedirectUri, allowedDomains: ['budgetlasvegas.com'],
 *     onUser: async (claims, req, res) => { ... establish the app's native session/JWT ... },
 *       (res is passed so JWT-cookie apps can res.cookie(...); session apps ignore it.)
 *   }));
 */

const express = require('express');
const msal = require('@azure/msal-node');

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
  return value;
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
 * @param {string} [opts.cookieName='__Host-oidc-state']
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
  sanitizeReturnTo,
  domainAllowed,
  sessionStateStore,
  signedCookieStateStore,
  SsoDeniedEvent,
  SSO_LOGIN_SUCCESS,
};

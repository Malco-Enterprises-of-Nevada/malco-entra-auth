# malco-entra-auth

Shared Microsoft Entra ID (Azure AD) OIDC auth for the Budget Las Vegas /
Malco app fleet. Extracted verbatim from `malco-portal/lib/entra-auth`
(previously vendored into 9 apps — this package is now the single source of
truth).

The security contract lives in `malco-infra/docs/SSO_MASTER_PLAN.md` §B and is
enforced by the router:

1. State check fails **closed** (no pending auth / missing state / missing code → 403)
2. Session regenerated **before** `onUser` grants identity (anti session-fixation)
3. `oid` is the primary identity key; email is a match hint only
4. JIT guest/domain guard — rejects `#EXT#` UPNs and non-allowed email domains
5. `returnTo` open-redirect sanitizer (same-origin relative paths only)
6. POST logout with `id_token_hint` + `post_logout_redirect_uri`
7. `response_mode=query` + PKCE S256
8. State is single-use (deleted before token exchange)
9. Claims shape: `{ oid, email (lowercased), name, roles }`
10. `onUser` may throw to deny (e.g. empty roles) → rendered 403

## Install

```bash
npm install malco-entra-auth
```

`express` (4.18+ or 5.x) and `@azure/msal-node` (^7) are peer dependencies —
every fleet app already has both.

## Usage

```js
const { createEntraAuth } = require('malco-entra-auth');

app.use('/auth/microsoft', createEntraAuth({
  tenantId: process.env.ENTRA_TENANT_ID,
  clientId: process.env.ENTRA_CLIENT_ID,
  clientSecret: process.env.ENTRA_CLIENT_SECRET,
  redirectUri: process.env.ENTRA_REDIRECT_URI,
  postLogoutRedirectUri: process.env.BASE_URL,
  allowedDomains: ['budgetlasvegas.com'],
  onUser: async (claims, req, res) => {
    // establish the app's native session/JWT; throw to deny
  },
}));
```

Stateless (JWT-cookie) apps pass `stateStore: signedCookieStateStore(secret)`
instead of relying on `express-session` (see VehicleInspectionPortal).

### Automatic sign-in between fleet apps

Put `autoSignIn()` in front of the app's login page so an employee who is
already signed in to Microsoft (from the portal or any other fleet app) goes
straight through instead of clicking "Sign in with Microsoft" again:

```js
const { autoSignIn } = require('malco-entra-auth');

router.get('/login', autoSignIn({ getReturnTo: () => '/dashboard' }), renderLoginPage);
```

When SSO is on, it redirects to `<basePath>/login?returnTo=<sanitized path>`.
Entra still has the browser session, so the employee lands signed in without
a prompt. It renders the app's own login page instead when:

- SSO is off (`enabled`, default `ssoEnabled()`), or the request isn't a
  top-level navigation: a fetch, a service-worker precache, or a page loading
  in an iframe (`Sec-Fetch-Dest` other than `document`). A framed login page is
  not forwarded, so it can't set the `entra_auto` loop guard below.
- `?local` is present: the break-glass form. A 15-minute `entra_local`
  cookie keeps it showing through failed-login redirects to the bare login page.
- any `skipParams` query param is present (default `['signedOut']`). Point app
  logouts that land on the login page at `<login>?signedOut=1`, or logging out
  silently signs the employee back in.
- this app already auto-redirected in the last 60 s (`entra_auto` cookie). This
  loop guard stops a denied user, or a session cookie that didn't stick, from
  bouncing to Microsoft forever.

Options: `basePath` (default `/auth/microsoft`), `enabled`, `getReturnTo(req)`
(default `req.query.returnTo`), `isSignedIn(req)` (default `false`; when true
the request goes to the app's handler, which forwards signed-in users),
`skipParams`.

### Auth flags

```js
const { ssoEnabled, localLoginEnabled } = require('malco-entra-auth/flags');
```

`localLoginEnabled()` **fails open** until SSO is verified in prod, then is
flipped off by setting `AUTH_LOCAL_ENABLED=false`.

## Exports

`createEntraAuth`, `autoSignIn`, `signedCookieStateStore`, `sessionStateStore`,
`sanitizeReturnTo`, `domainAllowed`, `SsoDeniedEvent`, `SSO_LOGIN_SUCCESS`
(and `ssoEnabled` / `localLoginEnabled` from `malco-entra-auth/flags`).

## Release

Cut a GitHub Release — `.github/workflows/npm-publish.yml` tests and publishes
to the public npm registry using the `npm_token` repo secret (same flow as
`bluezone-hllapi`). Bump `version` in `package.json` before tagging.

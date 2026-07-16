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

`express` (4.18+ or 5.x) and `@azure/msal-node` (^3.2) are peer dependencies —
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

### Auth flags

```js
const { ssoEnabled, localLoginEnabled } = require('malco-entra-auth/flags');
```

`localLoginEnabled()` **fails open** until SSO is verified in prod, then is
flipped off by setting `AUTH_LOCAL_ENABLED=false`.

## Exports

`createEntraAuth`, `signedCookieStateStore`, `sessionStateStore`,
`sanitizeReturnTo`, `domainAllowed`, `SsoDeniedEvent`, `SSO_LOGIN_SUCCESS`
(and `ssoEnabled` / `localLoginEnabled` from `malco-entra-auth/flags`).

## Release

Cut a GitHub Release — `.github/workflows/npm-publish.yml` tests and publishes
to the public npm registry using the `npm_token` repo secret (same flow as
`bluezone-hllapi`). Bump `version` in `package.json` before tagging.

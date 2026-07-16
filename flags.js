'use strict';

/**
 * Fleet auth flags.
 *   ssoEnabled       — Entra SSO is configured and on.
 *   localLoginEnabled — break-glass fails OPEN until SSO is verified, then is flipped off.
 */
const ssoEnabled = () => process.env.ENTRA_SSO_ENABLED !== 'false' && !!process.env.ENTRA_CLIENT_ID;
const localLoginEnabled = () =>
  process.env.AUTH_LOCAL_ENABLED !== 'false' || !process.env.ENTRA_CLIENT_ID;

module.exports = { ssoEnabled, localLoginEnabled };

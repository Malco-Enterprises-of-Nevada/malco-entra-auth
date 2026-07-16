'use strict';

const express = require('express');
const request = require('supertest');
const {
  createEntraAuth,
  sanitizeReturnTo,
  domainAllowed,
  signedCookieStateStore,
} = require('..');
const { ssoEnabled, localLoginEnabled } = require('../flags');

describe('pure helpers', () => {
  test('sanitizeReturnTo blocks open redirects', () => {
    expect(sanitizeReturnTo('/dashboard')).toBe('/dashboard');
    expect(sanitizeReturnTo('//evil.com')).toBe('/');
    expect(sanitizeReturnTo('https://evil.com')).toBe('/');
    expect(sanitizeReturnTo('/\\evil')).toBe('/');
    expect(sanitizeReturnTo('')).toBe('/');
    expect(sanitizeReturnTo(undefined)).toBe('/');
  });

  test('domainAllowed enforces the allowlist', () => {
    expect(domainAllowed('a@budgetlasvegas.com', ['budgetlasvegas.com'])).toBe(true);
    expect(domainAllowed('a@gmail.com', ['budgetlasvegas.com'])).toBe(false);
    expect(domainAllowed('weird', ['budgetlasvegas.com'])).toBe(false);
  });

  test('signedCookieStateStore is exported (stateless-app support)', () => {
    expect(typeof signedCookieStateStore).toBe('function');
  });
});

describe('auth flags', () => {
  const saved = {};
  beforeEach(() => {
    for (const k of ['ENTRA_SSO_ENABLED', 'ENTRA_CLIENT_ID', 'AUTH_LOCAL_ENABLED']) {
      saved[k] = process.env[k];
      delete process.env[k];
    }
  });
  afterEach(() => {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  });

  test('ssoEnabled requires a client id', () => {
    expect(ssoEnabled()).toBe(false);
    process.env.ENTRA_CLIENT_ID = 'x';
    expect(ssoEnabled()).toBe(true);
    process.env.ENTRA_SSO_ENABLED = 'false';
    expect(ssoEnabled()).toBe(false);
  });

  test('localLoginEnabled fails open until explicitly flipped off with SSO configured', () => {
    expect(localLoginEnabled()).toBe(true); // no SSO configured -> break-glass stays on
    process.env.ENTRA_CLIENT_ID = 'x';
    expect(localLoginEnabled()).toBe(true); // still on until flipped
    process.env.AUTH_LOCAL_ENABLED = 'false';
    expect(localLoginEnabled()).toBe(false); // flipped off post-verification
  });
});

describe('router mount (session-app shape)', () => {
  const buildApp = () => {
    const app = express();
    // minimal fake session so the router's session state store works
    app.use((req, _res, next) => {
      req.session = {};
      next();
    });
    app.use(
      '/auth/microsoft',
      createEntraAuth({
        tenantId: '11111111-1111-1111-1111-111111111111',
        clientId: 'test-client-id',
        clientSecret: 'test-client-secret',
        redirectUri: 'http://localhost/auth/microsoft/callback',
        onUser: async () => {},
      })
    );
    return app;
  };

  test('callback with no pending state fails closed (403)', async () => {
    const res = await request(buildApp()).get('/auth/microsoft/callback?code=abc');
    expect(res.status).toBe(403);
  });
});

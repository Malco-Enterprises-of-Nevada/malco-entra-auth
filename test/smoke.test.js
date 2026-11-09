'use strict';

const express = require('express');
const request = require('supertest');
const {
  createEntraAuth,
  autoSignIn,
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
    expect(sanitizeReturnTo('/\t/evil.com')).toBe('/');
    expect(sanitizeReturnTo('/\n/evil.com')).toBe('/');
    expect(sanitizeReturnTo('/a b')).toBe('/');
    expect(sanitizeReturnTo('/claims?id=5&tab=notes')).toBe('/claims?id=5&tab=notes');
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

describe('autoSignIn (login page forwards straight to Microsoft)', () => {
  const buildApp = (opts = {}) => {
    const app = express();
    app.get('/login', autoSignIn({ enabled: () => true, ...opts }), (req, res) => res.send('login page'));
    return app;
  };
  const setCookies = (res) => res.headers['set-cookie'] || [];

  test('redirects to <basePath>/login carrying returnTo and sets the loop guard', async () => {
    const res = await request(buildApp()).get('/login?returnTo=%2Fclaims%3Fid%3D5');
    expect(res.status).toBe(302);
    expect(res.headers.location).toBe('/auth/microsoft/login?returnTo=%2Fclaims%3Fid%3D5');
    expect(setCookies(res).some((c) => /^entra_auto=1;.*HttpOnly/i.test(c))).toBe(true);
  });

  test('defaults returnTo to / and sanitizes open redirects', async () => {
    for (const bad of ['', '?returnTo=%2F%2Fevil.com', '?returnTo=%2F%09%2Fevil.com', '?returnTo=https%3A%2F%2Fevil.com']) {
      const res = await request(buildApp()).get(`/login${bad}`);
      expect(res.headers.location).toBe('/auth/microsoft/login?returnTo=%2F');
    }
  });

  test('honours basePath and getReturnTo (and survives a throwing getReturnTo)', async () => {
    let res = await request(
      buildApp({ basePath: '/admin/auth/microsoft', getReturnTo: () => '/admin/dashboard' })
    ).get('/login');
    expect(res.headers.location).toBe('/admin/auth/microsoft/login?returnTo=%2Fadmin%2Fdashboard');

    res = await request(
      buildApp({
        getReturnTo: () => {
          throw new Error('no session');
        },
      })
    ).get('/login');
    expect(res.headers.location).toBe('/auth/microsoft/login?returnTo=%2F');
  });

  test('strips trailing slashes from basePath so a root mount stays on this origin', async () => {
    for (const [basePath, location] of [
      ['/', '/login?returnTo=%2F'],
      ['/auth/microsoft/', '/auth/microsoft/login?returnTo=%2F'],
    ]) {
      const res = await request(buildApp({ basePath })).get('/login');
      expect(res.headers.location).toBe(location);
    }
  });

  test('renders the login page when SSO is off', async () => {
    const res = await request(buildApp({ enabled: () => false })).get('/login');
    expect(res.status).toBe(200);
    expect(res.text).toBe('login page');
  });

  test('?local shows the break-glass page and keeps showing it via a cookie', async () => {
    const res = await request(buildApp()).get('/login?local=1');
    expect(res.status).toBe(200);
    expect(setCookies(res).some((c) => /^entra_local=1;/.test(c))).toBe(true);

    const again = await request(buildApp()).get('/login').set('Cookie', 'entra_local=1');
    expect(again.status).toBe(200);
  });

  test('skipParams (default ?signedOut, plus app extras) render the login page', async () => {
    expect((await request(buildApp()).get('/login?signedOut=1')).status).toBe(200);
    expect((await request(buildApp()).get('/login?timeout=true')).status).toBe(302);
    const app = buildApp({ skipParams: ['signedOut', 'timeout'] });
    expect((await request(app).get('/login?timeout=true')).status).toBe(200);
  });

  test('isSignedIn hands signed-in users to the app handler (no Microsoft round trip)', async () => {
    const res = await request(buildApp({ isSignedIn: () => true })).get('/login');
    expect(res.status).toBe(200);
    expect(setCookies(res)).toHaveLength(0);
  });

  test('loop guard: a second hit within the guard window renders the login page', async () => {
    const res = await request(buildApp()).get('/login').set('Cookie', 'other=x; entra_auto=1');
    expect(res.status).toBe(200);
  });

  test('only top-level navigations are forwarded (not fetch / service-worker precache)', async () => {
    const app = buildApp();
    expect((await request(app).get('/login').set('Sec-Fetch-Mode', 'cors')).status).toBe(200);
    expect((await request(app).get('/login').set('Sec-Fetch-Mode', 'navigate')).status).toBe(302);
  });

  test('framed navigations render the login page without setting the loop guard', async () => {
    const app = buildApp();
    const nav = (dest) => request(app).get('/login').set('Sec-Fetch-Mode', 'navigate').set('Sec-Fetch-Dest', dest);
    const framed = await nav('iframe');
    expect(framed.status).toBe(200);
    expect(setCookies(framed)).toHaveLength(0);
    expect((await nav('document')).status).toBe(302);
  });

  test('defaults `enabled` to the ssoEnabled flag', async () => {
    const saved = { id: process.env.ENTRA_CLIENT_ID, on: process.env.ENTRA_SSO_ENABLED };
    try {
      delete process.env.ENTRA_SSO_ENABLED;
      delete process.env.ENTRA_CLIENT_ID;
      const app = express();
      app.get('/login', autoSignIn(), (req, res) => res.send('login page'));
      expect((await request(app).get('/login')).status).toBe(200);
      process.env.ENTRA_CLIENT_ID = 'x';
      expect((await request(app).get('/login')).status).toBe(302);
    } finally {
      if (saved.id === undefined) delete process.env.ENTRA_CLIENT_ID;
      else process.env.ENTRA_CLIENT_ID = saved.id;
      if (saved.on === undefined) delete process.env.ENTRA_SSO_ENABLED;
      else process.env.ENTRA_SSO_ENABLED = saved.on;
    }
  });
});

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { generateKeyPairSync } = require('node:crypto');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const jwksRsa = require('jwks-rsa');

test('Lab 4 routes retain login, refresh, registration and logout', async t => {
    // Override all credentials before loading the application; never contact Auth0.
    Object.assign(process.env, {
        AUTH0_DOMAIN: 'tenant.example',
        AUTH0_AUDIENCE: 'https://lab-api.example',
        AUTH0_CLIENT_ID: 'test-client',
        AUTH0_CLIENT_SECRET: 'test-secret',
        AUTH0_MGMT_CLIENT_ID: 'test-management-client',
        AUTH0_MGMT_CLIENT_SECRET: 'test-management-secret',
        AUTH0_MGMT_AUDIENCE: 'https://tenant.example/api/v2/',
        AUTH0_CONNECTION: 'Username-Password-Authentication',
        REFRESH_THRESHOLD_SECONDS: '60'
    });
    const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'local', use: 'sig', alg: 'RS256' };
    t.mock.method(jwksRsa.JwksClient.prototype, 'getKeys', async () => [jwk]);
    const makeToken = (expiresIn, id) => jwt.sign({ sub: 'auth0|local-user' }, privateKey, {
        algorithm: 'RS256', keyid: 'local', issuer: 'https://tenant.example/',
        audience: 'https://lab-api.example', expiresIn, jwtid: id
    });
    let loginToken = makeToken(300, 'initial');
    let loginLifetime = 300;
    let refreshToken = makeToken(600, 'refreshed');
    const grants = [];
    t.mock.method(axios, 'post', async (url, body, config) => {
        if (url === 'https://tenant.example/api/v2/users') {
            assert.equal(config.headers.Authorization, 'Bearer fake-management-token');
            assert.equal(body.connection, 'Username-Password-Authentication');
            return { data: { user_id: 'auth0|created', email: body.email } };
        }
        assert.equal(url, 'https://tenant.example/oauth/token');
        const form = new URLSearchParams(body);
        const grant = form.get('grant_type');
        grants.push(grant);
        if (grant === 'password') {
            assert.equal(form.get('audience'), process.env.AUTH0_AUDIENCE);
            assert.ok(form.get('scope').includes('offline_access'));
            return { data: { access_token: loginToken, refresh_token: 'fake-refresh',
                token_type: 'Bearer', expires_in: loginLifetime } };
        }
        if (grant === 'refresh_token') {
            assert.equal(form.get('refresh_token'), 'fake-refresh');
            return { data: { access_token: refreshToken, refresh_token: 'fake-rotated-refresh',
                expires_in: 600 } };
        }
        assert.equal(grant, 'client_credentials');
        return { data: { access_token: 'fake-management-token' } };
    });
    const app = require('../index');
    const server = app.listen(0, '127.0.0.1');
    await new Promise(resolve => server.once('listening', resolve));
    t.after(() => new Promise(resolve => server.close(resolve)));
    const base = `http://127.0.0.1:${server.address().port}`;
    const request = (route, token, body) => fetch(base + route, {
        method: body ? 'POST' : 'GET',
        headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}),
            ...(body ? { 'Content-Type': 'application/json' } : {}) },
        body: body ? JSON.stringify(body) : undefined
    });
    const login = () => request('/api/login', null, { login: 'student@example.com', password: 'test-only' });

    assert.equal((await request('/')).status, 200);
    assert.equal((await request('/api/login', null, {})).status, 400);
    assert.equal((await request('/api/register', null, {})).status, 400);
    const loggedIn = await login();
    assert.equal(loggedIn.status, 200);
    assert.equal((await loggedIn.json()).token, loginToken);
    for (const route of ['/api/me', '/api/token-status']) {
        assert.equal((await request(route)).status, 401);
        assert.equal((await request(route, 'abc.def.xyz')).status, 401);
        const response = await request(route, loginToken);
        assert.equal(response.status, 200);
        const data = await response.json();
        assert.equal(data.token, undefined);
        if (route === '/api/me') assert.equal(data.user.sub, 'auth0|local-user');
    }
    const created = await request('/api/register', null, { email: 'new@example.com', password: 'test-only' });
    assert.equal(created.status, 201);
    assert.equal((await created.json()).user.userId, 'auth0|created');

    loginToken = makeToken(30, 'near-expiry');
    loginLifetime = 30;
    assert.equal((await login()).status, 200);
    const refreshed = await request('/api/token-status', loginToken);
    assert.equal(refreshed.status, 200);
    assert.equal(refreshed.headers.get('x-new-access-token'), refreshToken);
    assert.equal((await refreshed.json()).refreshed, true);
    assert.equal((await request('/api/me', loginToken)).status, 401);
    assert.equal((await request('/api/me', refreshToken)).status, 200);
    assert.equal((await request('/api/logout', refreshToken, {})).status, 200);
    assert.equal((await request('/api/me', refreshToken)).status, 401);

    loginToken = makeToken(30, 'bad-refresh-session');
    assert.equal((await login()).status, 200);
    refreshToken = 'abc.def.xyz';
    const invalidRefresh = await request('/api/me', loginToken);
    assert.equal(invalidRefresh.status, 401);
    assert.equal(invalidRefresh.headers.get('x-new-access-token'), null);
    loginToken = makeToken(-1, 'expired');
    assert.equal((await login()).status, 401);
    loginToken = 'abc.def.xyz';
    assert.equal((await login()).status, 401);
    assert.ok(grants.includes('password'));
    assert.ok(grants.includes('refresh_token'));
    assert.ok(grants.includes('client_credentials'));
});

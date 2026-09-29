const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const http = require('node:http');
const express = require('express');

test('Authorization Code callback and error handling', async t => {
    const app = express();
    app.listen = () => {};
    const env = {
        AUTH0_DOMAIN: 'test.auth0.com', AUTH0_CLIENT_ID: 'test-client',
        AUTH0_CLIENT_SECRET: 'private-test-secret',
        AUTH0_CALLBACK_URL: 'http://localhost:3000/callback',
        AUTH0_MGMT_CLIENT_ID: 'test-management', AUTH0_MGMT_CLIENT_SECRET: 'test-management-secret'
    };
    const calls = [];
    const logs = [];
    let tokenResponse;
    let tokenError;
    let now = Date.now();
    vm.runInNewContext(fs.readFileSync(path.join(__dirname, 'index.js'), 'utf8'), {
        require: name => {
            if (name === 'dotenv') return { config() {} };
            if (name === 'express') return Object.assign(() => app, express);
            if (name === 'axios') return { async post(...args) {
                calls.push(args);
                if (tokenError) throw tokenError;
                return { data: tokenResponse };
            } };
            return require(name);
        },
        process: { env, exit() { throw new Error('Unexpected process.exit'); } },
        console: { log: (...args) => logs.push(args), error: (...args) => logs.push(args) },
        Date: class extends Date { static now() { return now; } },
        URL, URLSearchParams, __dirname
    });
    const server = http.createServer(app);
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => { server.close(); server.closeAllConnections(); });
    const origin = `http://127.0.0.1:${server.address().port}`;

    async function login() {
        const response = await fetch(`${origin}/login`, { redirect: 'manual' });
        assert.equal(response.status, 302);
        const url = new URL(response.headers.get('location'));
        assert.equal(url.origin + url.pathname, 'https://test.auth0.com/authorize');
        assert.equal(url.searchParams.get('scope'), 'openid profile email');
        assert.equal(url.searchParams.get('redirect_uri'), env.AUTH0_CALLBACK_URL);
        assert.equal(url.searchParams.get('response_type'), 'code');
        assert.equal(url.searchParams.get('response_mode'), 'query');
        assert.equal(url.searchParams.get('client_id'), env.AUTH0_CLIENT_ID);
        const cookie = response.headers.get('set-cookie');
        assert.match(cookie, /HttpOnly/);
        assert.match(cookie, /SameSite=Lax/);
        return { state: url.searchParams.get('state'), cookie: cookie.split(';')[0] };
    }
    async function callback(transaction, params) {
        const query = new URLSearchParams({ state: transaction.state, ...params });
        const response = await fetch(`${origin}/callback?${query}`, {
            headers: { Cookie: transaction.cookie }
        });
        const body = await response.text();
        assert.equal(response.headers.get('cache-control'), 'no-store');
        assert(!body.includes(env.AUTH0_CLIENT_SECRET));
        return { response, body };
    }

    tokenResponse = {
        access_token: 'access<&>', id_token: 'id-test', token_type: 'Bearer', expires_in: 3600,
        client_secret: env.AUTH0_CLIENT_SECRET, refresh_token: 'must-not-be-rendered'
    };
    const transaction = await login();
    let result = await callback(transaction, { code: 'code+with&special=characters' });
    assert.equal(result.response.status, 200);
    assert.match(result.body, /access&lt;&amp;&gt;/);
    for (const value of ['id-test', 'Bearer', '3600']) assert(result.body.includes(value));
    assert(!result.body.includes('must-not-be-rendered'));
    assert.equal(calls.length, 1);
    assert.equal(calls[0][0], 'https://test.auth0.com/oauth/token');
    assert.deepEqual(Object.fromEntries(new URLSearchParams(calls[0][1])), {
        grant_type: 'authorization_code', client_id: env.AUTH0_CLIENT_ID,
        client_secret: env.AUTH0_CLIENT_SECRET, code: 'code+with&special=characters',
        redirect_uri: env.AUTH0_CALLBACK_URL
    });
    assert.equal(calls[0][2].headers['Content-Type'], 'application/x-www-form-urlencoded');
    assert.equal(calls[0][2].maxRedirects, 0);

    result = await callback(transaction, { code: 'replay' });
    assert.equal(result.response.status, 400);
    for (const params of [{ code: 'test', state: 'wrong' }, {}, { code: '' },
        { error: 'access_denied', error_description: '<script>alert(1)</script>' }]) {
        result = await callback(await login(), params);
        assert.equal(result.response.status, 400);
        assert(!result.body.includes('<script>'));
        if (params.error) assert(result.body.includes('access_denied'));
    }
    const expired = await login();
    now += 11 * 60 * 1000;
    assert.equal((await callback(expired, { code: 'test' })).response.status, 400);
    const missingCookie = await login();
    missingCookie.cookie = '';
    assert.equal((await callback(missingCookie, { code: 'test' })).response.status, 400);
    assert.equal((await fetch(`${origin}/callback`)).status, 400);
    assert.equal(calls.length, 1, 'Invalid callbacks must not call the token endpoint');

    tokenResponse = { access_token: 'access-only', token_type: 'Bearer', expires_in: 0 };
    result = await callback(await login(), { code: 'test' });
    assert.equal(result.response.status, 200);
    assert(!result.body.includes('id_token'));

    tokenResponse = {};
    assert.equal((await callback(await login(), { code: 'test' })).response.status, 502);
    tokenError = { message: env.AUTH0_CLIENT_SECRET, response: { data: env.AUTH0_CLIENT_SECRET } };
    assert.equal((await callback(await login(), { code: 'test' })).response.status, 502);
    assert(!JSON.stringify(logs).includes(env.AUTH0_CLIENT_SECRET));
});

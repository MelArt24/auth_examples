const { test } = require('node:test');
const assert = require('node:assert/strict');
const { generateKeyPairSync, randomBytes } = require('node:crypto');
const express = require('express');
const jwt = require('jsonwebtoken');
const { createJwtValidator } = require('../auth/jwtValidator');
const { createRequireJwt } = require('../auth/requireJwt');
const { createJwe } = require('../auth/jwe');

// Temporary signing fixtures only; no application encryption keys or Auth0 calls.
const first = generateKeyPairSync('rsa', { modulusLength: 2048 });
const second = generateKeyPairSync('rsa', { modulusLength: 2048 });
const domain = 'tenant.example';
const audience = 'https://lab-api.example';
const issuer = `https://${domain}/`;
const now = () => Math.floor(Date.now() / 1000);

function sign(claims = {}, options = {}, key = first.privateKey) {
    return jwt.sign({
        sub: 'auth0|test-user', iss: issuer, aud: audience,
        exp: now() + 300, ...claims
    }, key, { algorithm: 'RS256', keyid: 'first', ...options });
}

function tamper(token) {
    const parts = token.split('.');
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url'));
    payload.role = 'admin';
    parts[1] = Buffer.from(JSON.stringify(payload)).toString('base64url');
    return parts.join('.');
}

test('JWT middleware verifies signatures and claims over HTTP', async t => {
    const secret = randomBytes(32).toString('base64url');
    const { encryptJwt, decryptJwt } = createJwe(secret);
    const requestedKids = [];
    const verifyToken = createJwtValidator({
        domain,
        audience,
        jwksClient: {
            async getSigningKey(kid) {
                requestedKids.push(kid);
                const pair = { first, second }[kid];
                if (!pair) throw new Error('Unknown signing key');
                return { getPublicKey: () => pair.publicKey };
            }
        }
    });
    const app = express();
    app.get('/protected', createRequireJwt(verifyToken, decryptJwt), (req, res) => {
        res.json({ user: { sub: req.auth.sub } });
    });
    const server = app.listen(0, '127.0.0.1');
    await new Promise(resolve => server.once('listening', resolve));
    t.after(() => new Promise(resolve => server.close(resolve)));
    const url = `http://127.0.0.1:${server.address().port}/protected`;
    const valid = sign();
    const noKid = jwt.sign({ iss: issuer, aud: audience, exp: now() + 300 },
        first.privateKey, { algorithm: 'RS256' });
    const noExpiry = jwt.sign({ iss: issuer, aud: audience },
        first.privateKey, { algorithm: 'RS256', keyid: 'first' });
    const failures = [
        ['missing header', null],
        ['wrong scheme', `Basic ${valid}`],
        ['raw token', valid],
        ['missing bearer token', 'Bearer'],
        ['extra credential', `Bearer ${valid} extra`],
        ['malformed JWT', 'Bearer abc.def.xyz'],
        ['tampered payload', `Bearer ${tamper(valid)}`],
        ['invalid signature', `Bearer ${sign({}, {}, second.privateKey)}`],
        ['unknown kid', `Bearer ${sign({}, { keyid: 'unknown' })}`],
        ['missing kid', `Bearer ${noKid}`],
        ['wrong issuer', `Bearer ${sign({ iss: 'https://other.example/' })}`],
        ['issuer missing trailing slash', `Bearer ${sign({ iss: issuer.slice(0, -1) })}`],
        ['wrong audience', `Bearer ${sign({ aud: 'other-api' })}`],
        ['missing issuer', `Bearer ${sign({ iss: undefined })}`],
        ['missing audience', `Bearer ${sign({ aud: undefined })}`],
        ['expired', `Bearer ${sign({ exp: now() - 1 })}`],
        ['future nbf', `Bearer ${sign({ nbf: now() + 300 })}`],
        ['missing expiration', `Bearer ${noExpiry}`],
        ['RS384', `Bearer ${sign({}, { algorithm: 'RS384' })}`],
        ['HS256', `Bearer ${sign({}, { algorithm: 'HS256' }, 'test-only-secret')}`],
        ['unsigned', `Bearer ${sign({}, { algorithm: 'none' }, null)}`]
    ];

    // Preserve every original inner-JWT assertion inside a correctly encrypted JWE.
    const encryptedFailures = await Promise.all(failures.map(async ([name, value]) => [
        name,
        value?.startsWith('Bearer ') && name !== 'extra credential'
            ? `Bearer ${await encryptJwt(value.slice(7))}` : value
    ]));
    const encrypted = await encryptJwt(valid);
    function modifyPart(index) {
        const parts = encrypted.split('.');
        const bytes = Buffer.from(parts[index], 'base64url');
        bytes[0] ^= 1;
        parts[index] = bytes.toString('base64url');
        return parts.join('.');
    }
    const { CompactEncrypt } = await import('jose');
    async function withHeader(header) {
        return new CompactEncrypt(new TextEncoder().encode(valid))
            .setProtectedHeader(header).encrypt(Buffer.from(secret, 'base64url'));
    }
    encryptedFailures.push(
        ['raw JWS bearer', `Bearer ${valid}`],
        ['malformed JWE', 'Bearer abc..def.ghi.xyz'],
        ['extra JWE credential', `Bearer ${encrypted} extra`],
        ['tampered ciphertext', `Bearer ${modifyPart(3)}`],
        ['tampered authentication tag', `Bearer ${modifyPart(4)}`],
        ['tampered IV', `Bearer ${modifyPart(2)}`],
        ['wrong encryption key', `Bearer ${await createJwe(randomBytes(32).toString('base64url')).encryptJwt(valid)}`],
        ['wrong content type', `Bearer ${await withHeader({ alg: 'dir', enc: 'A256GCM', cty: 'text/plain' })}`],
        ['missing content type', `Bearer ${await withHeader({ alg: 'dir', enc: 'A256GCM' })}`],
        ['unsupported JWE enc', `Bearer ${await withHeader({ alg: 'dir', enc: 'A128CBC-HS256', cty: 'JWT' })}`],
        ['unsupported JWE alg', `Bearer ${await withHeader({ alg: 'A256KW', enc: 'A256GCM', cty: 'JWT' })}`]
    );

    for (const [name, authorization] of encryptedFailures) {
        await t.test(name, async () => {
            const response = await fetch(url, {
                headers: authorization ? { Authorization: authorization } : {}
            });
            assert.equal(response.status, 401);
            assert.equal(response.headers.get('www-authenticate'), 'Bearer');
            assert.deepEqual(await response.json(), {
                authenticated: false, error: 'Unauthorized'
            });
        });
    }

    for (const [name, token] of [
        ['valid token', valid],
        ['audience array', sign({ aud: ['other-api', audience] })],
        ['rotated key', sign({}, { keyid: 'second' }, second.privateKey)]
    ]) {
        await t.test(name, async () => {
            const response = await fetch(url, {
                headers: { Authorization: `bearer ${await encryptJwt(token)}` }
            });
            assert.equal(response.status, 200);
            assert.deepEqual(await response.json(), { user: { sub: 'auth0|test-user' } });
        });
    }
    assert.ok(requestedKids.includes('first'));
    assert.ok(requestedKids.includes('second'));

    await t.test('JWKS outage rejects safely', async () => {
        const failing = createJwtValidator({ domain, audience, jwksClient: {
            async getSigningKey() { throw new Error('Network failure'); }
        } });
        await assert.rejects(failing(valid), /Signing key unavailable/);
    });
    await t.test('unsupported algorithm does not trigger key lookup', async () => {
        const count = requestedKids.length;
        await assert.rejects(verifyToken(sign({}, { algorithm: 'RS384' })));
        assert.equal(requestedKids.length, count);
    });
});

test('validator rejects missing or malformed server configuration', () => {
    assert.throws(() => createJwtValidator({ domain }));
    assert.throws(() => createJwtValidator({ domain: 'https://tenant.example/', audience }));
});

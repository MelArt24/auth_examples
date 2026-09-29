const { test } = require('node:test');
const assert = require('node:assert/strict');
const { randomBytes, generateKeyPairSync } = require('node:crypto');
const { spawnSync } = require('node:child_process');
const path = require('node:path');
const jwt = require('jsonwebtoken');
const { createJwe } = require('../auth/jwe');

test('compact JWE hides the entire JWS and round-trips without changing it', async () => {
    const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const inner = jwt.sign({ sub: 'auth0|student', iss: 'https://tenant.example/',
        aud: 'https://lab-api.example' }, privateKey,
    { algorithm: 'RS256', keyid: 'example', expiresIn: 300 });
    const { encryptJwt, decryptJwt } = createJwe(randomBytes(32).toString('base64url'));
    const first = await encryptJwt(inner);
    const second = await encryptJwt(inner);
    const parts = first.split('.');
    assert.equal(inner.split('.').length, 3);
    assert.equal(parts.length, 5);
    assert.equal(parts[1], ''); // dir has no encrypted key component.
    assert.deepEqual(JSON.parse(Buffer.from(parts[0], 'base64url')), {
        alg: 'dir', enc: 'A256GCM', cty: 'JWT'
    });
    assert.notEqual(first, second);
    assert.notEqual(parts[2], second.split('.')[2]); // Fresh IV per encryption.
    assert.equal(await decryptJwt(first), inner);
    assert.equal(await decryptJwt(second), inner);
    assert.ok(!first.includes(inner.split('.')[1]));
    for (const part of parts) {
        const decoded = Buffer.from(part, 'base64url').toString('utf8');
        for (const claim of ['"sub"', '"iss"', '"aud"', 'auth0|student']) {
            assert.ok(!decoded.includes(claim));
        }
    }
});

test('JWE key configuration rejects missing, invalid and incorrectly sized keys', async t => {
    const valid = randomBytes(32).toString('base64url');
    const invalidKeys = [undefined, null, '', '<32-byte-base64url-key>',
        '!', 'A'.repeat(42) + '+', 'A'.repeat(42) + '/', valid + '=',
        ' ' + valid, valid + '\n', randomBytes(31).toString('base64url'),
        randomBytes(33).toString('base64url'), 'A'.repeat(42) + 'B'];
    for (const [index, value] of invalidKeys.entries()) {
        await t.test(`invalid configuration ${index + 1}`, () => {
            assert.throws(() => createJwe(value), /JWE_SECRET_KEY must be exactly 32 bytes/);
        });
    }
    assert.doesNotThrow(() => createJwe(valid));
});

test('application refuses to start without a valid JWE key', () => {
    for (const secret of ['', 'invalid']) {
        const result = spawnSync(process.execPath, ['index.js'], {
            cwd: path.join(__dirname, '..'),
            encoding: 'utf8',
            timeout: 5000,
            env: { ...process.env, JWE_SECRET_KEY: secret,
                AUTH0_DOMAIN: 'tenant.example', AUTH0_AUDIENCE: 'https://lab-api.example',
                AUTH0_CLIENT_ID: 'test', AUTH0_CLIENT_SECRET: 'test',
                AUTH0_MGMT_CLIENT_ID: 'test', AUTH0_MGMT_CLIENT_SECRET: 'test' }
        });
        assert.equal(result.error, undefined);
        assert.notEqual(result.status, 0);
        assert.match(result.stderr, /JWE_SECRET_KEY must be exactly 32 bytes/);
        assert.ok(!result.stdout.includes('Server:'));
    }
});

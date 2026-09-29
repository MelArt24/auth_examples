function createJwe(secret) {
    const configurationError =
        'JWE_SECRET_KEY must be exactly 32 bytes encoded as unpadded base64url';

    if (typeof secret !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(secret)) {
        throw new Error(configurationError);
    }

    const key = Buffer.from(secret, 'base64url');
    if (key.length !== 32 || key.toString('base64url') !== secret) {
        throw new Error(configurationError);
    }

    async function encryptJwt(jwt) {
        const { CompactEncrypt } = await import('jose');

        return new CompactEncrypt(new TextEncoder().encode(jwt))
            .setProtectedHeader({ alg: 'dir', enc: 'A256GCM', cty: 'JWT' })
            .encrypt(key);
    }

    async function decryptJwt(jwe) {
        const { compactDecrypt } = await import('jose');
        const { plaintext, protectedHeader } = await compactDecrypt(jwe, key, {
            keyManagementAlgorithms: ['dir'],
            contentEncryptionAlgorithms: ['A256GCM']
        });

        if (protectedHeader.cty !== 'JWT') {
            throw new Error('Invalid nested JWT content type');
        }

        return new TextDecoder('utf-8', { fatal: true }).decode(plaintext);
    }

    return { encryptJwt, decryptJwt };
}

module.exports = { createJwe };

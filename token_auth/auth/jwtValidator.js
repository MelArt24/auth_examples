const jwt = require('jsonwebtoken');
const jwksRsa = require('jwks-rsa');

function createJwtValidator({ domain, audience, jwksClient }) {
    if (!domain || !/^[a-zA-Z0-9.-]+$/.test(domain) || !audience) {
        throw new Error('AUTH0_DOMAIN must be a hostname and AUTH0_AUDIENCE is required');
    }

    const issuer = `https://${domain}/`;
    const client = jwksClient || jwksRsa({
        jwksUri: `${issuer}.well-known/jwks.json`,
        cache: true,
        cacheMaxAge: 600000,
        rateLimit: true,
        jwksRequestsPerMinute: 10,
        timeout: 5000
    });

    function getSigningKey(header, callback) {
        if (header.alg !== 'RS256' ||
            typeof header.kid !== 'string' || !header.kid.trim()) {
            return callback(new Error('Invalid signing header'));
        }

        client.getSigningKey(header.kid)
            .then(key => callback(null, key.getPublicKey()))
            .catch(() => callback(new Error('Signing key unavailable')));
    }

    return function verifyToken(token) {
        return new Promise((resolve, reject) => {
            jwt.verify(token, getSigningKey, {
                algorithms: ['RS256'],
                issuer,
                audience
            }, (error, claims) => {
                if (error) {
                    return reject(error);
                }

                if (!claims || typeof claims !== 'object' ||
                    !Number.isFinite(claims.exp)) {
                    return reject(new Error('Token expiration is required'));
                }

                resolve(claims);
            });
        });
    };
}

module.exports = { createJwtValidator };

function getAccessToken(req) {
    const header = req.get('Authorization');
    const match = typeof header === 'string'
        ? /^Bearer +([^\s,]+)$/i.exec(header)
        : null;

    return match ? match[1] : null;
}

function unauthorized(res) {
    return res.status(401)
        .set('WWW-Authenticate', 'Bearer')
        .json({ authenticated: false, error: 'Unauthorized' });
}

function createRequireJwt(verifyToken, decryptJwt) {
    return async function requireJwt(req, res, next) {
        const token = getAccessToken(req);

        if (!token) {
            return unauthorized(res);
        }

        try {
            const innerAccessToken = await decryptJwt(token);
            req.auth = await verifyToken(innerAccessToken);
            req.encryptedToken = token;
            req.innerAccessToken = innerAccessToken;
        } catch {
            return unauthorized(res);
        }

        next();
    };
}

module.exports = { createRequireJwt, getAccessToken, unauthorized };

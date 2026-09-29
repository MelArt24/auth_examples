require('dotenv').config();

const express = require('express');
const axios = require('axios');
const path = require('path');
const { createJwtValidator } = require('./auth/jwtValidator');
const { createJwe } = require('./auth/jwe');
const { createRequireJwt, getAccessToken, unauthorized } = require('./auth/requireJwt');

const app = express();

const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const AUTH0_DOMAIN = process.env.AUTH0_DOMAIN;

const AUTH0_CLIENT_ID = process.env.AUTH0_CLIENT_ID;
const AUTH0_CLIENT_SECRET = process.env.AUTH0_CLIENT_SECRET;
const AUTH0_AUDIENCE = process.env.AUTH0_AUDIENCE;

const AUTH0_MGMT_CLIENT_ID =
    process.env.AUTH0_MGMT_CLIENT_ID;

const AUTH0_MGMT_CLIENT_SECRET =
    process.env.AUTH0_MGMT_CLIENT_SECRET;

const AUTH0_MGMT_AUDIENCE =
    process.env.AUTH0_MGMT_AUDIENCE ||
    `https://${AUTH0_DOMAIN}/api/v2/`;

const AUTH0_CONNECTION =
    process.env.AUTH0_CONNECTION ||
    'Username-Password-Authentication';

const REFRESH_THRESHOLD_SECONDS =
    Number(process.env.REFRESH_THRESHOLD_SECONDS || 60);

const REFRESH_THRESHOLD_MS =
    REFRESH_THRESHOLD_SECONDS * 1000;

const AUTH0_TOKEN_URL =
    `https://${AUTH0_DOMAIN}/oauth/token`;

const AUTH0_USERS_URL =
    `https://${AUTH0_DOMAIN}/api/v2/users`;

const requiredVariables = [
    'AUTH0_DOMAIN',
    'AUTH0_AUDIENCE',
    'AUTH0_CLIENT_ID',
    'AUTH0_CLIENT_SECRET',
    'AUTH0_MGMT_CLIENT_ID',
    'AUTH0_MGMT_CLIENT_SECRET'
];

const missingVariables =
    requiredVariables.filter(
        variable => !process.env[variable]
    );

if (missingVariables.length > 0) {
    console.error(
        'Missing environment variables:',
        missingVariables.join(', ')
    );

    process.exit(1);
}

const sessions = new Map();
const verifyToken = createJwtValidator({
    domain: AUTH0_DOMAIN,
    audience: AUTH0_AUDIENCE
});
const { encryptJwt, decryptJwt } = createJwe(process.env.JWE_SECRET_KEY);
const requireJwt = createRequireJwt(verifyToken, decryptJwt);


function calculateExpiresAt(expiresIn) {
    if (!expiresIn) {
        return null;
    }

    return Date.now() + expiresIn * 1000;
}


function getRemainingSeconds(expiresAt) {
    if (!expiresAt) {
        return null;
    }

    return Math.max(
        0,
        Math.floor(
            (expiresAt - Date.now()) / 1000
        )
    );
}

async function loginWithAuth0(
    username,
    password
) {
    const body = new URLSearchParams();

    body.append(
        'grant_type',
        'password'
    );

    body.append(
        'username',
        username
    );

    body.append(
        'password',
        password
    );

    body.append(
        'client_id',
        AUTH0_CLIENT_ID
    );

    body.append(
        'client_secret',
        AUTH0_CLIENT_SECRET
    );

    body.append(
        'scope',
        'openid profile email offline_access'
    );

    if (AUTH0_AUDIENCE) {
        body.append(
            'audience',
            AUTH0_AUDIENCE
        );
    }

    const response =
        await axios.post(
            AUTH0_TOKEN_URL,
            body.toString(),
            {
                headers: {
                    'Content-Type':
                        'application/x-www-form-urlencoded'
                }
            }
        );

    return response.data;
}

async function refreshAuth0Token(
    refreshToken
) {
    const body = new URLSearchParams();

    body.append(
        'grant_type',
        'refresh_token'
    );

    body.append(
        'client_id',
        AUTH0_CLIENT_ID
    );

    body.append(
        'client_secret',
        AUTH0_CLIENT_SECRET
    );

    body.append(
        'refresh_token',
        refreshToken
    );

    const response =
        await axios.post(
            AUTH0_TOKEN_URL,
            body.toString(),
            {
                headers: {
                    'Content-Type':
                        'application/x-www-form-urlencoded'
                }
            }
        );

    return response.data;
}

async function getManagementToken() {
    const body = new URLSearchParams();

    body.append(
        'grant_type',
        'client_credentials'
    );

    body.append(
        'client_id',
        AUTH0_MGMT_CLIENT_ID
    );

    body.append(
        'client_secret',
        AUTH0_MGMT_CLIENT_SECRET
    );

    body.append(
        'audience',
        AUTH0_MGMT_AUDIENCE
    );

    const response =
        await axios.post(
            AUTH0_TOKEN_URL,
            body.toString(),
            {
                headers: {
                    'Content-Type':
                        'application/x-www-form-urlencoded'
                }
            }
        );

    return response.data.access_token;
}

async function createAuth0User(
    email,
    password
) {
    const managementToken =
        await getManagementToken();

    const response =
        await axios.post(
            AUTH0_USERS_URL,
            {
                email,
                password,
                connection: AUTH0_CONNECTION
            },
            {
                headers: {
                    Authorization:
                        `Bearer ${managementToken}`,

                    'Content-Type':
                        'application/json'
                }
            }
        );

    return response.data;
}

async function refreshSessionIfNeeded(
    currentEncryptedToken,
    session
) {
    if (!session.expiresAt) {
        return {
            encryptedToken:
            currentEncryptedToken,

            session,

            refreshed: false
        };
    }

    const remainingMs =
        session.expiresAt - Date.now();

    if (
        remainingMs >
        REFRESH_THRESHOLD_MS
    ) {
        return {
            encryptedToken:
            currentEncryptedToken,

            session,

            refreshed: false
        };
    }

    console.log(
        '---------------------------------------'
    );

    console.log(
        'Access token is close to expiration.'
    );

    console.log(
        'Remaining:',
        Math.max(
            0,
            Math.floor(remainingMs / 1000)
        ),
        'seconds'
    );

    if (!session.refreshToken) {
        console.log(
            'Refresh token is not available.'
        );

        throw new Error(
            'Refresh token is missing'
        );
    }

    console.log(
        'Refreshing access token...'
    );

    const refreshResult =
        await refreshAuth0Token(
            session.refreshToken
        );

    const newAccessToken =
        refreshResult.access_token;

    if (!newAccessToken) {
        throw new Error(
            'Auth0 did not return new access token'
        );
    }

    const claims = await verifyToken(newAccessToken);
    const newEncryptedToken = await encryptJwt(newAccessToken);

    const newRefreshToken =
        refreshResult.refresh_token ||
        session.refreshToken;

    const newExpiresAt =
        calculateExpiresAt(
            refreshResult.expires_in
        );

    const updatedSession = {
        ...session,

        innerAccessToken:
        newAccessToken,

        refreshToken:
        newRefreshToken,

        expiresAt:
        newExpiresAt
    };

    sessions.delete(
        currentEncryptedToken
    );

    sessions.set(
        newEncryptedToken,
        updatedSession
    );

    console.log(
        'Access token refreshed successfully.'
    );

    console.log(
        'New lifetime:',
        refreshResult.expires_in,
        'seconds'
    );

    console.log(
        '---------------------------------------'
    );

    return {
        encryptedToken:
        newEncryptedToken,

        session:
        updatedSession,

        refreshed: true,
        claims
    };
}

async function requireAuthentication(
    req,
    res,
    next
) {
    const encryptedToken = req.encryptedToken;

    if (!encryptedToken) {
        return unauthorized(res);
    }

    const session =
        sessions.get(encryptedToken);

    if (!session) {
        return unauthorized(res);
    }

    try {
        const result =
            await refreshSessionIfNeeded(
                encryptedToken,
                session
            );

        req.session =
            result.session;

        req.encryptedToken = result.encryptedToken;
        req.innerAccessToken = result.session.innerAccessToken;

        req.tokenRefreshed =
            result.refreshed;

        if (result.refreshed) {
            req.auth = result.claims;
            res.set(
                'X-New-Access-Token',
                result.encryptedToken
            );
        }

        next();

    } catch (error) {
        console.error(
            'Token refresh failed:',
            'Unable to refresh or validate the session token'
        );

        sessions.delete(
            encryptedToken
        );

        return unauthorized(res);
    }
}

app.get('/', (req, res) => {
    res.sendFile(
        path.join(
            __dirname,
            'index.html'
        )
    );
});

app.post(
    '/api/login',
    async (req, res) => {

        const {
            login,
            password
        } = req.body;

        if (!login || !password) {
            return res
                .status(400)
                .json({
                    message:
                        'Email and password are required'
                });
        }

        try {
            console.log(
                'Sending login request to Auth0...'
            );

            console.log(
                `User: ${login}`
            );

            const authResult =
                await loginWithAuth0(
                    login,
                    password
                );

            const accessToken =
                authResult.access_token;

            const refreshToken =
                authResult.refresh_token;

            if (!accessToken) {
                return res
                    .status(500)
                    .json({
                        message:
                            'Auth0 did not return access token'
                    });
            }

            await verifyToken(accessToken);
            const encryptedToken = await encryptJwt(accessToken);

            const expiresAt =
                calculateExpiresAt(
                    authResult.expires_in
                );

            const session = {
                username:
                login,

                innerAccessToken: accessToken,

                refreshToken,

                expiresAt
            };

            sessions.set(
                encryptedToken,
                session
            );

            console.log(
                '---------------------------------------'
            );

            console.log(
                'Login successful'
            );

            console.log(
                `User: ${login}`
            );

            console.log(
                'Expires in:',
                authResult.expires_in,
                'seconds'
            );

            console.log(
                'Refresh token received:',
                Boolean(refreshToken)
            );

            console.log(
                '---------------------------------------'
            );

            return res.json({
                authenticated: true,

                username:
                login,

                token:
                encryptedToken,

                tokenType:
                authResult.token_type,

                expiresIn:
                authResult.expires_in,

                refreshEnabled:
                    Boolean(refreshToken)
            });

        } catch (error) {
            console.error(
                'Auth0 login error:',
                'Authentication or access-token validation failed'
            );

            const message =
                error.response
                    ?.data
                    ?.error_description ||
                error.response
                    ?.data
                    ?.message ||
                'Authentication failed';

            return res
                .status(401)
                .json({
                    authenticated: false,
                    message
                });
        }
    }
);

app.post(
    '/api/register',
    async (req, res) => {

        const {
            email,
            password
        } = req.body;

        if (!email || !password) {
            return res
                .status(400)
                .json({
                    message:
                        'Email and password are required'
                });
        }

        try {
            console.log(
                `Creating Auth0 user: ${email}`
            );

            const user =
                await createAuth0User(
                    email,
                    password
                );

            console.log(
                'User created successfully:',
                user.user_id
            );

            return res
                .status(201)
                .json({
                    success: true,

                    message:
                        'User successfully created',

                    user: {
                        userId:
                        user.user_id,

                        email:
                        user.email
                    }
                });

        } catch (error) {
            console.error(
                'Create user error:',
                'Auth0 user creation request failed'
            );

            const auth0Message =
                error.response
                    ?.data
                    ?.message ||
                'Unable to create user';

            return res
                .status(
                    error.response?.status ||
                    500
                )
                .json({
                    success: false,
                    message:
                    auth0Message
                });
        }
    }
);

app.get(
    '/api/me',
    requireJwt,
    requireAuthentication,
    (req, res) => {

        const remainingSeconds =
            getRemainingSeconds(
                req.session.expiresAt
            );

        return res.json({
            authenticated: true,

            user: { sub: req.auth.sub },

            username:
            req.session.username,

            expiresAt:
            req.session.expiresAt,

            remainingSeconds,

            refreshed:
            req.tokenRefreshed
        });
    }
);

app.get(
    '/api/token-status',
    requireJwt,
    requireAuthentication,
    (req, res) => {

        return res.json({
            valid: true,

            refreshed:
            req.tokenRefreshed,

            expiresAt:
            req.session.expiresAt,

            remainingSeconds:
                getRemainingSeconds(
                    req.session.expiresAt
                ),

            refreshThresholdSeconds:
            REFRESH_THRESHOLD_SECONDS
        });
    }
);

app.post(
    '/api/logout',
    (req, res) => {

        const encryptedToken =
            getAccessToken(req);

        if (encryptedToken) {
            sessions.delete(
                encryptedToken
            );
        }

        console.log(
            'User logged out'
        );

        return res.json({
            success: true
        });
    }
);

if (require.main === module) {
    app.listen(
        PORT,
        () => {
            console.log(
                '======================================='
            );

            console.log(
                'Auth0 Token Authentication'
            );

            console.log(
                `Server: http://localhost:${PORT}`
            );

            console.log(
                `Auth0 domain: ${AUTH0_DOMAIN}`
            );

            console.log(
                `Refresh threshold: ${REFRESH_THRESHOLD_SECONDS} sec`
            );

            console.log(
                '======================================='
            );
        }
    );
}

module.exports = app;

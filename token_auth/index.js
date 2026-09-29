require('dotenv').config();

const express = require('express');
const axios = require('axios');
const path = require('path');
const { randomBytes } = require('crypto');

const app = express();

const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const AUTH0_DOMAIN = process.env.AUTH0_DOMAIN;

const AUTH0_CLIENT_ID = process.env.AUTH0_CLIENT_ID;
const AUTH0_CLIENT_SECRET = process.env.AUTH0_CLIENT_SECRET;
const AUTH0_CALLBACK_URL = process.env.AUTH0_CALLBACK_URL;

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
    'AUTH0_CLIENT_ID',
    'AUTH0_CALLBACK_URL',
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
const pendingLogins = new Map();
const STATE_COOKIE = 'auth0_login_state';
const STATE_TTL_MS = 10 * 60 * 1000;
const stateCookieOptions = {
    httpOnly: true,
    sameSite: 'lax',
    secure: AUTH0_CALLBACK_URL.startsWith('https://'),
    path: '/callback'
};

function escapeHtml(value) {
    return String(value).replace(/[&<>"']/g, character => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;',
        '"': '&quot;', "'": '&#39;'
    }[character]));
}

function sendCallbackPage(res, status, title, values) {
    const rows = Object.entries(values).map(([label, value]) =>
        `<dt>${escapeHtml(label)}</dt><dd><pre>${escapeHtml(value)}</pre></dd>`
    ).join('');

    return res.status(status).type('html').send(`<!DOCTYPE html>
<html lang="uk">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)}</title></head>
<body><h1>${escapeHtml(title)}</h1><dl>${rows}</dl>
<a href="/login">Увійти знову</a> | <a href="/">На головну</a></body>
</html>`);
}

function getAccessToken(req) {
    const authorizationHeader =
        req.get('Authorization');

    if (!authorizationHeader) {
        return null;
    }

    if (
        authorizationHeader.startsWith('Bearer ')
    ) {
        return authorizationHeader.substring(7);
    }

    return authorizationHeader;
}


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
    currentAccessToken,
    session
) {
    if (!session.expiresAt) {
        return {
            accessToken:
            currentAccessToken,

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
            accessToken:
            currentAccessToken,

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

    const newRefreshToken =
        refreshResult.refresh_token ||
        session.refreshToken;

    const newExpiresAt =
        calculateExpiresAt(
            refreshResult.expires_in
        );

    const updatedSession = {
        ...session,

        accessToken:
        newAccessToken,

        refreshToken:
        newRefreshToken,

        expiresAt:
        newExpiresAt
    };

    sessions.delete(
        currentAccessToken
    );

    sessions.set(
        newAccessToken,
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
        accessToken:
        newAccessToken,

        session:
        updatedSession,

        refreshed: true
    };
}

async function requireAuthentication(
    req,
    res,
    next
) {
    const accessToken =
        getAccessToken(req);

    if (!accessToken) {
        return res.status(401).json({
            authenticated: false,
            message:
                'Authorization token is required'
        });
    }

    const session =
        sessions.get(accessToken);

    if (!session) {
        return res.status(401).json({
            authenticated: false,
            message:
                'Session not found. Please log in again.'
        });
    }

    try {
        const result =
            await refreshSessionIfNeeded(
                accessToken,
                session
            );

        req.session =
            result.session;

        req.accessToken =
            result.accessToken;

        req.tokenRefreshed =
            result.refreshed;

        if (result.refreshed) {
            res.set(
                'X-New-Access-Token',
                result.accessToken
            );
        }

        next();

    } catch (error) {
        console.error(
            'Token refresh failed:',
            error.response?.data ||
            error.message
        );

        sessions.delete(
            accessToken
        );

        return res.status(401).json({
            authenticated: false,
            message:
                'Session expired. Please log in again.'
        });
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

app.get('/login', (req, res) => {
    for (const [state, expiresAt] of pendingLogins) {
        if (expiresAt <= Date.now()) pendingLogins.delete(state);
    }
    const state = randomBytes(32).toString('hex');
    pendingLogins.set(state, Date.now() + STATE_TTL_MS);
    res.cookie(STATE_COOKIE, state, { ...stateCookieOptions, maxAge: STATE_TTL_MS });
    res.set('Cache-Control', 'no-store');
    const authorizeUrl = new URL('/authorize', `https://${AUTH0_DOMAIN}`);

    authorizeUrl.search = new URLSearchParams({
        client_id: AUTH0_CLIENT_ID,
        redirect_uri: AUTH0_CALLBACK_URL,
        response_type: 'code',
        response_mode: 'query',
        scope: 'openid profile email',
        state
    }).toString();

    res.redirect(authorizeUrl.toString());
});

app.get('/callback', async (req, res) => {
    res.set({
        'Cache-Control': 'no-store',
        'Referrer-Policy': 'no-referrer',
        'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
        'X-Content-Type-Options': 'nosniff'
    });

    const { code, state, error, error_description: errorDescription } = req.query;
    const cookieState = (req.get('Cookie') || '').split(';')
        .map(cookie => cookie.trim())
        .find(cookie => cookie.startsWith(`${STATE_COOKIE}=`))
        ?.slice(STATE_COOKIE.length + 1);
    const expiresAt = typeof state === 'string' ? pendingLogins.get(state) : undefined;

    if (!expiresAt || expiresAt <= Date.now() || state !== cookieState) {
        return sendCallbackPage(res, 400, 'Authorization error', {
            message: 'Invalid or expired state. Start the login process from /login.'
        });
    }

    pendingLogins.delete(state);
    res.clearCookie(STATE_COOKIE, stateCookieOptions);

    if (error !== undefined || errorDescription !== undefined) {
        const redact = value => String(value).split(AUTH0_CLIENT_SECRET).join('[redacted]');
        return sendCallbackPage(res, 400, 'Auth0 rejected the authorization', {
            error: typeof error === 'string' ? redact(error) : 'authorization_error',
            error_description: typeof errorDescription === 'string'
                ? redact(errorDescription) : 'Auth0 did not provide an error description.'
        });
    }

    if (typeof code !== 'string' || !code.trim()) {
        return sendCallbackPage(res, 400, 'Authorization error', {
            message: 'Authorization code is invalid or absent.'
        });
    }

    try {
        const body = new URLSearchParams({
            grant_type: 'authorization_code',
            client_id: AUTH0_CLIENT_ID,
            client_secret: AUTH0_CLIENT_SECRET,
            code,
            redirect_uri: AUTH0_CALLBACK_URL
        });
        const { data } = await axios.post(AUTH0_TOKEN_URL, body.toString(), {
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            timeout: 10000,
            maxRedirects: 0
        });

        if (!data || typeof data.access_token !== 'string' || !data.access_token) {
            throw new Error('Missing access token');
        }

        const result = { access_token: data.access_token };
        if (typeof data.id_token === 'string' && data.id_token) {
            result.id_token = data.id_token;
        }
        result.token_type = data.token_type ?? 'Not returned';
        result.expires_in = data.expires_in ?? 'Not returned';
        return sendCallbackPage(res, 200, 'Successful authorization', result);
    } catch {
        return sendCallbackPage(res, 502, 'Error retrieving tokens', {
            message: 'Failed to exchange the authorization code for tokens. Please start the login process again.'
        });
    }
});

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
                error.response?.data ||
                error.message
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
    requireAuthentication,
    (req, res) => {

        const remainingSeconds =
            getRemainingSeconds(
                req.session.expiresAt
            );

        return res.json({
            authenticated: true,

            username:
            req.session.username,

            token:
            req.accessToken,

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
    requireAuthentication,
    (req, res) => {

        return res.json({
            valid: true,

            token:
            req.accessToken,

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

        const accessToken =
            getAccessToken(req);

        if (accessToken) {
            sessions.delete(
                accessToken
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

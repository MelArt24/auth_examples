require('dotenv').config();

const express = require('express');
const axios = require('axios');
const path = require('path');

const app = express();
const port = process.env.PORT || 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const AUTH0_DOMAIN = process.env.AUTH0_DOMAIN;
const AUTH0_CLIENT_ID = process.env.AUTH0_CLIENT_ID;
const AUTH0_CLIENT_SECRET = process.env.AUTH0_CLIENT_SECRET;
const AUTH0_AUDIENCE = process.env.AUTH0_AUDIENCE;

const AUTH0_TOKEN_URL = `https://${AUTH0_DOMAIN}/oauth/token`;

const requiredEnvironmentVariables = [
    'AUTH0_DOMAIN',
    'AUTH0_CLIENT_ID',
    'AUTH0_CLIENT_SECRET'
];

const missingVariables = requiredEnvironmentVariables.filter(
    variable => !process.env[variable]
);

if (missingVariables.length > 0) {
    console.error(
        `Missing environment variables: ${missingVariables.join(', ')}`
    );

    process.exit(1);
}

const sessions = new Map();

function getAccessToken(req) {
    const authorizationHeader = req.get('Authorization');

    if (!authorizationHeader) {
        return null;
    }

    if (authorizationHeader.startsWith('Bearer ')) {
        return authorizationHeader.substring(7);
    }

    return authorizationHeader;
}

app.get('/', (req, res) => {
    const accessToken = getAccessToken(req);

    if (accessToken) {
        const session = sessions.get(accessToken);

        if (session) {
            return res.json({
                authenticated: true,
                username: session.username,
                expiresAt: session.expiresAt
            });
        }

        return res.status(401).json({
            authenticated: false,
            message: 'Invalid session'
        });
    }

    res.sendFile(path.join(__dirname, 'index.html'));
});

app.post('/api/login', async (req, res) => {
    const { login, password } = req.body;

    if (!login || !password) {
        return res.status(400).json({
            message: 'Login and password are required'
        });
    }

    try {
        const requestBody = new URLSearchParams();

        requestBody.append('grant_type', 'password');
        requestBody.append('username', login);
        requestBody.append('password', password);
        requestBody.append('client_id', AUTH0_CLIENT_ID);
        requestBody.append('client_secret', AUTH0_CLIENT_SECRET);

        requestBody.append('scope', 'openid profile email');

        if (AUTH0_AUDIENCE) {
            requestBody.append('audience', AUTH0_AUDIENCE);
        }

        console.log('Sending login request to Auth0...');
        console.log(`User: ${login}`);

        const auth0Response = await axios.post(
            AUTH0_TOKEN_URL,
            requestBody.toString(),
            {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                }
            }
        );

        const {
            access_token,
            token_type,
            expires_in,
            scope
        } = auth0Response.data;

        if (!access_token) {
            return res.status(500).json({
                message: 'Auth0 did not return an access token'
            });
        }

        const expiresAt = expires_in
            ? Date.now() + expires_in * 1000
            : null;

        sessions.set(access_token, {
            username: login,
            accessToken: access_token,
            expiresAt
        });

        console.log('---------------------------------------');
        console.log('Login successful');
        console.log(`User: ${login}`);
        console.log(`Token type: ${token_type}`);
        console.log(`Expires in: ${expires_in} seconds`);
        console.log('---------------------------------------');

        return res.json({
            authenticated: true,
            username: login,

            token: access_token,
            tokenType: token_type,
            expiresIn: expires_in,
            scope: scope || ''
        });
    } catch (error) {
        console.error('Auth0 authentication error');

        if (error.response) {
            console.error(error.response.data);

            const auth0Error =
                error.response.data?.error_description ||
                error.response.data?.error ||
                'Authentication failed';

            return res.status(401).json({
                authenticated: false,
                message: auth0Error
            });
        }

        console.error(error.message);

        return res.status(502).json({
            authenticated: false,
            message: 'Unable to connect to Auth0'
        });
    }
});

app.post('/api/logout', (req, res) => {
    const accessToken = getAccessToken(req);

    if (accessToken) {
        sessions.delete(accessToken);
    }

    console.log('User logged out');

    return res.json({
        success: true
    });
});

app.listen(port, () => {
    console.log('=======================================');
    console.log('Token Auth + Auth0');
    console.log(`Server: http://localhost:${port}`);
    console.log(`Auth0 domain: ${AUTH0_DOMAIN}`);
    console.log('=======================================');
});
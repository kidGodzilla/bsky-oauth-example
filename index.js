require('dotenv').config();

const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const path = require('path');
const express = require('express');
const cors = require('cors');

const { NodeOAuthClient, Session } = require('@atproto/oauth-client-node');
const { JoseKey } = require('@atproto/jwk-jose');
const { Agent } = require('@atproto/api');

const JWT_SECRET = process.env.JWT_SECRET;
const debug = process.env.DEBUG || false;
const port = process.env.PORT || 5000;

// OAuth Settings
const OAUTH_APP_NAME = 'Bluesky OAuth Example App';
const REDIRECT_URL = '/';

// Express App
const app = express();
app.use(express.json());

app.use(cors({
    origin: process.env.BASE_URL,
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'Authorization'],
}));

app.use((err, req, res, next) => {
    console.error('Error:', err);
    res.status(500).send('Internal Server Error');
});

let client = null;

// Simple In-memory session store (OAuth requirement)
class InMemoryStore {
    constructor() {
        this.storeData = {};
    }

    // stateStore methods
    async set(key, internalState) {
        this.storeData[key] = internalState;
    }

    async get(key) {
        return this.storeData[key] || undefined;
    }

    async del(key) {
        delete this.storeData[key];
    }
}
const stateStore = new InMemoryStore();
const sessionStore = new InMemoryStore();

async function oauthClientInit() {
    client = new NodeOAuthClient({
        // This object will be used to build the payload of the /client-metadata.json
        // endpoint metadata, exposing the client metadata to the OAuth server.
        clientMetadata: {
            // Must be a URL that will be exposing this metadata
            client_id: process.env.BASE_URL.includes('127.0.0.1') ? `http://localhost?redirect_uri=${encodeURIComponent(`${process.env.BASE_URL}/oauth/callback`)}&scope=${encodeURIComponent('atproto transition:generic')}` :
                process.env.BASE_URL + '/client-metadata.json',
            client_name: OAUTH_APP_NAME,
            client_uri: process.env.BASE_URL,
            logo_uri: process.env.BASE_URL + '/logo.png',
            tos_uri: process.env.BASE_URL + '/tos',
            policy_uri: process.env.BASE_URL + '/policy',
            redirect_uris: [process.env.BASE_URL + '/oauth/callback'],
            grant_types: ['authorization_code', 'refresh_token'],
            response_types: ['code'],
            scope: 'atproto transition:generic',
            application_type: 'web',
            token_endpoint_auth_method: 'private_key_jwt',
            token_endpoint_auth_signing_alg: 'RS256',
            dpop_bound_access_tokens: true,
            jwks_uri: process.env.BASE_URL + '/jwks.json',
        },

        // Used to authenticate the client to the token endpoint. Will be used to
        // build the jwks object to be exposed on the "jwks_uri" endpoint.
        keyset: await Promise.all([
            JoseKey.fromImportable(process.env.PRIVATE_KEY_1, 'key1'),
            JoseKey.fromImportable(process.env.PRIVATE_KEY_2, 'key2'),
            JoseKey.fromImportable(process.env.PRIVATE_KEY_3, 'key3'),
        ]),

        stateStore,
        sessionStore,
    });
}

/* Authentication Middleware */
const verifyToken = (req, res, next) => {
    const authHeader = req.headers['authorization']; // Expecting 'Bearer <token>'
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access denied. No token provided.' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid or expired token.' });
        }

        req.auth = { user };

        // Add user information to request for use in subsequent middleware/routes
        req.user = user;
        next();
    });
};

// OAuth informational endpoints
app.get('/client-metadata.json', (req, res) => res.json(client.clientMetadata));
app.get('/jwks.json', (req, res) => res.json(client.jwks));


// Create an endpoint to initiate the OAuth flow
app.get('/oauth/login', async (req, res, next) => {
    try {
        const handle = req.query.handle;
        if (!handle) return res.status(400).send('Handle is required');
        const state = crypto.randomBytes(16).toString('hex');

        // Revoke any pending authentication requests if the connection is closed (optional)
        const ac = new AbortController()
        req.on('close', () => ac.abort())

        const url = await client.authorize(handle, {
            signal: ac.signal,
            state,
            // Only supported if OAuth server is openid-compliant
            // ui_locales: 'en fr-CA fr',
        })

        res.redirect(url)
    } catch (err) {
        next(err)
    }
});

// Create an endpoint to handle the OAuth callback
app.get(['/oauth/callback'], async (req, res, next) => {
    try {
        const params = new URLSearchParams(req.url.split('?')[1]);

        if (debug) console.log('OAuth return URL:', req.url);

        const { session, state } = await client.callback(params);

        // Process successful authentication here
        if (debug) console.log('authorize() was called with state:', state);
        if (debug) console.log('User authenticated as:', session.did);
        if (debug) console.log('[Session]:', session, session.service);

        const agent = new Agent(session);

        // Make Authenticated API calls
        const profile = await agent.getProfile({ actor: agent.did });
        if (debug) console.log('Bsky profile:', profile.data);

        // Create JWT payload
        const payload = {
            did: profile.data.did,
            handle: profile.data.handle,
            displayName: profile.data.displayName,
            avatar: profile.data.avatar,
        };

        // Generate a JWT token
        const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '48h' }); // Adjust expiration as needed

        const url = `${REDIRECT_URL}?token=${encodeURIComponent(token)
            }&did=${ encodeURIComponent(profile.data.did) 
            }&handle=${ encodeURIComponent(profile.data.handle) 
            }&displayName=${ encodeURIComponent(profile.data.displayName) 
            }&avatar=${ encodeURIComponent(profile.data.avatar)}`;

        if (debug) console.log('Redirecting to:', url);

        res.redirect(url);
    } catch (err) {
        next(err);
    }
});

// Small endpoint to describe the current user
app.get('/me', verifyToken, (req, res) => {
    res.json({ user: req.auth.user });
});

// Small endpoint to demonstrate an API request
app.get('/profile', verifyToken, async (req, res) => {
    if (!req.user || !req.user.did) return res.status(500).send('Error');

    try {
        const oauthSession = await client.restore(req.user.did);
        // Instantiate the api Agent using an OAuthSession
        const agent = new Agent(oauthSession);

        const profile = await agent.getProfile({ actor: agent.did });
        if (debug) console.log('Bsky profile:', profile.data);

        res.json(profile);
    } catch(e) {
        console.log(e);
        res.status(403).send('Unauthorized'); // Simplified error handling for this example
    }
});

app.get(['/',], (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get(['/login'], (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.use(express.static('public'));

oauthClientInit();

app.listen(port, function () { console.log('App listening on port', port) });

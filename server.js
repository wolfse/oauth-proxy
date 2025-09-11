const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const cors = require('cors');
const app = express();

app.use(express.json());
app.use(cors());
app.use(express.urlencoded({ extended: true }));

const CONFIG = {
    // Befintliga Memberful OAuth2 credentials som Prenly använder
    MEMBERFUL_BASE_URL: process.env.MEMBERFUL_BASE_URL || 'https://alltomwhisky.memberful.com',
    MEMBERFUL_CLIENT_ID: process.env.MEMBERFUL_CLIENT_ID || 'r9u1v8eaFPvQoom1bGbunyfa',
    MEMBERFUL_CLIENT_SECRET: process.env.MEMBERFUL_CLIENT_SECRET || 'ZzUm82nvs1M6XkDpEirPK71H',
    
    // Prenly Remote Authority API
    PRENLY_SHARED_KEY: process.env.PRENLY_SHARED_KEY,
    
    // Bridge konfiguration
    BRIDGE_BASE_URL: process.env.BRIDGE_BASE_URL || 'http://localhost:3000',
    PORT: process.env.PORT || 3000
};

const userTokens = new Map();
const sessions = new Map();

function generateState() {
    return crypto.randomBytes(16).toString('hex');
}

// === MOBIL APP OAUTH2 BRIDGE ===

/**
 * OAuth2 Authorization för mobila appar
 */
app.get('/oauth/authorize', (req, res) => {
    const { client_id, redirect_uri, response_type = 'code', scope = 'read', state } = req.query;

    console.log('Mobile OAuth request:', { client_id, redirect_uri, scope, state });

    // Kontrollera att det är en mobil app
    if (!redirect_uri || !redirect_uri.startsWith('com.paperton')) {
        return res.status(400).json({ 
            error: 'invalid_request',
            error_description: 'This endpoint only supports mobile app redirects'
        });
    }

    const sessionId = generateState();
    sessions.set(sessionId, {
        originalRedirectUri: redirect_uri,
        originalState: state,
        timestamp: Date.now()
    });

    // Redirect till Memberful OAuth
    const memberfulAuthUrl = new URL(`${CONFIG.MEMBERFUL_BASE_URL}/oauth`);
    memberfulAuthUrl.searchParams.set('response_type', 'code');
    memberfulAuthUrl.searchParams.set('client_id', CONFIG.MEMBERFUL_CLIENT_ID);
    memberfulAuthUrl.searchParams.set('redirect_uri', `${CONFIG.BRIDGE_BASE_URL}/oauth/callback`);
    memberfulAuthUrl.searchParams.set('scope', scope);
    memberfulAuthUrl.searchParams.set('state', sessionId);

    console.log('Redirecting to Memberful:', memberfulAuthUrl.toString());
    res.redirect(memberfulAuthUrl.toString());
});

/**
 * OAuth2 Callback från Memberful
 */
app.get('/oauth/callback', async (req, res) => {
    const { code, state, error } = req.query;

    if (error) {
        console.error('OAuth error:', error);
        return res.status(400).json({ error, error_description: req.query.error_description });
    }

    const session = sessions.get(state);
    if (!session) {
        return res.status(400).json({ error: 'invalid_session' });
    }

    try {
        // Växla code mot access token
        const tokenResponse = await axios.post(`${CONFIG.MEMBERFUL_BASE_URL}/oauth/token`, 
            new URLSearchParams({
                grant_type: 'authorization_code',
                client_id: CONFIG.MEMBERFUL_CLIENT_ID,
                client_secret: CONFIG.MEMBERFUL_CLIENT_SECRET,
                code: code,
                redirect_uri: `${CONFIG.BRIDGE_BASE_URL}/oauth/callback`
            }),
            {
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
            }
        );

        const { access_token } = tokenResponse.data;

        // Hämta användardata
        const userResponse = await axios.post(`${CONFIG.MEMBERFUL_BASE_URL}/api/graphql`, {
            query: `
                query {
                    currentMember {
                        id email fullName
                        subscriptions {
                            id plan { id name } active
                        }
                    }
                }
            `
        }, {
            headers: {
                'Authorization': `Bearer ${access_token}`,
                'Content-Type': 'application/json'
            }
        });

        const memberData = userResponse.data.data.currentMember;
        const proxyCode = generateState();
        
        userTokens.set(proxyCode, {
            uid: memberData.id,
            access_token,
            memberData,
            timestamp: Date.now()
        });

        // Redirect till app
        const appCallbackUrl = new URL(session.originalRedirectUri);
        appCallbackUrl.searchParams.set('code', proxyCode);
        if (session.originalState) {
            appCallbackUrl.searchParams.set('state', session.originalState);
        }

        sessions.delete(state);
        res.redirect(appCallbackUrl.toString());

    } catch (error) {
        console.error('OAuth error:', error.response?.data || error.message);
        res.status(500).json({ error: 'oauth_error' });
    }
});

/**
 * Token endpoint för mobila appar
 */
app.post('/oauth/token', async (req, res) => {
    const { grant_type, code } = req.body;

    if (grant_type !== 'authorization_code') {
        return res.status(400).json({ error: 'unsupported_grant_type' });
    }

    const tokenData = userTokens.get(code);
    if (!tokenData) {
        return res.status(400).json({ error: 'invalid_grant' });
    }

    const proxyAccessToken = generateState();
    userTokens.set(proxyAccessToken, {
        uid: tokenData.uid,
        memberful_access_token: tokenData.access_token,
        memberData: tokenData.memberData,
        timestamp: Date.now()
    });

    userTokens.delete(code);

    res.json({
        access_token: proxyAccessToken,
        token_type: 'Bearer',
        expires_in: 3600,
        scope: 'read',
        user_id: tokenData.uid
    });
});

/**
 * Prenly getUser endpoint
 */
app.post('/oauth2/getUser', async (req, res) => {
    const authHeader = req.headers.authorization;
    const { sharedKey, uid } = req.body;

    if (sharedKey !== CONFIG.PRENLY_SHARED_KEY) {
        return res.status(403).json({ message: 'Invalid shared key' });
    }

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ message: 'Missing authorization' });
    }

    const accessToken = authHeader.split(' ')[1];
    const tokenData = userTokens.get(accessToken);

    if (!tokenData || tokenData.uid !== uid) {
        return res.status(401).json({ message: 'Invalid token' });
    }

    try {
        const userResponse = await axios.post(`${CONFIG.MEMBERFUL_BASE_URL}/api/graphql`, {
            query: `
                query {
                    currentMember {
                        id email fullName
                        subscriptions { id plan { id name } active }
                    }
                }
            `
        }, {
            headers: {
                'Authorization': `Bearer ${tokenData.memberful_access_token}`,
                'Content-Type': 'application/json'
            }
        });

        const memberData = userResponse.data.data.currentMember;

        const userSummary = {
            uid: memberData.id,
            customerNumber: memberData.id,
            email: memberData.email,
            givenName: memberData.fullName ? memberData.fullName.split(' ')[0] : null,
            familyName: memberData.fullName ? memberData.fullName.split(' ').slice(1).join(' ') : null,
            productCodes: memberData.subscriptions
                .filter(sub => sub.active)
                .map(sub => sub.plan.name.toLowerCase().replace(/\s+/g, '-')),
            limitedProductCodes: [],
            metaData: { favoriteTitleSlugs: [] }
        };

        res.json(userSummary);

    } catch (error) {
        if (error.response?.status === 401) {
            userTokens.delete(accessToken);
            return res.status(401).json({ message: 'Token expired' });
        }
        res.status(500).json({ message: 'Failed to fetch user data' });
    }
});

// Health check
app.get('/health', (req, res) => {
    res.json({ 
        status: 'ok',
        timestamp: new Date().toISOString(),
        activeTokens: userTokens.size
    });
});

// Cleanup old tokens
setInterval(() => {
    const now = Date.now();
    const maxAge = 60 * 60 * 1000;

    for (const [key, data] of userTokens) {
        if (now - data.timestamp > maxAge) {
            userTokens.delete(key);
        }
    }
}, 10 * 60 * 1000);

app.listen(CONFIG.PORT, () => {
    console.log(`Bridge running on port ${CONFIG.PORT}`);
});

module.exports = app;

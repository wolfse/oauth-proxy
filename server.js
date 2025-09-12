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
 * Denna endpoint hanterar endast mobila redirect URIs
 */
app.get('/oauth/authorize', (req, res) => {
    const { client_id, redirect_uri, response_type = 'code', scope = 'read', state } = req.query;

    console.log('📱 Mobile OAuth request:', { client_id, redirect_uri, scope, state });

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

    // Redirect till Memberful OAuth med web redirect URI
    const memberfulAuthUrl = new URL(`${CONFIG.MEMBERFUL_BASE_URL}/oauth`);
    memberfulAuthUrl.searchParams.set('response_type', 'code');
    memberfulAuthUrl.searchParams.set('client_id', CONFIG.MEMBERFUL_CLIENT_ID);
    memberfulAuthUrl.searchParams.set('redirect_uri', `${CONFIG.BRIDGE_BASE_URL}/oauth/callback`);
    memberfulAuthUrl.searchParams.set('scope', scope);
    memberfulAuthUrl.searchParams.set('state', sessionId);

    console.log(`🔄 Redirecting to Memberful: ${memberfulAuthUrl.toString()}`);
    res.redirect(memberfulAuthUrl.toString());
});

/**
 * OAuth2 Callback från Memberful
 */
app.get('/oauth/callback', async (req, res) => {
    const { code, state, error } = req.query;

    console.log('📥 Callback from Memberful:', { code: code ? 'present' : 'missing', state, error });

    if (error) {
        console.error('OAuth error from Memberful:', error);
        return res.status(400).json({ error, error_description: req.query.error_description });
    }

    const session = sessions.get(state);
    if (!session) {
        return res.status(400).json({ error: 'invalid_session' });
    }

    try {
        // Växla code mot access token med Memberful
        const tokenResponse = await axios.post(`${CONFIG.MEMBERFUL_BASE_URL}/oauth/token`, 
            new URLSearchParams({
                grant_type: 'authorization_code',
                client_id: CONFIG.MEMBERFUL_CLIENT_ID,
                client_secret: CONFIG.MEMBERFUL_CLIENT_SECRET,
                code: code,
                redirect_uri: `${CONFIG.BRIDGE_BASE_URL}/oauth/callback`
            }),
            {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                }
            }
        );

        const { access_token } = tokenResponse.data;

        // Hämta användardata från Memberful API
        const userResponse = await axios.post(`${CONFIG.MEMBERFUL_BASE_URL}/api/graphql`, {
            query: `
                query {
                    currentMember {
                        id
                        email
                        fullName
                        subscriptions {
                            id
                            plan { id name }
                            active
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
        const uid = memberData.id;

        // Generera proxy authorization code för appen
        const proxyCode = generateState();
        userTokens.set(proxyCode, {
            uid,
            access_token,
            memberData,
            timestamp: Date.now()
        });

        // Redirect tillbaka till mobil app
        const appCallbackUrl = new URL(session.originalRedirectUri);
        appCallbackUrl.searchParams.set('code', proxyCode);
        if (session.originalState) {
            appCallbackUrl.searchParams.set('state', session.originalState);
        }

        console.log(`📱 Redirecting to app: ${appCallbackUrl.toString()}`);
        
        sessions.delete(state);
        res.redirect(appCallbackUrl.toString());

    } catch (error) {
        console.error('Error in OAuth flow:', error.response?.data || error.message);
        res.status(500).json({ 
            error: 'oauth_error',
            error_description: error.message
        });
    }
});

/**
 * OAuth2 Token endpoint för mobila appar
 */
app.post('/oauth/token', async (req, res) => {
    const { grant_type, code } = req.body;

    console.log('📱 Token request from mobile app:', { grant_type, code: code ? 'present' : 'missing' });

    if (grant_type !== 'authorization_code') {
        return res.status(400).json({ 
            error: 'unsupported_grant_type',
            error_description: 'Only authorization_code is supported'
        });
    }

    const tokenData = userTokens.get(code);
    if (!tokenData) {
        return res.status(400).json({ 
            error: 'invalid_grant',
            error_description: 'Invalid authorization code'
        });
    }

    // Skapa proxy access token
    const proxyAccessToken = generateState();
    userTokens.set(proxyAccessToken, {
        uid: tokenData.uid,
        memberful_access_token: tokenData.access_token,
        memberData: tokenData.memberData,
        timestamp: Date.now()
    });

    userTokens.delete(code); // Rensa authorization code

    const response = {
        access_token: proxyAccessToken,
        token_type: 'Bearer',
        expires_in: 3600,
        scope: 'read',
        user_id: tokenData.uid
    };

    console.log('✅ Token provided to mobile app');
    res.json(response);
});

// === PRENLY REMOTE AUTHORITY API ===

/**
 * Prenly getUser endpoint
 */
app.post('/oauth2/getUser', async (req, res) => {
    const authHeader = req.headers.authorization;
    const { sharedKey, uid } = req.body;

    console.log('📊 GetUser request:', { uid, hasAuth: !!authHeader });

    if (sharedKey !== CONFIG.PRENLY_SHARED_KEY) {
        return res.status(403).json({ 
            message: 'Invalid shared key',
            code: 'INVALID_SHARED_KEY'
        });
    }

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ 
            message: 'Missing authorization header',
            code: 'UNAUTHORIZED'
        });
    }

    const accessToken = authHeader.split(' ')[1];
    const tokenData = userTokens.get(accessToken);

    if (!tokenData || tokenData.uid !== uid) {
        return res.status(401).json({ 
            message: 'Invalid token',
            code: 'INVALID_TOKEN'
        });
    }

    try {
        // Hämta uppdaterad data från Memberful
        const userResponse = await axios.post(`${CONFIG.MEMBERFUL_BASE_URL}/api/graphql`, {
            query: `
                query {
                    currentMember {
                        id email fullName
                        subscriptions {
                            id
                            plan { id name }
                            active
                        }
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

        console.log('✅ User data returned to Prenly:', { uid: userSummary.uid, productCodes: userSummary.productCodes });
        res.json(userSummary);

    } catch (error) {
        console.error('Error fetching user data:', error.response?.data || error.message);
        
        if (error.response?.status === 401) {
            userTokens.delete(accessToken);
            return res.status(401).json({ 
                message: 'Token expired',
                code: 'TOKEN_EXPIRED'
            });
        }
        
        res.status(500).json({ 
            message: 'Failed to fetch user data',
            code: 'FETCH_FAILED'
        });
    }
});

// === SSO WEBHOOK FÖR AUTOMATISK KOPPLING ===

/**
 * Webhook för automatisk Prenly-koppling när användare loggar in på webben
 */
app.post('/webhook/memberful-login', async (req, res) => {
    const { member_id, email } = req.body;
    
    console.log('🔗 Auto-connecting member to Prenly:', { member_id, email });
    
    // Här kan du implementera automatisk koppling till Prenly
    // för användare som loggar in på webben
    
    res.json({ status: 'ok' });
});

// === HJÄLP-ENDPOINTS ===

app.get('/health', (req, res) => {
    res.json({ 
        status: 'ok',
        timestamp: new Date().toISOString(),
        activeTokens: userTokens.size,
        activeSessions: sessions.size
    });
});

app.get('/config', (req, res) => {
    res.json({
        bridge_type: 'Memberful SSO Bridge',
        memberful_base_url: CONFIG.MEMBERFUL_BASE_URL,
        endpoints: {
            mobile_authorize: `${CONFIG.BRIDGE_BASE_URL}/oauth/authorize`,
            mobile_token: `${CONFIG.BRIDGE_BASE_URL}/oauth/token`,
            oauth2_getUser: `${CONFIG.BRIDGE_BASE_URL}/oauth2/getUser`,
            callback: `${CONFIG.BRIDGE_BASE_URL}/oauth/callback`
        }
    });
});

// === SESSION CLEANUP ===

setInterval(() => {
    const now = Date.now();
    const maxAge = 60 * 60 * 1000; // 1 timme

    for (const [key, data] of userTokens) {
        if (now - data.timestamp > maxAge) {
            userTokens.delete(key);
        }
    }

    for (const [key, session] of sessions) {
        if (now - session.timestamp > 10 * 60 * 1000) { // 10 minuter
            sessions.delete(key);
        }
    }
}, 10 * 60 * 1000);

app.listen(CONFIG.PORT, () => {
    console.log(`🌉 Memberful SSO Bridge running on port ${CONFIG.PORT}`);
    console.log(`📍 Endpoints:`);
    console.log(`   - Mobile OAuth: ${CONFIG.BRIDGE_BASE_URL}/oauth/authorize`);
    console.log(`   - Token: ${CONFIG.BRIDGE_BASE_URL}/oauth/token`);
    console.log(`   - GetUser: ${CONFIG.BRIDGE_BASE_URL}/oauth2/getUser`);
    console.log(`   - Health: ${CONFIG.BRIDGE_BASE_URL}/health`);
});

module.exports = app;

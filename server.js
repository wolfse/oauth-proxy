const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const cors = require('cors');
const app = express();

app.use(express.json());
app.use(cors());
app.use(express.urlencoded({ extended: true }));

const CONFIG = {
    // Memberful OAuth2 credentials
    MEMBERFUL_BASE_URL: process.env.MEMBERFUL_BASE_URL || 'https://alltomwhisky.memberful.com',
    MEMBERFUL_CLIENT_ID: process.env.MEMBERFUL_CLIENT_ID,
    MEMBERFUL_CLIENT_SECRET: process.env.MEMBERFUL_CLIENT_SECRET,
    
    // Prenly configuration
    PRENLY_SHARED_KEY: process.env.PRENLY_SHARED_KEY,
    PRENLY_CLIENT_SECRET: process.env.PRENLY_CLIENT_SECRET,
    
    // Bridge configuration
    BRIDGE_BASE_URL: process.env.RAILWAY_PUBLIC_DOMAIN ? 
        `https://${process.env.RAILWAY_PUBLIC_DOMAIN}` : 
        process.env.BRIDGE_BASE_URL || 'http://localhost:3000',
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

    console.log('📱 Mobile OAuth request:', { client_id, redirect_uri, scope, state });

    // Validera client_id
    if (client_id !== 'prenly-mobile') {
        return res.status(400).json({ 
            error: 'invalid_client_id',
            error_description: 'Invalid client_id'
        });
    }

    // Kontrollera att det är en mobil app
    if (!redirect_uri || !redirect_uri.startsWith('com.paperton')) {
        return res.status(400).json({ 
            error: 'invalid_request',
            error_description: 'This endpoint only supports mobile app redirects'
        });
    }

    if (response_type !== 'code') {
        return res.status(400).json({ 
            error: 'unsupported_response_type',
            error_description: 'Only code response_type is supported'
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

    console.log('🔄 Redirecting to Memberful:', memberfulAuthUrl.toString());
    res.redirect(memberfulAuthUrl.toString());
});

/**
 * OAuth2 Callback från Memberful
 */
app.get('/oauth/callback', async (req, res) => {
    const { code, state, error } = req.query;

    console.log('📥 Callback from Memberful:', { 
        code: code ? 'present' : 'missing', 
        state, 
        error 
    });

    if (error) {
        console.error('OAuth error from Memberful:', error);
        return res.status(400).json({ 
            error: error, 
            error_description: req.query.error_description || 'OAuth authorization failed'
        });
    }

    if (!code || !state) {
        return res.status(400).json({ 
            error: 'invalid_request',
            error_description: 'Missing code or state parameter'
        });
    }

    const session = sessions.get(state);
    if (!session) {
        return res.status(400).json({ 
            error: 'invalid_session',
            error_description: 'Invalid or expired session'
        });
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
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Accept': 'application/json'
                }
            }
        );

        const { access_token } = tokenResponse.data;
        console.log('✅ Got access token from Memberful');

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
                            plan {
                                id
                                name
                            }
                            active
                        }
                    }
                }
            `
        }, {
            headers: {
                'Authorization': `Bearer ${access_token}`,
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }
        });

        const memberData = userResponse.data.data.currentMember;
        if (!memberData) {
            throw new Error('No member data returned from Memberful');
        }

        console.log('✅ Got member data:', { id: memberData.id, email: memberData.email });

        // Generera proxy authorization code för appen
        const proxyCode = generateState();
        
        userTokens.set(proxyCode, {
            uid: memberData.id,
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

        console.log('📱 Redirecting to app:', appCallbackUrl.toString());
        
        sessions.delete(state);
        res.redirect(appCallbackUrl.toString());

    } catch (error) {
        console.error('❌ Error in OAuth flow:', error.response?.data || error.message);
        res.status(500).json({ 
            error: 'oauth_error',
            error_description: 'Failed to complete OAuth authorization'
        });
    }
});

/**
 * OAuth2 Token endpoint för mobila appar
 */
app.post('/oauth/token', async (req, res) => {
    const { grant_type, code, client_id, client_secret } = req.body;

    console.log('📱 Token request from mobile app:', { 
        grant_type, 
        client_id, 
        code: code ? 'present' : 'missing',
        client_secret: client_secret ? 'present' : 'missing'
    });

    if (grant_type !== 'authorization_code') {
        return res.status(400).json({ 
            error: 'unsupported_grant_type',
            error_description: 'Only authorization_code grant type is supported'
        });
    }

    // Validera client credentials
    if (client_id !== 'prenly-mobile' || client_secret !== CONFIG.PRENLY_CLIENT_SECRET) {
        console.error('❌ Invalid client credentials:', { 
            provided_client_id: client_id,
            expected_client_id: 'prenly-mobile',
            secret_match: client_secret === CONFIG.PRENLY_CLIENT_SECRET
        });
        return res.status(401).json({ 
            error: 'invalid_client',
            error_description: 'Invalid client credentials'
        });
    }

    const tokenData = userTokens.get(code);
    if (!tokenData) {
        return res.status(400).json({ 
            error: 'invalid_grant',
            error_description: 'Invalid or expired authorization code'
        });
    }

    // Generera proxy access token
    const proxyAccessToken = generateState();
    userTokens.set(proxyAccessToken, {
        uid: tokenData.uid,
        memberful_access_token: tokenData.access_token,
        memberData: tokenData.memberData,
        timestamp: Date.now()
    });

    // Ta bort authorization code (kan bara användas en gång)
    userTokens.delete(code);

    const response = {
        access_token: proxyAccessToken,
        token_type: 'Bearer',
        expires_in: 3600,
        scope: 'read'
        // INTE user_id här - Prenly hämtar det via getUser
    };

    console.log('✅ Token provided to mobile app');
    res.json(response);
});

// === PRENLY REMOTE AUTHORITY API ===

/**
 * Prenly getUser endpoint enligt Remote Authority API spec
 * POST /oauth2/getUser
 */
app.post('/oauth2/getUser', async (req, res) => {
    const authHeader = req.headers.authorization;
    const { sharedKey, uid } = req.body;

    console.log('📊 GetUser request from Prenly:', { 
        uid, 
        hasAuth: !!authHeader,
        hasSharedKey: !!sharedKey,
        sharedKeyMatch: sharedKey === CONFIG.PRENLY_SHARED_KEY
    });

    // Validera shared key
    if (sharedKey !== CONFIG.PRENLY_SHARED_KEY) {
        console.error('❌ Invalid shared key provided');
        return res.status(403).json({ 
            message: 'Invalid shared key',
            code: 'INVALID_SHARED_KEY'
        });
    }

    // Validera bearer token
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ 
            message: 'Missing or invalid authorization header',
            code: 'UNAUTHORIZED'
        });
    }

    const accessToken = authHeader.split(' ')[1];
    const tokenData = userTokens.get(accessToken);

    if (!tokenData) {
        console.error('❌ Token not found:', { token: accessToken });
        return res.status(401).json({ 
            message: 'Invalid access token',
            code: 'INVALID_TOKEN'
        });
    }

    if (tokenData.uid !== uid) {
        console.error('❌ UID mismatch:', { 
            token_uid: tokenData.uid, 
            requested_uid: uid 
        });
        return res.status(401).json({ 
            message: 'User ID mismatch',
            code: 'UID_MISMATCH'
        });
    }

    try {
        // Hämta uppdaterad användardata från Memberful
        const userResponse = await axios.post(`${CONFIG.MEMBERFUL_BASE_URL}/api/graphql`, {
            query: `
                query {
                    currentMember {
                        id
                        email
                        fullName
                        subscriptions {
                            id
                            plan {
                                id
                                name
                            }
                            active
                            renewsAt
                        }
                        createdAt
                    }
                }
            `
        }, {
            headers: {
                'Authorization': `Bearer ${tokenData.memberful_access_token}`,
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }
        });

        const memberData = userResponse.data.data.currentMember;

        if (!memberData) {
            console.error('❌ No member data from Memberful');
            return res.status(404).json({ 
                message: 'User not found in Memberful',
                code: 'USER_NOT_FOUND'
            });
        }

        // Översätt Memberful data till Prenly UserSummary format
        const userSummary = {
            uid: memberData.id,
            customerNumber: memberData.id,
            email: memberData.email,
            givenName: memberData.fullName ? memberData.fullName.split(' ')[0] : null,
            familyName: memberData.fullName ? memberData.fullName.split(' ').slice(1).join(' ') : null,
            
            // Översätt aktiva prenumerationer till product codes
            productCodes: memberData.subscriptions
                .filter(sub => sub.active)
                .map(sub => sub.plan.name.toLowerCase().replace(/\s+/g, '-')),
            
            // Begränsade product codes (används ej för tillfället)
            limitedProductCodes: [],
            
            // Meta-data för Prenly-funktioner
            metaData: {
                favoriteTitleSlugs: []
            }
        };

        console.log('✅ User data returned to Prenly:', { 
            uid: userSummary.uid, 
            productCodes: userSummary.productCodes,
            email: userSummary.email
        });

        res.json(userSummary);

    } catch (error) {
        console.error('❌ Error fetching user data from Memberful:', error.response?.data || error.message);
        
        if (error.response?.status === 401) {
            // Memberful token är ogiltigt, logga ut användaren
            userTokens.delete(accessToken);
            return res.status(401).json({ 
                message: 'Access token expired or invalid',
                code: 'TOKEN_EXPIRED'
            });
        }
        
        res.status(500).json({ 
            message: 'Failed to fetch user data from Memberful',
            code: 'FETCH_USER_FAILED'
        });
    }
});

// === HJÄLP-ENDPOINTS ===

/**
 * Health check endpoint
 */
app.get('/health', (req, res) => {
    res.json({ 
        status: 'ok',
        timestamp: new Date().toISOString(),
        activeTokens: userTokens.size,
        activeSessions: sessions.size,
        bridge_url: CONFIG.BRIDGE_BASE_URL
    });
});

/**
 * Configuration endpoint (utan känsliga data)
 */
app.get('/config', (req, res) => {
    res.json({
        bridge_type: 'Memberful SSO Bridge for Prenly',
        memberful_base_url: CONFIG.MEMBERFUL_BASE_URL,
        bridge_base_url: CONFIG.BRIDGE_BASE_URL,
        endpoints: {
            mobile_authorize: `${CONFIG.BRIDGE_BASE_URL}/oauth/authorize`,
            mobile_token: `${CONFIG.BRIDGE_BASE_URL}/oauth/token`,
            oauth2_getUser: `${CONFIG.BRIDGE_BASE_URL}/oauth2/getUser`,
            callback: `${CONFIG.BRIDGE_BASE_URL}/oauth/callback`,
            health: `${CONFIG.BRIDGE_BASE_URL}/health`
        },
        oauth_config: {
            client_id: 'prenly-mobile',
            supported_grant_types: ['authorization_code'],
            supported_scopes: ['read']
        }
    });
});

// === SESSION CLEANUP ===

// Rensa gamla sessioner och tokens varje 10 minuter
setInterval(() => {
    const now = Date.now();
    const tokenMaxAge = 60 * 60 * 1000; // 1 timme för tokens
    const sessionMaxAge = 10 * 60 * 1000; // 10 minuter för sessions

    let cleanedTokens = 0;
    let cleanedSessions = 0;

    // Rensa gamla user tokens
    for (const [key, data] of userTokens) {
        if (now - data.timestamp > tokenMaxAge) {
            userTokens.delete(key);
            cleanedTokens++;
        }
    }

    // Rensa gamla sessions
    for (const [key, session] of sessions) {
        if (now - session.timestamp > sessionMaxAge) {
            sessions.delete(key);
            cleanedSessions++;
        }
    }

    if (cleanedTokens > 0 || cleanedSessions > 0) {
        console.log(`🧹 Cleanup: removed ${cleanedTokens} tokens, ${cleanedSessions} sessions`);
    }
}, 10 * 60 * 1000);

// === ERROR HANDLING ===

app.use((error, req, res, next) => {
    console.error('❌ Unhandled error:', error);
    res.status(500).json({ 
        error: 'internal_server_error',
        error_description: 'An unexpected error occurred'
    });
});

// === START SERVER ===

app.listen(CONFIG.PORT, () => {
    console.log(`🌉 Memberful SSO Bridge running on port ${CONFIG.PORT}`);
    console.log(`🔗 Bridge URL: ${CONFIG.BRIDGE_BASE_URL}`);
    console.log(`📍 Endpoints:`);
    console.log(`   - Mobile OAuth: ${CONFIG.BRIDGE_BASE_URL}/oauth/authorize`);
    console.log(`   - Token: ${CONFIG.BRIDGE_BASE_URL}/oauth/token`);
    console.log(`   - GetUser: ${CONFIG.BRIDGE_BASE_URL}/oauth2/getUser`);
    console.log(`   - Health: ${CONFIG.BRIDGE_BASE_URL}/health`);
    console.log(`   - Config: ${CONFIG.BRIDGE_BASE_URL}/config`);
    console.log(`✅ Ready for Prenly integration`);
});

module.exports = app;

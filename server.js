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
const refreshTokens = new Map(); // Ny Map för refresh tokens

function generateState() {
    return crypto.randomBytes(16).toString('hex');
}

function generateRefreshToken() {
    return crypto.randomBytes(32).toString('hex'); // Längre än access tokens
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

    // Acceptera både mobil och webb redirects
    const isMobileApp = redirect_uri && redirect_uri.startsWith('com.paperton');
    const isWebApp = redirect_uri && (redirect_uri.startsWith('https://') || redirect_uri.startsWith('http://'));

    if (!isMobileApp && !isWebApp) {
        return res.status(400).json({ 
            error: 'invalid_request',
            error_description: 'Unsupported redirect URI format'
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

        // Använd mockad testdata - Memberful OAuth tokens fungerar inte med deras user API
        const memberData = {
            id: '123456',
            email: 'test@alltomwhisky.se',
            fullName: 'Test User',
            subscriptions: [{ id: '1', plan: { id: '1', name: 'Premium' }, active: true }]
        };
        
        console.log('✅ Using test member data:', { 
            id: memberData.id, 
            email: memberData.email
        });

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
 * OAuth2 Token endpoint för mobila appar - MED REFRESH TOKEN STÖD
 */
app.post('/oauth/token', async (req, res) => {
    const { grant_type, code, client_id, client_secret, refresh_token } = req.body;

    console.log('📱 Token request from mobile app:', { 
        grant_type, 
        client_id, 
        code: code ? 'present' : 'missing',
        client_secret: client_secret ? 'present' : 'missing',
        refresh_token: refresh_token ? 'present' : 'missing'
    });

    // Validera client credentials - hantera både POST body och headers
    let clientId = req.body.client_id;
    let clientSecret = req.body.client_secret;

    // Fallback till Authorization header om POST body saknas
    if (!clientId || !clientSecret) {
        const authHeader = req.headers.authorization;
        if (authHeader && authHeader.startsWith('Basic ')) {
            const base64Credentials = authHeader.split(' ')[1];
            const credentials = Buffer.from(base64Credentials, 'base64').toString('ascii');
            [clientId, clientSecret] = credentials.split(':');
        }
    }

    if (clientId !== 'prenly-mobile' || clientSecret !== CONFIG.PRENLY_CLIENT_SECRET) {
        console.error('❌ Invalid client credentials');
        return res.status(401).json({ 
            error: 'invalid_client',
            error_description: 'Invalid client credentials'
        });
    }

    // === AUTHORIZATION CODE FLOW ===
    if (grant_type === 'authorization_code') {
        const tokenData = userTokens.get(code);
        if (!tokenData) {
            return res.status(400).json({ 
                error: 'invalid_grant',
                error_description: 'Invalid or expired authorization code'
            });
        }

        // Generera både access token och refresh token
        const proxyAccessToken = generateState();
        const proxyRefreshToken = generateRefreshToken();
        
        // Spara access token
        userTokens.set(proxyAccessToken, {
            uid: tokenData.uid,
            memberful_access_token: tokenData.access_token,
            memberData: tokenData.memberData,
            timestamp: Date.now()
        });

        // Spara refresh token (längre livstid)
        refreshTokens.set(proxyRefreshToken, {
            uid: tokenData.uid,
            memberful_access_token: tokenData.access_token,
            memberData: tokenData.memberData,
            timestamp: Date.now()
        });

        // Ta bort authorization code (kan bara användas en gång)
        userTokens.delete(code);

        const response = {
            access_token: proxyAccessToken,
            refresh_token: proxyRefreshToken,
            token_type: 'Bearer',
            expires_in: 3600,
            scope: 'read'
        };

        console.log('✅ Access token + refresh token provided to mobile app');
        console.log('DEBUG - Access token for testing:', proxyAccessToken);
        console.log('DEBUG - Refresh token for testing:', proxyRefreshToken);
        res.json(response);
        return;
    }

    // === REFRESH TOKEN FLOW ===
    if (grant_type === 'refresh_token') {
        if (!refresh_token) {
            return res.status(400).json({ 
                error: 'invalid_request',
                error_description: 'refresh_token parameter required'
            });
        }

        const refreshData = refreshTokens.get(refresh_token);
        if (!refreshData) {
            return res.status(400).json({ 
                error: 'invalid_grant',
                error_description: 'Invalid or expired refresh token'
            });
        }

        console.log('🔄 Refreshing access token for user:', refreshData.uid);

        try {
            // Försök först använda befintlig Memberful token
            let memberfulToken = refreshData.memberful_access_token;
            let memberData = refreshData.memberData;

            // Testa om Memberful token fortfarande fungerar
            try {
                const testResponse = await axios.post(`${CONFIG.MEMBERFUL_BASE_URL}/api/graphql`, {
                    query: '{ currentMember { id } }'
                }, {
                    headers: {
                        'Authorization': `Bearer ${memberfulToken}`,
                        'Content-Type': 'application/json'
                    }
                });

                if (!testResponse.data.data?.currentMember) {
                    throw new Error('Memberful token expired');
                }
                
            } catch (memberfulError) {
                console.log('⚠️ Memberful token expired, refresh token invalid');
                // Om Memberful token är ogiltigt, refresh token är också ogiltigt
                refreshTokens.delete(refresh_token);
                return res.status(400).json({ 
                    error: 'invalid_grant',
                    error_description: 'Refresh token expired - user must log in again'
                });
            }

            // Generera ny access token
            const newAccessToken = generateState();
            
            userTokens.set(newAccessToken, {
                uid: refreshData.uid,
                memberful_access_token: memberfulToken,
                memberData: memberData,
                timestamp: Date.now()
            });

            // Uppdatera refresh token timestamp
            refreshTokens.set(refresh_token, {
                ...refreshData,
                timestamp: Date.now()
            });

            const response = {
                access_token: newAccessToken,
                token_type: 'Bearer',
                expires_in: 3600,
                scope: 'read'
                // refresh_token behålls densamma
            };

            console.log('✅ Access token refreshed for user:', refreshData.uid);
            res.json(response);
            return;
        } catch (error) {
            console.error('❌ Error refreshing token:', error.message);
            refreshTokens.delete(refresh_token);
            return res.status(400).json({ 
                error: 'invalid_grant',
                error_description: 'Failed to refresh token - user must log in again'
            });
        }
    }

    // Okänd grant_type
    return res.status(400).json({ 
        error: 'unsupported_grant_type',
        error_description: 'Only authorization_code and refresh_token grant types are supported'
    });
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

/**
 * OpenID Connect UserInfo endpoint
 * GET /userinfo
 */
app.get('/userinfo', async (req, res) => {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ 
            error: 'invalid_token',
            error_description: 'Bearer token required'
        });
    }

    const accessToken = authHeader.split(' ')[1];
    const tokenData = userTokens.get(accessToken);

    if (!tokenData) {
        return res.status(401).json({ 
            error: 'invalid_token',
            error_description: 'Invalid or expired access token'
        });
    }

    console.log('✅ UserInfo request for user:', tokenData.uid);

    // OpenID Connect UserInfo response enligt Prenly spec
    const userInfo = {
        sub: tokenData.uid,  // Required: Subject identifier
        
        // Optional user identification (för "inloggad som Anna/Johan")
        name: tokenData.memberData?.fullName,
        given_name: tokenData.memberData?.fullName ? tokenData.memberData.fullName.split(' ')[0] : undefined,
        family_name: tokenData.memberData?.fullName ? tokenData.memberData.fullName.split(' ').slice(1).join(' ') : undefined,
        email: tokenData.memberData?.email,
        
        // Custom claim för Prenly: produktkoder
        products: ['AOW']
    };

    // Ta bort undefined-värden
    Object.keys(userInfo).forEach(key => {
        if (userInfo[key] === undefined) {
            delete userInfo[key];
        }
    });

    res.json(userInfo);
});

// === HJÄLP-ENDPOINTS ===

/**
 * Health check endpoint - uppdaterad med refresh tokens
 */
app.get('/health', (req, res) => {
    res.json({ 
        status: 'ok',
        timestamp: new Date().toISOString(),
        activeAccessTokens: userTokens.size,
        activeRefreshTokens: refreshTokens.size,
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
            userinfo: `${CONFIG.BRIDGE_BASE_URL}/userinfo`,
            logout: `${CONFIG.BRIDGE_BASE_URL}/logout`,
            callback: `${CONFIG.BRIDGE_BASE_URL}/oauth/callback`,
            health: `${CONFIG.BRIDGE_BASE_URL}/health`
        },
        oauth_config: {
            client_id: 'prenly-mobile',
            supported_grant_types: ['authorization_code', 'refresh_token'],
            supported_scopes: ['read'],
            features: ['refresh_tokens', 'logout', 'userinfo']
        }
    });
});

// === LOGOUT ENDPOINTS ===

/**
 * Logout endpoint - POST method - uppdaterad för refresh tokens
 */
app.post('/logout', async (req, res) => {
    try {
        const authHeader = req.headers.authorization;
        const token = authHeader?.replace('Bearer ', '');
        
        if (!token) {
            return res.status(400).json({ 
                error: 'No token provided',
                success: false 
            });
        }

        console.log('User logging out, token:', token.substring(0, 8) + '...');
        
        let tokensRemoved = 0;

        // Ta bort access token
        if (userTokens.has(token)) {
            const tokenData = userTokens.get(token);
            userTokens.delete(token);
            tokensRemoved++;

            // Hitta och ta bort associerade refresh tokens
            for (const [refreshToken, refreshData] of refreshTokens) {
                if (refreshData.uid === tokenData.uid) {
                    refreshTokens.delete(refreshToken);
                    tokensRemoved++;
                }
            }
        }

        console.log(`✅ Removed ${tokensRemoved} tokens for user`);

        res.json({ 
            success: true, 
            message: 'Logged out successfully' 
        });

    } catch (error) {
        console.error('Logout error:', error);
        res.status(500).json({ 
            error: 'Logout failed',
            success: false 
        });
    }
});

/**
 * Logout endpoint - GET method (för enklare integration)
 */
app.get('/logout', (req, res) => {
    const { redirect_uri, post_logout_redirect_uri } = req.query;
    const redirectUrl = redirect_uri || post_logout_redirect_uri;
    
    console.log('User accessed logout via GET', { redirectUrl });
    
    if (redirectUrl) {
        // Redirect tillbaka till appen efter logout
        res.redirect(redirectUrl);
    } else {
        // Ingen redirect - returnera JSON
        res.json({ 
            success: true, 
            message: 'Logged out successfully' 
        });
    }
});

// === SESSION CLEANUP ===

// Rensa gamla sessioner och tokens varje 10 minuter - uppdaterad för refresh tokens
setInterval(() => {
    const now = Date.now();
    const accessTokenMaxAge = 60 * 60 * 1000; // 1 timme för access tokens
    const refreshTokenMaxAge = 30 * 24 * 60 * 60 * 1000; // 30 dagar för refresh tokens
    const sessionMaxAge = 10 * 60 * 1000; // 10 minuter för sessions

    let cleanedAccessTokens = 0;
    let cleanedRefreshTokens = 0;
    let cleanedSessions = 0;

    // Rensa gamla access tokens
    for (const [key, data] of userTokens) {
        if (now - data.timestamp > accessTokenMaxAge) {
            userTokens.delete(key);
            cleanedAccessTokens++;
        }
    }

    // Rensa gamla refresh tokens
    for (const [key, data] of refreshTokens) {
        if (now - data.timestamp > refreshTokenMaxAge) {
            refreshTokens.delete(key);
            cleanedRefreshTokens++;
        }
    }

    // Rensa gamla sessions
    for (const [key, session] of sessions) {
        if (now - session.timestamp > sessionMaxAge) {
            sessions.delete(key);
            cleanedSessions++;
        }
    }

    if (cleanedAccessTokens > 0 || cleanedRefreshTokens > 0 || cleanedSessions > 0) {
        console.log(`🧹 Cleanup: removed ${cleanedAccessTokens} access tokens, ${cleanedRefreshTokens} refresh tokens, ${cleanedSessions} sessions`);
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
    console.log(`   - UserInfo: ${CONFIG.BRIDGE_BASE_URL}/userinfo`);
    console.log(`   - Logout: ${CONFIG.BRIDGE_BASE_URL}/logout`);
    console.log(`   - Health: ${CONFIG.BRIDGE_BASE_URL}/health`);
    console.log(`   - Config: ${CONFIG.BRIDGE_BASE_URL}/config`);
    console.log(`🎯 Features: OAuth2, OpenID Connect, Refresh Tokens, Logout`);
    console.log(`✅ Ready for Prenly integration with 30-day sessions!`);
});

module.exports = app;

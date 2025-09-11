const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const cors = require('cors');
const app = express();

// Middleware
app.use(express.json());
app.use(cors());
app.use(express.urlencoded({ extended: true }));

// Konfiguration - dessa värden ska sättas via miljövariabler
const CONFIG = {
    // Memberful OAuth2 PKCE endpoints
    MEMBERFUL_BASE_URL: process.env.MEMBERFUL_BASE_URL || 'https://your-account.memberful.com',
    MEMBERFUL_CLIENT_ID: process.env.MEMBERFUL_CLIENT_ID,
    MEMBERFUL_CLIENT_SECRET: process.env.MEMBERFUL_CLIENT_SECRET,
    
    // Prenly konfiguration
    PRENLY_SHARED_KEY: process.env.PRENLY_SHARED_KEY,
    
    // Proxy konfiguration
    PROXY_BASE_URL: process.env.PROXY_BASE_URL || 'http://localhost:3000',
    PORT: process.env.PORT || 3000
};

// In-memory storage för PKCE-sessioner (använd Redis/databas i produktion)
const sessions = new Map();
const userTokens = new Map(); // Lagra user tokens för Prenly API-anrop

// Hjälpfunktioner för PKCE
function generateCodeVerifier() {
    return crypto.randomBytes(32).toString('base64url');
}

function generateCodeChallenge(verifier) {
    return crypto.createHash('sha256').update(verifier).digest('base64url');
}

function generateState() {
    return crypto.randomBytes(16).toString('hex');
}

// === OAUTH2 AUTHORIZATION SERVER (för Prenly) ===

/**
 * OAuth2 Authorization Endpoint
 * Prenly kommer anropa detta när användare ska logga in
 */
app.get('/oauth/authorize', (req, res) => {
    const { 
        client_id, 
        redirect_uri, 
        response_type = 'code',
        scope = 'read',
        state 
    } = req.query;

    console.log('🔵 OAuth authorize request from Prenly:', { client_id, redirect_uri, scope, state });

    // Validera parametrar
    if (response_type !== 'code') {
        return res.status(400).json({ error: 'unsupported_response_type' });
    }

    // Generera PKCE-parametrar för Memberful
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = generateCodeChallenge(codeVerifier);
    const internalState = generateState();

    // Spara session-data
    const sessionId = generateState();
    sessions.set(sessionId, {
        codeVerifier,
        originalRedirectUri: redirect_uri,
        originalState: state,
        prenlyClientId: client_id,
        timestamp: Date.now()
    });

    // Bygg Memberful OAuth2 URL med PKCE
    const memberfulAuthUrl = new URL(`${CONFIG.MEMBERFUL_BASE_URL}/oauth/authorize`);
    memberfulAuthUrl.searchParams.set('client_id', CONFIG.MEMBERFUL_CLIENT_ID);
    memberfulAuthUrl.searchParams.set('redirect_uri', `${CONFIG.PROXY_BASE_URL}/oauth/callback`);
    memberfulAuthUrl.searchParams.set('response_type', 'code');
    memberfulAuthUrl.searchParams.set('scope', scope);
    memberfulAuthUrl.searchParams.set('code_challenge', codeChallenge);
    memberfulAuthUrl.searchParams.set('code_challenge_method', 'S256');
    memberfulAuthUrl.searchParams.set('state', `${internalState}.${sessionId}`);

    console.log(`🚀 Redirecting to Memberful OAuth with PKCE: ${memberfulAuthUrl.toString()}`);
    
    // Redirect användaren till Memberful
    res.redirect(memberfulAuthUrl.toString());
});

/**
 * OAuth2 Callback från Memberful
 * Memberful redirectar hit efter autentisering
 */
app.get('/oauth/callback', async (req, res) => {
    const { code, state, error } = req.query;

    console.log('🔵 OAuth callback from Memberful:', { code: code ? 'present' : 'missing', state, error });

    if (error) {
        console.error('OAuth error from Memberful:', error);
        return res.status(400).json({ error, error_description: req.query.error_description });
    }

    if (!code || !state) {
        return res.status(400).json({ error: 'missing_code_or_state' });
    }

    // Extrahera session ID från state
    const [internalState, sessionId] = state.split('.');
    const session = sessions.get(sessionId);

    if (!session) {
        return res.status(400).json({ error: 'invalid_session' });
    }

    try {
        // Växla authorization code mot access token med PKCE
        const tokenResponse = await axios.post(`${CONFIG.MEMBERFUL_BASE_URL}/oauth/token`, 
            new URLSearchParams({
                grant_type: 'authorization_code',
                client_id: CONFIG.MEMBERFUL_CLIENT_ID,
                client_secret: CONFIG.MEMBERFUL_CLIENT_SECRET,
                code: code,
                code_verifier: session.codeVerifier,
                redirect_uri: `${CONFIG.PROXY_BASE_URL}/oauth/callback`
            }),
            {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                }
            }
        );

        const { access_token, refresh_token, expires_in, token_type } = tokenResponse.data;

        console.log('✅ Successfully obtained tokens from Memberful');

        // Hämta användardata från Memberful GraphQL API
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
                'Authorization': `Bearer ${access_token}`,
                'Content-Type': 'application/json'
            }
        });

        const memberData = userResponse.data.data.currentMember;
        const uid = memberData.id;

        // Generera en proxy authorization code för Prenly
        const proxyCode = generateState();
        
        // Lagra access token för framtida Prenly API-anrop
        userTokens.set(uid, {
            access_token,
            refresh_token,
            expires_in,
            token_type,
            memberData,
            timestamp: Date.now()
        });

        // Spara authorization code session
        sessions.set(proxyCode, {
            uid,
            access_token,
            refresh_token,
            expires_in,
            token_type,
            memberData,
            timestamp: Date.now()
        });

        // Bygg callback URL för Prenly
        const callbackUrl = new URL(session.originalRedirectUri);
        callbackUrl.searchParams.set('code', proxyCode);
        if (session.originalState) {
            callbackUrl.searchParams.set('state', session.originalState);
        }

        console.log(`🔄 Redirecting back to Prenly: ${callbackUrl.toString()}`);

        // Rensa den ursprungliga sessionen
        sessions.delete(sessionId);

        // Redirect tillbaka till Prenly-appen
        res.redirect(callbackUrl.toString());

    } catch (error) {
        console.error('Error exchanging code for token:', error.response?.data || error.message);
        res.status(500).json({ 
            error: 'token_exchange_failed',
            error_description: error.response?.data?.error_description || error.message
        });
    }
});

/**
 * OAuth2 Token Endpoint
 * Prenly anropar detta för att växla authorization code mot access token
 */
app.post('/oauth/token', async (req, res) => {
    const { 
        grant_type, 
        client_id, 
        client_secret, 
        code, 
        redirect_uri 
    } = req.body;

    console.log('🔵 OAuth token request from Prenly:', { grant_type, client_id, code: code ? 'present' : 'missing' });

    // Validera grant type
    if (grant_type !== 'authorization_code') {
        return res.status(400).json({ 
            error: 'unsupported_grant_type',
            error_description: 'Only authorization_code grant type is supported'
        });
    }

    // Hämta session baserat på code
    const session = sessions.get(code);
    if (!session) {
        return res.status(400).json({ 
            error: 'invalid_grant',
            error_description: 'Invalid or expired authorization code'
        });
    }

    // Rensa sessionen (authorization codes ska bara användas en gång)
    sessions.delete(code);

    // Generera en proxy access token för Prenly
    const proxyAccessToken = generateState();
    
    // Lagra mapping mellan proxy token och Memberful token
    userTokens.set(proxyAccessToken, {
        uid: session.uid,
        memberful_access_token: session.access_token,
        refresh_token: session.refresh_token,
        memberData: session.memberData,
        timestamp: Date.now()
    });

    // Returnera token response enligt OAuth2 standard
    const tokenResponse = {
        access_token: proxyAccessToken,
        token_type: 'Bearer',
        expires_in: session.expires_in || 3600,
        scope: 'read'
    };

    // Lägg till refresh token om det finns
    if (session.refresh_token) {
        tokenResponse.refresh_token = session.refresh_token;
    }

    // Enligt Prenly spec: returnera user ID antingen i ID token, UserInfo endpoint eller custom property
    // Vi väljer custom property för enkelhet
    tokenResponse.user_id = session.uid;

    res.json(tokenResponse);

    console.log('✅ Token successfully provided to Prenly');
});

// === PRENLY REMOTE AUTHORITY API IMPLEMENTATION ===

/**
 * OAuth2 GetUser endpoint enligt Prenly spec
 * POST /oauth2/getUser
 */
app.post('/oauth2/getUser', async (req, res) => {
    const authHeader = req.headers.authorization;
    const { sharedKey, uid } = req.body;

    console.log('🔵 Prenly getUser request:', { uid, hasAuth: !!authHeader, hasSharedKey: !!sharedKey });

    // Validera shared key
    if (sharedKey !== CONFIG.PRENLY_SHARED_KEY) {
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

    if (!tokenData || tokenData.uid !== uid) {
        return res.status(401).json({ 
            message: 'Invalid access token or user ID mismatch',
            code: 'INVALID_TOKEN'
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
                'Content-Type': 'application/json'
            }
        });

        const memberData = userResponse.data.data.currentMember;

        if (!memberData) {
            return res.status(404).json({ 
                message: 'User not found',
                code: 'USER_NOT_FOUND'
            });
        }

        // Översätt Memberful data till Prenly UserSummary format
        const userSummary = {
            uid: memberData.id,
            customerNumber: memberData.id, // Använd ID som customer number
            email: memberData.email,
            givenName: memberData.fullName ? memberData.fullName.split(' ')[0] : null,
            familyName: memberData.fullName ? memberData.fullName.split(' ').slice(1).join(' ') : null,
            
            // Översätt aktiva prenumerationer till product codes
            productCodes: memberData.subscriptions
                .filter(sub => sub.active)
                .map(sub => sub.plan.name.toLowerCase().replace(/\s+/g, '-')),
            
            // Lägg till begränsade product codes om nödvändigt
            limitedProductCodes: [],
            
            // Meta-data för Prenly-funktioner
            metaData: {
                favoriteTitleSlugs: [] // Kan utökas senare
            }
        };

        console.log('✅ Successfully returned user data to Prenly:', { uid: userSummary.uid, productCodes: userSummary.productCodes });

        res.json(userSummary);

    } catch (error) {
        console.error('Error fetching user data from Memberful:', error.response?.data || error.message);
        
        if (error.response?.status === 401) {
            // Token är ogiltigt, logga ut användaren
            userTokens.delete(accessToken);
            return res.status(401).json({ 
                message: 'Access token expired or invalid',
                code: 'TOKEN_EXPIRED'
            });
        }
        
        res.status(500).json({ 
            message: 'Failed to fetch user data',
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
        sessions: sessions.size,
        activeTokens: userTokens.size
    });
});

/**
 * Konfigurationsinformation (utan känsliga data)
 */
app.get('/config', (req, res) => {
    res.json({
        memberful_base_url: CONFIG.MEMBERFUL_BASE_URL,
        proxy_base_url: CONFIG.PROXY_BASE_URL,
        endpoints: {
            // OAuth2 endpoints för Prenly
            authorize: `${CONFIG.PROXY_BASE_URL}/oauth/authorize`,
            token: `${CONFIG.PROXY_BASE_URL}/oauth/token`,
            callback: `${CONFIG.PROXY_BASE_URL}/oauth/callback`,
            
            // Prenly Remote Authority API
            oauth2_getUser: `${CONFIG.PROXY_BASE_URL}/oauth2/getUser`
        },
        prenly_integration: {
            type: "OAuth2 login form",
            description: "External OAuth2 authorisation server with Memberful backend"
        }
    });
});

/**
 * UserInfo endpoint (OpenID Connect standard)
 * Alternativ metod för Prenly att få user ID
 */
app.get('/userinfo', async (req, res) => {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'invalid_token' });
    }

    const accessToken = authHeader.split(' ')[1];
    const tokenData = userTokens.get(accessToken);

    if (!tokenData) {
        return res.status(401).json({ error: 'invalid_token' });
    }

    res.json({
        sub: tokenData.uid, // Subject (user ID)
        email: tokenData.memberData?.email,
        name: tokenData.memberData?.fullName
    });
});

// === SESSION CLEANUP ===

// Rensa gamla sessioner och tokens varje 10 minuter
setInterval(() => {
    const now = Date.now();
    const maxAge = 60 * 60 * 1000; // 1 timme för tokens
    const sessionMaxAge = 10 * 60 * 1000; // 10 minuter för sessions

    // Rensa gamla sessions
    for (const [key, session] of sessions) {
        if (now - session.timestamp > sessionMaxAge) {
            sessions.delete(key);
        }
    }

    // Rensa gamla user tokens
    for (const [key, token] of userTokens) {
        if (now - token.timestamp > maxAge) {
            userTokens.delete(key);
        }
    }
}, 10 * 60 * 1000);

// === ERROR HANDLING ===

app.use((error, req, res, next) => {
    console.error('Unhandled error:', error);
    res.status(500).json({ 
        error: 'internal_server_error',
        error_description: 'An unexpected error occurred'
    });
});

// === START SERVER ===

app.listen(CONFIG.PORT, () => {
    console.log(`🚀 OAuth2 Proxy server running on port ${CONFIG.PORT}`);
    console.log(`📋 Configuration:`);
    console.log(`   - Memberful: ${CONFIG.MEMBERFUL_BASE_URL}`);
    console.log(`   - Proxy: ${CONFIG.PROXY_BASE_URL}`);
    console.log(`📍 OAuth2 Endpoints for Prenly:`);
    console.log(`   - Authorization: ${CONFIG.PROXY_BASE_URL}/oauth/authorize`);
    console.log(`   - Token: ${CONFIG.PROXY_BASE_URL}/oauth/token`);
    console.log(`   - UserInfo: ${CONFIG.PROXY_BASE_URL}/userinfo`);
    console.log(`📍 Prenly Remote Authority API:`);
    console.log(`   - OAuth2 GetUser: ${CONFIG.PROXY_BASE_URL}/oauth2/getUser`);
    console.log(`   - Health: ${CONFIG.PROXY_BASE_URL}/health`);
});

module.exports = app;
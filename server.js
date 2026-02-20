const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const cors = require('cors');
const app = express();

app.use(express.json());
app.use(cors());
app.use(express.urlencoded({ extended: true }));

const CONFIG = {
    MEMBERFUL_BASE_URL: process.env.MEMBERFUL_BASE_URL || 'https://alltomwhisky.memberful.com',
    MEMBERFUL_CLIENT_ID: process.env.MEMBERFUL_CLIENT_ID,
    MEMBERFUL_CLIENT_SECRET: process.env.MEMBERFUL_CLIENT_SECRET,
    PRENLY_SHARED_KEY: process.env.PRENLY_SHARED_KEY,
    PRENLY_CLIENT_SECRET: process.env.PRENLY_CLIENT_SECRET,
    BRIDGE_BASE_URL: process.env.RAILWAY_PUBLIC_DOMAIN ? 
        `https://${process.env.RAILWAY_PUBLIC_DOMAIN}` : 
        process.env.BRIDGE_BASE_URL || 'http://localhost:3000',
    PORT: process.env.PORT || 3000
};

// Mappning från Memberful-plannamn till Prenly-produktkoder
const PLAN_TO_PRODUCT = {
    'Allt om Whisky +': 'AOW'
};

function mapSubscriptionsToProductCodes(subscriptions) {
    return subscriptions
        .filter(sub => sub.active && PLAN_TO_PRODUCT[sub.plan.name])
        .map(sub => PLAN_TO_PRODUCT[sub.plan.name]);
}

const userTokens = new Map();
const sessions = new Map();
const refreshTokens = new Map();

function generateState() {
    return crypto.randomBytes(16).toString('hex');
}

function generateRefreshToken() {
    return crypto.randomBytes(32).toString('hex');
}

const MEMBER_QUERY = `{ currentMember { id email fullName subscriptions { id active plan { id name } } } }`;

async function fetchMemberData(access_token) {
    const response = await axios.get(`${CONFIG.MEMBERFUL_BASE_URL}/api/graphql/member`, {
        params: { query: MEMBER_QUERY },
        headers: {
            'Authorization': `Bearer ${access_token}`,
            'Accept': 'application/json'
        }
    });
    const m = response.data.data?.currentMember;
    if (!m) throw new Error('No currentMember in response');
    return {
        id: String(m.id),
        email: m.email,
        fullName: m.fullName || '',
        subscriptions: (m.subscriptions || []).map(sub => ({
            id: String(sub.id),
            plan: { id: String(sub.plan.id), name: sub.plan.name },
            active: sub.active
        }))
    };
}

// === MOBIL APP OAUTH2 BRIDGE ===

app.get('/oauth/authorize', (req, res) => {
    const { client_id, redirect_uri, response_type = 'code', state } = req.query;

    console.log('📱 Mobile OAuth request:', { client_id, redirect_uri, state });

    if (client_id !== 'prenly-mobile') {
        return res.status(400).json({ error: 'invalid_client_id', error_description: 'Invalid client_id' });
    }

    const isMobileApp = redirect_uri && redirect_uri.startsWith('com.paperton');
    const isWebApp = redirect_uri && (redirect_uri.startsWith('https://') || redirect_uri.startsWith('http://'));

    if (!isMobileApp && !isWebApp) {
        return res.status(400).json({ error: 'invalid_request', error_description: 'Unsupported redirect URI format' });
    }

    if (response_type !== 'code') {
        return res.status(400).json({ error: 'unsupported_response_type', error_description: 'Only code response_type is supported' });
    }

    const sessionId = generateState();
    sessions.set(sessionId, {
        originalRedirectUri: redirect_uri,
        originalState: state,
        timestamp: Date.now()
    });

    const memberfulAuthUrl = new URL(`${CONFIG.MEMBERFUL_BASE_URL}/oauth`);
    memberfulAuthUrl.searchParams.set('response_type', 'code');
    memberfulAuthUrl.searchParams.set('client_id', CONFIG.MEMBERFUL_CLIENT_ID);
    memberfulAuthUrl.searchParams.set('redirect_uri', `${CONFIG.BRIDGE_BASE_URL}/oauth/callback`);
    memberfulAuthUrl.searchParams.set('scope', 'read');
    memberfulAuthUrl.searchParams.set('state', sessionId);

    console.log('🔄 Redirecting to Memberful:', memberfulAuthUrl.toString());
    res.redirect(memberfulAuthUrl.toString());
});

app.get('/oauth/callback', async (req, res) => {
    const { code, state, error } = req.query;

    console.log('📥 Callback from Memberful:', { 
        code: code ? 'present' : 'missing', 
        state, 
        error 
    });

    if (error) {
        console.error('OAuth error from Memberful:', error);
        return res.status(400).json({ error: error, error_description: req.query.error_description || 'OAuth authorization failed' });
    }

    if (!code || !state) {
        return res.status(400).json({ error: 'invalid_request', error_description: 'Missing code or state parameter' });
    }

    const session = sessions.get(state);
    if (!session) {
        return res.status(400).json({ error: 'invalid_session', error_description: 'Invalid or expired session' });
    }

    try {
        const tokenResponse = await axios.post(`${CONFIG.MEMBERFUL_BASE_URL}/oauth/token`, 
            new URLSearchParams({
                grant_type: 'authorization_code',
                client_id: CONFIG.MEMBERFUL_CLIENT_ID,
                client_secret: CONFIG.MEMBERFUL_CLIENT_SECRET,
                code: code,
                redirect_uri: `${CONFIG.BRIDGE_BASE_URL}/oauth/callback`
            }),
            { headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json' } }
        );

        const { access_token } = tokenResponse.data;
        console.log('✅ Got access token from Memberful');

        let memberData;
        try {
            memberData = await fetchMemberData(access_token);
            const productCodes = mapSubscriptionsToProductCodes(memberData.subscriptions);
            console.log('✅ Got real member data:', { 
                id: memberData.id, 
                email: memberData.email,
                productCodes
            });
        } catch (memberError) {
            console.error('❌ Failed to fetch member data:', memberError.response?.data || memberError.message);
            throw memberError;
        }

        const proxyCode = generateState();
        userTokens.set(proxyCode, {
            uid: memberData.id,
            access_token,
            memberData,
            timestamp: Date.now()
        });

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
        res.status(500).json({ error: 'oauth_error', error_description: 'Failed to complete OAuth authorization' });
    }
});

app.post('/oauth/token', async (req, res) => {
    const { grant_type, code, refresh_token } = req.body;

    console.log('📱 Token request from mobile app:', { 
        grant_type, 
        client_id: req.body.client_id, 
        code: code ? 'present' : 'missing',
        client_secret: req.body.client_secret ? 'present' : 'missing',
        refresh_token: refresh_token ? 'present' : 'missing'
    });

    let clientId = req.body.client_id;
    let clientSecret = req.body.client_secret;

    if (!clientId || !clientSecret) {
        const authHeader = req.headers.authorization;
        if (authHeader && authHeader.startsWith('Basic ')) {
            const credentials = Buffer.from(authHeader.split(' ')[1], 'base64').toString('ascii');
            [clientId, clientSecret] = credentials.split(':');
        }
    }

    if (clientId !== 'prenly-mobile' || clientSecret !== CONFIG.PRENLY_CLIENT_SECRET) {
        console.error('❌ Invalid client credentials');
        return res.status(401).json({ error: 'invalid_client', error_description: 'Invalid client credentials' });
    }

    if (grant_type === 'authorization_code') {
        const tokenData = userTokens.get(code);
        if (!tokenData) {
            return res.status(400).json({ error: 'invalid_grant', error_description: 'Invalid or expired authorization code' });
        }

        const proxyAccessToken = generateState();
        const proxyRefreshToken = generateRefreshToken();
        
        userTokens.set(proxyAccessToken, {
            uid: tokenData.uid,
            memberful_access_token: tokenData.access_token,
            memberData: tokenData.memberData,
            timestamp: Date.now()
        });

        refreshTokens.set(proxyRefreshToken, {
            uid: tokenData.uid,
            memberful_access_token: tokenData.access_token,
            memberData: tokenData.memberData,
            timestamp: Date.now()
        });

        userTokens.delete(code);

        console.log('✅ Access token + refresh token provided to mobile app');
        res.json({
            access_token: proxyAccessToken,
            refresh_token: proxyRefreshToken,
            token_type: 'Bearer',
            expires_in: 3600,
            scope: 'read'
        });
        return;
    }

    if (grant_type === 'refresh_token') {
        if (!refresh_token) {
            return res.status(400).json({ error: 'invalid_request', error_description: 'refresh_token parameter required' });
        }

        const refreshData = refreshTokens.get(refresh_token);
        if (!refreshData) {
            return res.status(400).json({ error: 'invalid_grant', error_description: 'Invalid or expired refresh token' });
        }

        console.log('🔄 Refreshing access token for user:', refreshData.uid);

        try {
            try {
                await fetchMemberData(refreshData.memberful_access_token);
            } catch (memberfulError) {
                console.log('⚠️ Memberful token expired, refresh token invalid');
                refreshTokens.delete(refresh_token);
                return res.status(400).json({ error: 'invalid_grant', error_description: 'Refresh token expired - user must log in again' });
            }

            const newAccessToken = generateState();
            userTokens.set(newAccessToken, {
                uid: refreshData.uid,
                memberful_access_token: refreshData.memberful_access_token,
                memberData: refreshData.memberData,
                timestamp: Date.now()
            });

            refreshTokens.set(refresh_token, { ...refreshData, timestamp: Date.now() });

            console.log('✅ Access token refreshed for user:', refreshData.uid);
            res.json({ access_token: newAccessToken, token_type: 'Bearer', expires_in: 3600, scope: 'read' });
            return;
        } catch (error) {
            console.error('❌ Error refreshing token:', error.message);
            refreshTokens.delete(refresh_token);
            return res.status(400).json({ error: 'invalid_grant', error_description: 'Failed to refresh token - user must log in again' });
        }
    }

    return res.status(400).json({ error: 'unsupported_grant_type', error_description: 'Only authorization_code and refresh_token grant types are supported' });
});

// === PRENLY REMOTE AUTHORITY API ===

app.post('/oauth2/getUser', async (req, res) => {
    const authHeader = req.headers.authorization;
    const { sharedKey, uid } = req.body;

    console.log('📊 GetUser request from Prenly:', { uid, hasAuth: !!authHeader, hasSharedKey: !!sharedKey });

    if (sharedKey !== CONFIG.PRENLY_SHARED_KEY) {
        console.error('❌ Invalid shared key provided');
        return res.status(403).json({ message: 'Invalid shared key', code: 'INVALID_SHARED_KEY' });
    }

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ message: 'Missing or invalid authorization header', code: 'UNAUTHORIZED' });
    }

    const accessToken = authHeader.split(' ')[1];
    const tokenData = userTokens.get(accessToken);

    if (!tokenData) {
        console.error('❌ Token not found');
        return res.status(401).json({ message: 'Invalid access token', code: 'INVALID_TOKEN' });
    }

    if (tokenData.uid !== uid) {
        console.error('❌ UID mismatch:', { token_uid: tokenData.uid, requested_uid: uid });
        return res.status(401).json({ message: 'User ID mismatch', code: 'UID_MISMATCH' });
    }

    try {
        const memberData = await fetchMemberData(tokenData.memberful_access_token);
        const productCodes = mapSubscriptionsToProductCodes(memberData.subscriptions);

        const userSummary = {
            uid: memberData.id,
            customerNumber: memberData.id,
            email: memberData.email,
            givenName: memberData.fullName ? memberData.fullName.split(' ')[0] : null,
            familyName: memberData.fullName ? memberData.fullName.split(' ').slice(1).join(' ') : null,
            productCodes,
            limitedProductCodes: [],
            metaData: { favoriteTitleSlugs: [] }
        };

        console.log('✅ User data returned to Prenly:', { uid: userSummary.uid, productCodes: userSummary.productCodes, email: userSummary.email });
        res.json(userSummary);

    } catch (error) {
        console.error('❌ Error fetching user data from Memberful:', error.response?.data || error.message);
        if (error.response?.status === 401) {
            userTokens.delete(accessToken);
            return res.status(401).json({ message: 'Access token expired or invalid', code: 'TOKEN_EXPIRED' });
        }
        res.status(500).json({ message: 'Failed to fetch user data from Memberful', code: 'FETCH_USER_FAILED' });
    }
});

// === USERINFO ENDPOINT ===

app.get('/userinfo', (req, res) => {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'invalid_token', error_description: 'Bearer token required' });
    }

    const accessToken = authHeader.split(' ')[1];
    const tokenData = userTokens.get(accessToken);

    if (!tokenData) {
        return res.status(401).json({ error: 'invalid_token', error_description: 'Invalid or expired access token' });
    }

    console.log('✅ UserInfo request for user:', tokenData.uid);

    const productCodes = mapSubscriptionsToProductCodes(tokenData.memberData?.subscriptions || []);

    const userInfo = {
        sub: tokenData.uid,
        name: tokenData.memberData?.fullName,
        given_name: tokenData.memberData?.fullName ? tokenData.memberData.fullName.split(' ')[0] : undefined,
        family_name: tokenData.memberData?.fullName ? tokenData.memberData.fullName.split(' ').slice(1).join(' ') : undefined,
        email: tokenData.memberData?.email,
        products: productCodes
    };

    Object.keys(userInfo).forEach(key => { if (userInfo[key] === undefined) delete userInfo[key]; });

    res.json(userInfo);
});

// === HJÄLP-ENDPOINTS ===

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

app.get('/config', (req, res) => {
    res.json({
        bridge_type: 'Memberful SSO Bridge for Prenly',
        memberful_base_url: CONFIG.MEMBERFUL_BASE_URL,
        bridge_base_url: CONFIG.BRIDGE_BASE_URL,
        plan_mappings: PLAN_TO_PRODUCT,
        endpoints: {
            mobile_authorize: `${CONFIG.BRIDGE_BASE_URL}/oauth/authorize`,
            mobile_token: `${CONFIG.BRIDGE_BASE_URL}/oauth/token`,
            oauth2_getUser: `${CONFIG.BRIDGE_BASE_URL}/oauth2/getUser`,
            userinfo: `${CONFIG.BRIDGE_BASE_URL}/userinfo`,
            logout: `${CONFIG.BRIDGE_BASE_URL}/logout`,
            callback: `${CONFIG.BRIDGE_BASE_URL}/oauth/callback`,
            health: `${CONFIG.BRIDGE_BASE_URL}/health`
        }
    });
});

// === LOGOUT ENDPOINTS ===

app.post('/logout', async (req, res) => {
    try {
        const token = req.headers.authorization?.replace('Bearer ', '');
        if (!token) return res.status(400).json({ error: 'No token provided', success: false });

        console.log('User logging out, token:', token.substring(0, 8) + '...');
        let tokensRemoved = 0;

        if (userTokens.has(token)) {
            const tokenData = userTokens.get(token);
            userTokens.delete(token);
            tokensRemoved++;
            for (const [refreshToken, refreshData] of refreshTokens) {
                if (refreshData.uid === tokenData.uid) {
                    refreshTokens.delete(refreshToken);
                    tokensRemoved++;
                }
            }
        }

        console.log(`✅ Removed ${tokensRemoved} tokens for user`);
        res.json({ success: true, message: 'Logged out successfully' });
    } catch (error) {
        console.error('Logout error:', error);
        res.status(500).json({ error: 'Logout failed', success: false });
    }
});

app.get('/logout', (req, res) => {
    const redirectUrl = req.query.redirect_uri || req.query.post_logout_redirect_uri;
    console.log('User accessed logout via GET', { redirectUrl });
    if (redirectUrl) {
        res.redirect(redirectUrl);
    } else {
        res.json({ success: true, message: 'Logged out successfully' });
    }
});

// === SESSION CLEANUP ===

setInterval(() => {
    const now = Date.now();
    let cleanedAccessTokens = 0, cleanedRefreshTokens = 0, cleanedSessions = 0;

    for (const [key, data] of userTokens) {
        if (now - data.timestamp > 60 * 60 * 1000) { userTokens.delete(key); cleanedAccessTokens++; }
    }
    for (const [key, data] of refreshTokens) {
        if (now - data.timestamp > 30 * 24 * 60 * 60 * 1000) { refreshTokens.delete(key); cleanedRefreshTokens++; }
    }
    for (const [key, session] of sessions) {
        if (now - session.timestamp > 10 * 60 * 1000) { sessions.delete(key); cleanedSessions++; }
    }

    if (cleanedAccessTokens > 0 || cleanedRefreshTokens > 0 || cleanedSessions > 0) {
        console.log(`🧹 Cleanup: removed ${cleanedAccessTokens} access tokens, ${cleanedRefreshTokens} refresh tokens, ${cleanedSessions} sessions`);
    }
}, 10 * 60 * 1000);

// === ERROR HANDLING ===

app.use((error, req, res, next) => {
    console.error('❌ Unhandled error:', error);
    res.status(500).json({ error: 'internal_server_error', error_description: 'An unexpected error occurred' });
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

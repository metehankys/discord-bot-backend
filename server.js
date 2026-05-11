const express = require('express');
const axios = require('axios');
const crypto = require('crypto');

const app = express();
app.use(express.json());

// ⚠️ CHANGE THIS TO YOUR ACTUAL DISCORD WEBHOOK URL ⚠️
const DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/1503513260052447353/8zxS6ttxLO3AVzyQMYPwXIHonl0tQm62dYEZAbQDcBMAHUkv5K7qxPOgnUXiWgybVe6s";

// This is the secret token that your Java mod sends. 
// It MUST match the decrypted token in your Java mod!
const EXPECTED_SECRET_TOKEN = "METHE_CLIENT_SECURE_TOKEN_2026";

// ═══════════════════════════════════════════════════════
// ███  WHITELIST & SECURITY SYSTEM  ███
// ═══════════════════════════════════════════════════════

// Admin token for managing whitelist via API (set in Render env vars, or use default)
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || "methe_admin_secret_2026";

// Hardcoded whitelist — edit this and redeploy to add/remove users permanently
// hwid: null = will auto-bind on first login
const WHITELIST = [
    { username: "metehankys", hwid: null, tier: "admin" },
    { username: "Metheos", hwid: null, tier: "user" },
];

// Runtime whitelist (starts as copy of hardcoded, can be modified via API at runtime)
const runtimeWhitelist = [...WHITELIST.map(u => ({ ...u }))];

// Active sessions: session_token → { username, hwid, lastHeartbeat, createdAt }
const activeSessions = new Map();

// Session timeout: if no heartbeat for 10 minutes, session expires
const SESSION_TIMEOUT_MS = 10 * 60 * 1000;
const HEARTBEAT_INTERVAL_SECONDS = 300; // 5 minutes

// Generate a secure random session token
function generateSessionToken() {
    return crypto.randomBytes(32).toString('hex');
}

// Find a user in the whitelist (case-insensitive)
function findWhitelistUser(username) {
    return runtimeWhitelist.find(u => u.username.toLowerCase() === username.toLowerCase());
}

// Clean up expired sessions periodically
setInterval(() => {
    const now = Date.now();
    for (const [token, session] of activeSessions.entries()) {
        if (now - session.lastHeartbeat > SESSION_TIMEOUT_MS) {
            console.log(`[Security] Session expired for: ${session.username}`);
            activeSessions.delete(token);
        }
    }
}, 60 * 1000); // Check every minute

// ──────────────────────────────────────
// POST /api/auth/verify — Initial login verification
// ──────────────────────────────────────
app.post('/api/auth/verify', (req, res) => {
    const { username, hwid, version } = req.body;

    if (!username || !hwid) {
        return res.status(400).json({ allowed: false, reason: "Missing username or hwid." });
    }

    const user = findWhitelistUser(username);

    // Not in whitelist
    if (!user) {
        console.log(`[Security] ❌ REJECTED: ${username} (not in whitelist)`);
        return res.status(403).json({ allowed: false, reason: "User not authorized." });
    }

    // HWID binding: first login → bind HWID to user
    if (user.hwid === null) {
        user.hwid = hwid;
        console.log(`[Security] 🔒 HWID bound for ${username}: ${hwid.substring(0, 12)}...`);
    }

    // HWID mismatch check
    if (user.hwid !== hwid) {
        console.log(`[Security] ❌ HWID MISMATCH for ${username}! Expected: ${user.hwid.substring(0, 12)}... Got: ${hwid.substring(0, 12)}...`);
        return res.status(403).json({ allowed: false, reason: "Hardware mismatch. Contact admin for HWID reset." });
    }

    // Check if user already has an active session (invalidate old one)
    for (const [token, session] of activeSessions.entries()) {
        if (session.username.toLowerCase() === username.toLowerCase()) {
            activeSessions.delete(token);
            console.log(`[Security] ♻️ Old session invalidated for ${username}`);
        }
    }

    // Create new session
    const sessionToken = generateSessionToken();
    activeSessions.set(sessionToken, {
        username: username,
        hwid: hwid,
        lastHeartbeat: Date.now(),
        createdAt: Date.now(),
        version: version || "unknown"
    });

    console.log(`[Security] ✅ VERIFIED: ${username} | Tier: ${user.tier} | Version: ${version || "?"}`);

    return res.status(200).json({
        allowed: true,
        session_token: sessionToken,
        tier: user.tier,
        heartbeat_interval: HEARTBEAT_INTERVAL_SECONDS,
        hwid_bound: user.hwid === hwid,
        message: "Welcome to Methe Client."
    });
});

// ──────────────────────────────────────
// POST /api/auth/heartbeat — Periodic verification
// ──────────────────────────────────────
app.post('/api/auth/heartbeat', (req, res) => {
    const { session_token, username, hwid } = req.body;

    if (!session_token) {
        return res.status(400).json({ status: "error", reason: "Missing session token." });
    }

    const session = activeSessions.get(session_token);

    // Session not found (expired or invalid)
    if (!session) {
        console.log(`[Security] ⚠️ Heartbeat from unknown session: ${username || "?"}`);
        return res.status(401).json({ status: "revoked", reason: "Session expired or invalid. Restart required." });
    }

    // Verify HWID hasn't changed mid-session
    if (hwid && session.hwid !== hwid) {
        console.log(`[Security] 🚨 HWID CHANGED mid-session for ${session.username}!`);
        activeSessions.delete(session_token);
        return res.status(403).json({ status: "revoked", reason: "Hardware identity changed." });
    }

    // Verify user is still in whitelist
    const user = findWhitelistUser(session.username);
    if (!user) {
        console.log(`[Security] 🚫 User removed from whitelist during session: ${session.username}`);
        activeSessions.delete(session_token);
        return res.status(403).json({ status: "revoked", reason: "User removed from whitelist." });
    }

    // All good — refresh heartbeat
    session.lastHeartbeat = Date.now();

    return res.status(200).json({
        status: "active",
        next_heartbeat: HEARTBEAT_INTERVAL_SECONDS,
        uptime_minutes: Math.floor((Date.now() - session.createdAt) / 60000)
    });
});

// ──────────────────────────────────────
// GET /api/auth/whitelist — View whitelist (admin only)
// ──────────────────────────────────────
app.get('/api/auth/whitelist', (req, res) => {
    const token = req.query.admin_token || req.headers['x-admin-token'];
    if (token !== ADMIN_TOKEN) {
        return res.status(403).json({ error: "Admin access required." });
    }

    const list = runtimeWhitelist.map(u => ({
        username: u.username,
        tier: u.tier,
        hwid_bound: u.hwid !== null,
        hwid_preview: u.hwid ? u.hwid.substring(0, 12) + "..." : "not bound"
    }));

    const sessions = [];
    for (const [token, s] of activeSessions.entries()) {
        sessions.push({
            username: s.username,
            uptime_minutes: Math.floor((Date.now() - s.createdAt) / 60000),
            last_heartbeat_ago: Math.floor((Date.now() - s.lastHeartbeat) / 1000) + "s",
            version: s.version
        });
    }

    return res.status(200).json({ whitelist: list, active_sessions: sessions });
});

// ──────────────────────────────────────
// POST /api/auth/whitelist/add — Add user (admin only)
// ──────────────────────────────────────
app.post('/api/auth/whitelist/add', (req, res) => {
    const { admin_token, username, tier } = req.body;
    if (admin_token !== ADMIN_TOKEN) {
        return res.status(403).json({ error: "Admin access required." });
    }
    if (!username) {
        return res.status(400).json({ error: "Username required." });
    }

    const existing = findWhitelistUser(username);
    if (existing) {
        return res.status(409).json({ error: "User already in whitelist.", user: existing.username });
    }

    runtimeWhitelist.push({ username, hwid: null, tier: tier || "user" });
    console.log(`[Security] ➕ Admin added user: ${username} (tier: ${tier || "user"})`);

    return res.status(200).json({ success: true, message: `${username} added to whitelist.` });
});

// ──────────────────────────────────────
// POST /api/auth/whitelist/remove — Remove user (admin only)
// ──────────────────────────────────────
app.post('/api/auth/whitelist/remove', (req, res) => {
    const { admin_token, username } = req.body;
    if (admin_token !== ADMIN_TOKEN) {
        return res.status(403).json({ error: "Admin access required." });
    }
    if (!username) {
        return res.status(400).json({ error: "Username required." });
    }

    const idx = runtimeWhitelist.findIndex(u => u.username.toLowerCase() === username.toLowerCase());
    if (idx === -1) {
        return res.status(404).json({ error: "User not found in whitelist." });
    }

    const removed = runtimeWhitelist.splice(idx, 1)[0];

    // Also kill any active sessions for this user
    for (const [token, session] of activeSessions.entries()) {
        if (session.username.toLowerCase() === username.toLowerCase()) {
            activeSessions.delete(token);
        }
    }

    console.log(`[Security] ➖ Admin removed user: ${removed.username}`);
    return res.status(200).json({ success: true, message: `${removed.username} removed from whitelist.` });
});

// ──────────────────────────────────────
// POST /api/auth/whitelist/reset-hwid — Reset HWID for a user (admin only)
// ──────────────────────────────────────
app.post('/api/auth/whitelist/reset-hwid', (req, res) => {
    const { admin_token, username } = req.body;
    if (admin_token !== ADMIN_TOKEN) {
        return res.status(403).json({ error: "Admin access required." });
    }
    if (!username) {
        return res.status(400).json({ error: "Username required." });
    }

    const user = findWhitelistUser(username);
    if (!user) {
        return res.status(404).json({ error: "User not found in whitelist." });
    }

    user.hwid = null;
    console.log(`[Security] 🔄 HWID reset for: ${username}`);
    return res.status(200).json({ success: true, message: `HWID reset for ${username}. Will re-bind on next login.` });
});

// ═══════════════════════════════════════════════════════
// ███  GHOST CHAT SYSTEM (Existing)  ███
// ═══════════════════════════════════════════════════════

// Rate limiting map (IP -> timestamp)
const rateLimits = new Map();
const RATE_LIMIT_MS = 1000; // 1 message per second per IP

// In-memory message store for polling (keeps last 50 messages)
const messages = [];
const MAX_MESSAGES = 50;
let messageIdCounter = 1;

// GET endpoint for Minecraft clients to poll new messages
app.get('/api/ghost-chat', (req, res) => {
    const token = req.query.token;
    if (token !== EXPECTED_SECRET_TOKEN) {
        return res.status(403).json({ error: "Access Denied: Invalid Security Token." });
    }

    const sinceId = parseInt(req.query.since) || 0;
    const newMessages = messages.filter(m => m.id > sinceId);
    
    res.status(200).json({ messages: newMessages });
});

// POST endpoint for sending messages
app.post('/api/ghost-chat', async (req, res) => {
    const { token, sender, message } = req.body;
    const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

    // 1. Verify Reverse-Engineering Protection Token
    if (token !== EXPECTED_SECRET_TOKEN) {
        return res.status(403).json({ error: "Access Denied: Invalid Security Token." });
    }

    // 2. Input Validation
    if (!sender || !message || message.length > 500) {
        return res.status(400).json({ error: "Invalid payload." });
    }

    // 3. Spam / Rate Limiting Protection
    const lastRequest = rateLimits.get(clientIp);
    const now = Date.now();
    if (lastRequest && now - lastRequest < RATE_LIMIT_MS) {
        return res.status(429).json({ error: "Rate limit exceeded. Please wait." });
    }
    rateLimits.set(clientIp, now);

    // 4. Save to memory for other clients to read
    const msgObj = {
        id: messageIdCounter++,
        sender: sender,
        text: message,
        timestamp: Date.now()
    };
    messages.push(msgObj);
    if (messages.length > MAX_MESSAGES) {
        messages.shift(); // Remove oldest message
    }

    // 5. Forward to Discord Webhook
    try {
        await axios.post(DISCORD_WEBHOOK_URL, {
            content: `[GLOBAL GHOST] **${sender}**: ${message}`
        });
        return res.status(200).json({ success: true });
    } catch (error) {
        console.error("Webhook forwarding failed:", error.message);
        // We still return 200 so the game chat doesn't error out if Discord is rate limiting us
        return res.status(200).json({ success: true, warning: "Failed to reach Discord." });
    }
});

// ═══════════════════════════════════════════════════════
// ███  SERVER STARTUP  ███
// ═══════════════════════════════════════════════════════

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Global Ghost Chat Proxy Server running on port ${PORT}`);
    console.log(`Reverse Engineering Protection: ENABLED`);
    console.log(`Whitelist Security System: ENABLED (${runtimeWhitelist.length} users)`);
    console.log(`Active sessions will expire after ${SESSION_TIMEOUT_MS / 60000} minutes without heartbeat`);
});

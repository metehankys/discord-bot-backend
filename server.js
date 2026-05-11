const express = require('express');
const axios = require('axios');

const app = express();
app.use(express.json());

// ⚠️ CHANGE THIS TO YOUR ACTUAL DISCORD WEBHOOK URL ⚠️
const DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/YOUR_WEBHOOK_ID/YOUR_WEBHOOK_TOKEN";

// This is the secret token that your Java mod sends. 
// It MUST match the decrypted token in your Java mod!
const EXPECTED_SECRET_TOKEN = "METHE_CLIENT_SECURE_TOKEN_2026";

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

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Global Ghost Chat Proxy Server running on port ${PORT}`);
    console.log(`Reverse Engineering Protection: ENABLED`);
});

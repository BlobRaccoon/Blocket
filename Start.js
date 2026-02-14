const getBannedIps = () => JSON.parse(fs.readFileSync(BAN_FILE, 'utf8'));
require('dotenv').config();
const axios = require("axios");
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const svgCaptcha = require('svg-captcha');
const app = express();
const server = http.createServer(app);
const io = new Server(server);
const OPEN_COST = 25;
const STARTING_TOKENS = 10000;
const JWT_SECRET = process.env.JWT_SECRET;
const DB_FILE = './users.json';
const SESSION_FILE = './JWTs.json';
const BAN_FILE = './banned_ips.json';
const CHAT_HISTORY_LIMIT = 100;
let chatHistory = [];
const BANNED_IPS_FILE = path.join(__dirname, 'banned_ips.json');
const mutedUsers = new Set();
const ADMIN_PASSWORD = process.env.OWNER_PASSWORD;

const saveBannedIps = (ips) => fs.writeFileSync(BAN_FILE, JSON.stringify(ips, null, 2));
let bannedIps = getBannedIps();
const PACKS = {
    Cat: [
    { id: "11", name: "Black Cat", chance: 25, file: "black.png", rarity: "Super Common", sellprice: 10 },
    { id: "16", name: "Orange Cat", chance: 25, file: "orange.png", rarity: "Super Common", sellprice: 10 },
    { id: "12", name: "Void Cat", chance: 15, file: "void.png", rarity: "Common", sellprice: 80 },
    { id: "17", name: "Siamese Cat", chance: 15, file: "siamese.png", rarity: "Uncommon", sellprice: 150 },
    { id: "13", name: "Business Cat", chance: 10, file: "business.png", rarity: "Rare", sellprice: 300 },
    { id: "14", name: "Hacker Cat", chance: 5, file: "hacker.png", rarity: "Epic", sellprice: 600 },
    { id: "18", name: "Ghost Cat", chance: 3, file: "ghost.png", rarity: "Legendary", sellprice: 1200 },
    { id: "19", name: "Co-Founder cat", chance: 1.9, file: "co.png", rarity: "Mythical", sellprice: 3000 },
    { id: "15", name: "Founder Cat", chance: 0.1, file: "founder.png", rarity: "Godlike", sellprice: 5000 }
    ],
    Dog: [
    { id: "21", name: "Border Collie", chance: 35, file: "bordercollie.png", rarity: "Super Common", sellprice: 10 },
    { id: "29", name: "Frorkie", chance: 20, file: "frorkie.png", rarity: "Super Common", sellprice: 10 },
    { id: "22", name: "Husky", chance: 15, file: "husky.png", rarity: "Common", sellprice: 80 },
    { id: "23", name: "German Shepherd", chance: 10, file: "german.png", rarity: "Uncommon", sellprice: 150 },
    { id: "24", name: "Chuwawa", chance: 10, file: "chuwawa.png", rarity: "Rare", sellprice: 300 },
    { id: "25", name: "Angry Dog", chance: 6, file: "angry.png", rarity: "Epic", sellprice: 600 },
    { id: "26", name: "Sad Dog", chance: 3, file: "sad.png", rarity: "Legendary", sellprice: 1000 },
    { id: "27", name: "Bonk dog", chance: 0.9, file: "bonk.png", rarity: "Mythical", sellprice: 2500 },
    { id: "28", name: "Doge", chance: 0.1, file: "doge.png", rarity: "Godlike", sellprice: 5000 }
]
};


if (!fs.existsSync(DB_FILE)) fs.writeFileSync(DB_FILE, '[]');
if (!fs.existsSync(SESSION_FILE)) fs.writeFileSync(SESSION_FILE, '{}');
if (!fs.existsSync(BAN_FILE)) fs.writeFileSync(BAN_FILE, '[]');
const BLOCKS_DIR = path.join(__dirname, 'blocks');
if (!fs.existsSync(BLOCKS_DIR)) fs.mkdirSync(BLOCKS_DIR);


app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname));

const getUsers = () => JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
const saveUsers = (users) => fs.writeFileSync(DB_FILE, JSON.stringify(users, null, 2));
const getSessions = () => JSON.parse(fs.readFileSync(SESSION_FILE, 'utf8'));
const saveSessions = (sessions) => fs.writeFileSync(SESSION_FILE, JSON.stringify(sessions, null, 2));

const authenticate = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(401).json({ error: "No token" });
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return res.status(401).json({ error: "Invalid token" });
        const sessions = getSessions();
        if (!sessions[decoded.username] || sessions[decoded.username].Token !== token) return res.status(401).json({ error: "Expired" });
        req.username = decoded.username;
        next();
    });
};

function rollWeighted(items) {
    const total = items.reduce((s, i) => s + i.chance, 0);
    let roll = Math.random() * total;

    for (const item of items) {
        roll -= item.chance;
        if (roll <= 0) return item;
    }
}


function sanitizeUrl(input) {
    let url = input.trim();
    url = url.replace(/^(hp|htp|httpp|http|https)s?:\/+/i, 'https://');
    if (!/^https?:\/\//i.test(url)) url = 'https://' + url;
    return url;
}


app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/register', (req, res) => res.sendFile(path.join(__dirname, 'reg.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'log.html')));
app.get('/stats', (req, res) => res.sendFile(path.join(__dirname, 'dash.html')));
app.get('/inventory', (req, res) => res.sendFile(path.join(__dirname, 'inventory.html')));
app.get('/market', (req, res) => res.sendFile(path.join(__dirname, 'market.html')));
app.get('/explorer', (req, res) => res.sendFile(path.join(__dirname, 'explorer.html')));
app.get('/logout', (req, res) => res.sendFile(path.join(__dirname, 'logout.html')));
app.get('/view/:page', (req, res) => res.sendFile(path.join(__dirname, 'viewer.html')));
app.get('/credits', (req, res) => res.sendFile(path.join(__dirname, 'credits.html')));
app.get('/terms', (req, res) => res.sendFile(path.join(__dirname, 'terms.html')));
app.get('/privacy', (req, res) => res.sendFile(path.join(__dirname, 'privacy.html')));
app.get('/chat', (req, res) => res.sendFile(path.join(__dirname, 'chat.html')));
app.get('/javascript/Isbot.js', (req, res) => res.sendFile(path.join(__dirname, 'IsBot.js')));
app.use('/blocks', express.static(BLOCKS_DIR));


app.get('/api/captcha', (req, res) => {
    const captcha = svgCaptcha.create({
        size: 5,
        noise: 3,
        color: true,
        background: '#ffffff'
    });

    const ip = req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress;

    const sessions = getSessions();
    sessions[ip] = { captcha: captcha.text.toLowerCase() };
    saveSessions(sessions);

    res.type('svg');
    res.send(captcha.data);
});

app.post('/api/registeruser', async (req, res) => {
    const { username, password, captchaInput } = req.body;

   const ip = req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress;

    if (getBannedIps().includes(ip)) {
        return res.status(403).json({ error: "Banned IP" });
    }

    const sessions = getSessions();
    if (!sessions[ip] || !sessions[ip].captcha || sessions[ip].captcha !== captchaInput.toLowerCase()) {
        return res.status(400).json({ error: "Invalid Captcha" });
    }

    delete sessions[ip];
    saveSessions(sessions);

    const users = getUsers();
    if (users.find(u => u.username === username)) {
        return res.status(400).json({ error: "Taken" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    users.push({
        username,
        password: hashedPassword,
        tokens: STARTING_TOKENS,
        inventory: {},
        messagesSent: 0,
        newperson: true,
        founder: false,
        moderator: false,
        banned: false,
        lastIp: ip,
        role: 'NewPerson 🆕',
        dateJoined: Date.now(),
        blocksOpened: 0
    });
    
    saveUsers(users);
    res.json({ message: "Success" });
});

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;

    const users = getUsers();
    const user = users.find(u => u.username === username);

    if (!user || user.banned || !(await bcrypt.compare(password, user.password))) {
        return res.status(401).json({ error: "Invalid Credentials" });
    }

    const token = jwt.sign({ username: user.username }, JWT_SECRET, { expiresIn: '1h' });
    const sessions = getSessions();
    sessions[username] = { Token: token, ExpiresAt: Date.now() + 3600000 };
    saveSessions(sessions);

    res.json({ token, username });
});

app.post('/api/UserPing', authenticate, async (req, res) => {
    const users = getUsers();
    const user = users.find(u => u.username === req.username);
    if (!user) return res.status(404).json({ error: "User not found" });

    const { ip, userAgent, platform, language } = req.body || {};
    const resolvedIp =
        req.headers["x-forwarded-for"]?.split(",")[0]?.trim() ||
        ip ||
        req.socket.remoteAddress;

    user.lastIp = resolvedIp;
    user.lastPing = Date.now();
    user.client = { userAgent, platform, language };

    try {
        const r = await axios.get(`https://ipapi.co/${resolvedIp}/json/`, { timeout: 6000 });
        const d = r.data;
        user.ipInfo = {
            ip: resolvedIp,
            country: d.country_name || null,
            countryCode: d.country_code || null,
            region: d.region || null,
            city: d.city || null,
            latitude: d.latitude || null,
            longitude: d.longitude || null,
            timezone: d.timezone || null,
            updatedAt: Date.now()
        };
    } catch {}

    const now = Date.now();
    let baseRole = "NewPerson 🆕";

    if (now - user.dateJoined > 31536000000) baseRole = "Og 👑";
    else if (now - user.dateJoined > 15552000000) baseRole = "Veteran 🎖️";

    if (user.founder) user.role = `Founder 🛠️ & ${baseRole}`;
    else if (user.moderator) user.role = `Moderator 🛡️ & ${baseRole}`;
    else user.role = baseRole;

    saveUsers(users);

    res.json({
        status: "Updated",
        role: user.role
    });
});

app.get('/api/userdata', authenticate, (req, res) => {
    const user = getUsers().find(u => u.username === req.username);
    const { password, lastIp, ipInfo, ...safeData } = user;
    res.json(safeData);
});
app.get('/mod/getUserData', authenticate, (req, res) => {
    const { password, username } = req.query;

    if (password !== process.env.OWNER_PASSWORD) {
        return res.status(403).json({ error: "Unauthorized" });
    }

    const users = getUsers();
    const user = users.find(u => u.username === username);

    if (!user) {
        return res.status(404).json({ error: "User not found" });
    }

    res.json(user);
});
app.post('/api/open', authenticate, (req, res) => {
    let { packType } = req.body;
    packType = packType.charAt(0).toUpperCase() + packType.slice(1).toLowerCase(); 

    const pack = PACKS[packType];
    if (!pack) return res.status(400).json({ error: "Invalid pack" });

    const users = getUsers();
    const user = users.find(u => u.username === req.username);
    
    if (user.tokens < OPEN_COST) return res.status(400).json({ error: "Insufficient tokens" });

    const rolled = rollWeighted(pack);
    
    const assetPath = path.join(BLOCKS_DIR, packType, rolled.file);
    if (!fs.existsSync(assetPath)) return res.status(500).json({ error: "Missing asset" });

    user.tokens -= OPEN_COST;

    if (user.blocksOpened === undefined) user.blocksOpened = 0;
    user.blocksOpened += 1;

    if (!user.inventory[rolled.id]) {
        user.inventory[rolled.id] = {
            id: rolled.id,
            name: rolled.name,
            rarity: rolled.rarity,
            file: rolled.file,
            pack: packType,
            sellprice: rolled.sellprice,
            count: 0 
        };
    }

    user.inventory[rolled.id].count += 1;
    
    saveUsers(users);

    res.json({
        received: {
            id: rolled.id,
            name: rolled.name,
            rarity: rolled.rarity,
            path: `/blocks/${packType}/${rolled.file}`
        },
        newBalance: user.tokens,
        totalOpened: user.blocksOpened 
    });
});
app.post('/api/admin/set-role', (req, res) => {
    const { username, role, password } = req.body;

    if (password !== ADMIN_PASSWORD) {
        return res.status(401).json({ error: "Unauthorized" });
    }

    const users = getUsers();
    const user = users.find(u => u.username.toLowerCase() === username.toLowerCase());

    if (!user) return res.status(404).json({ error: "User not found" });

    if (role === 'founder') {
        user.founder = true;
        user.moderator = false;
    } else if (role === 'moderator') {
        user.founder = false;
        user.moderator = true;
    } else {
        user.founder = false;
        user.moderator = false;
    }

    saveUsers(users);
    res.json({ success: true, message: `Updated ${username} to ${role.toUpperCase()}` });
});

const timedMutes = new Map();

io.use((socket, next) => {
    const clientIp = socket.handshake.address;
    if (getBannedIps().includes(clientIp)) return next(new Error("IP_BANNED"));

    const token = socket.handshake.auth.token;
    if (!token) return next(new Error("AUTH_REQUIRED"));

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return next(new Error("SESSION_EXPIRED"));

        const users = getUsers();
        const user = users.find(u => u.username === decoded.username);
        
        if (!user || user.banned) return next(new Error("ACCESS_DENIED"));

        socket.user = {
            username: user.username,
            role: user.role,
            isFounder: !!user.founder, 
            isStaff: !!(user.founder || user.moderator),
            newperson: user.newperson ?? true,
            lastIp: user.lastIp || clientIp
        };
        next();
    });
});

io.on('connection', (socket) => {
    let lastChatTime = 0;

    socket.join(`user:${socket.user.username}`);
    socket.emit('chat-history', chatHistory);

    socket.on('chat-message', (data) => {
        const now = Date.now();
        if (now - lastChatTime < 800) return socket.emit('err', "Rate limit exceeded.");
        lastChatTime = now;

        const msg = typeof data.message === 'string' ? data.message.trim() : "";
        if (!msg || msg.length > 500) return;

        if (timedMutes.has(socket.user.username)) {
            if (now < timedMutes.get(socket.user.username)) {
                return socket.emit('err', `Muted for ${Math.ceil((timedMutes.get(socket.user.username) - now) / 60000)}m.`);
            }
            timedMutes.delete(socket.user.username);
        }

        if (msg.startsWith('/')) {
            const args = msg.split(/\s+/);
            const cmd = args[0].toLowerCase().slice(1);
            const target = args[1];
            const users = getUsers();

            if (socket.user.isFounder) {
                const tUser = users.find(u => u.username.toLowerCase() === target?.toLowerCase());
                if (tUser) {
                    if (cmd === 'setmod') {
                        tUser.moderator = true; tUser.founder = false;
                        saveUsers(users);
                        return io.emit('chat-message', { user: "SYSTEM", role: "🛡️ STAFF", message: `${target} is now a Moderator.`, time: now });
                    }
                    if (cmd === 'setfounder') {
                        tUser.founder = true; tUser.moderator = false;
                        saveUsers(users);
                        return io.emit('chat-message', { user: "SYSTEM", role: "🛡️ STAFF", message: `${target} is now a Founder.`, time: now });
                    }
                }
            }

            if (socket.user.isStaff) {
                switch (cmd) {
                    case 'kick':
                        const ts = [...io.sockets.sockets.values()].find(s => s.user?.username.toLowerCase() === target?.toLowerCase());
                        if (ts) ts.disconnect();
                        return io.emit('chat-message', { user: "SYSTEM", role: "🛡️ STAFF", message: `${target} kicked.`, time: now });

                    case 'mute':
                        const minutes = parseInt(args[2]) || 60;
                        timedMutes.set(target, now + (minutes * 60000));
                        return io.emit('chat-message', { user: "SYSTEM", role: "🛡️ STAFF", message: `${target} muted for ${minutes}m.`, time: now });

                    case 'unmute':
                        timedMutes.delete(target);
                        return io.emit('chat-message', { user: "SYSTEM", role: "🛡️ STAFF", message: `${target} unmuted.`, time: now });

                    case 'ban':
                        const bUser = users.find(u => u.username.toLowerCase() === target?.toLowerCase());
                        if (bUser) {
                            bUser.banned = true;
                            saveUsers(users);
                            const bs = [...io.sockets.sockets.values()].find(s => s.user?.username.toLowerCase() === target.toLowerCase());
                            if (bs) bs.disconnect();
                        }
                        return io.emit('chat-message', { user: "SYSTEM", role: "🛡️ STAFF", message: `${target} banned.`, time: now });

                    case 'permban':
                        const pUser = users.find(u => u.username.toLowerCase() === target?.toLowerCase());
                        if (pUser) {
                            pUser.banned = true;
                            const bans = getBannedIps();
                            if (pUser.lastIp && !bans.includes(pUser.lastIp)) {
                                bans.push(pUser.lastIp);
                                saveBannedIps(bans);
                            }
                            saveUsers(users);
                            const ps = [...io.sockets.sockets.values()].find(s => s.user?.username.toLowerCase() === target.toLowerCase());
                            if (ps) ps.disconnect();
                        }
                        return io.emit('chat-message', { user: "SYSTEM", role: "🚨 PERMBAN", message: `${target} IP-BANNED.`, time: now });

                    case 'unban':
                        const ubUser = users.find(u => u.username.toLowerCase() === target?.toLowerCase());
                        if (ubUser) {
                            ubUser.banned = false;
                            const currentBans = getBannedIps().filter(ip => ip !== ubUser.lastIp);
                            saveBannedIps(currentBans);
                            saveUsers(users);
                        }
                        return io.emit('chat-message', { user: "SYSTEM", role: "🛡️ STAFF", message: `${target} unbanned.`, time: now });

                    case 'whois':
                        const wUser = users.find(u => u.username.toLowerCase() === target?.toLowerCase());
                        if (wUser) {
                            return socket.emit('chat-message', { user: "SYSTEM", role: "🛡️ INFO", message: `User: ${wUser.username} | IP: ${wUser.lastIp} | Role: ${wUser.role}`, time: now });
                        }
                        return;

                    case 'clear':
                        chatHistory.length = 0;
                        return io.emit('chat-history', []);

                    case 'announce':
                        return io.emit('chat-message', { user: "📢 ANNOUNCEMENT", role: "GLOBAL", message: args.slice(1).join(' ').toUpperCase(), time: now });
                }
            }

            switch (cmd) {
                case 'msg':
                    const pmContent = args.slice(2).join(' ');
                    if (!target || !pmContent) return;
                    io.to(`user:${target}`).emit('chat-message', { user: `(DM) ${socket.user.username}`, role: "📩 PRIV", message: pmContent, time: now });
                    return socket.emit('chat-message', { user: `(DM) To ${target}`, role: "📩 PRIV", message: pmContent, time: now });

                case 'roll':
                    return io.emit('chat-message', { user: "SYSTEM", role: "🎲 ROLL", message: `${socket.user.username} rolled ${Math.floor(Math.random() * 100) + 1}/100`, time: now });

                case 'stats':
                    const me = users.find(u => u.username === socket.user.username);
                    return socket.emit('chat-message', { user: "SYSTEM", role: "📊 STATS", message: `Messages: ${me?.messagesSent || 0}`, time: now });
                
                case 'staff':
                    const staff = [...io.sockets.sockets.values()].filter(s => s.user?.isStaff).map(s => s.user.username);
                    return socket.emit('chat-message', { user: "SYSTEM", role: "🛡️ ONLINE", message: staff.join(', ') || "None", time: now });

                case 'help':
                    let help = socket.user.isStaff ? "kick, ban, permban, unban, whois, mute, unmute, clear, announce, roll, stats, staff, msg" : "roll, stats, staff, msg, help";
                    if (socket.user.isFounder) help += ", setmod, setfounder";
                    return socket.emit('chat-message', { user: "SYSTEM", role: "❓ HELP", message: `Commands: ${help}`, time: now });
            }
        }

        const udb = getUsers();
        const dbUser = udb.find(u => u.username === socket.user.username);
        if (dbUser) {
            dbUser.messagesSent = (dbUser.messagesSent || 0) + 1;
            saveUsers(udb);
        }

        const chatData = {
            user: socket.user.username,
            role: socket.user.newperson ? "🆕 NEW" : socket.user.role,
            message: msg.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;"),
            time: now
        };

        chatHistory.push(chatData);
        if (chatHistory.length > 50) chatHistory.shift();
        io.emit('chat-message', chatData);
    });

    socket.on('disconnect', () => {
    });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const { createProxyMiddleware } = require('http-proxy-middleware');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'nexior-studio-secret-change-in-production';
const ACE_DATA_API_KEY = process.env.ACE_DATA_API_KEY || '';

// ── Database ──
const db = new Database('users.db');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
  )
`);

// ── Middleware ──
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());

// ── Auth middleware ──
const authMiddleware = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No token provided' });
  }
  try {
    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
};

// ── Auth Routes ──

// Register
app.post('/api/auth/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  }
  try {
    const hash = await bcrypt.hash(password, 10);
    const stmt = db.prepare('INSERT INTO users (email, password) VALUES (?, ?)');
    const result = stmt.run(email, hash);
    const token = jwt.sign({ id: result.lastInsertRowid, email }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user: { id: result.lastInsertRowid, email } });
  } catch (err) {
    if (err.message.includes('UNIQUE')) {
      return res.status(409).json({ error: 'Email already registered' });
    }
    res.status(500).json({ error: 'Registration failed' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const valid = await bcrypt.compare(password, user.password);
  if (!valid) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user: { id: user.id, email: user.email } });
});

// Get current user
app.get('/api/auth/me', authMiddleware, (req, res) => {
  const user = db.prepare('SELECT id, email, created_at FROM users WHERE id = ?').get(req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json(user);
});

// ── Token endpoint (compatible with Ace Data Cloud SSO token format) ──
app.post('/sso/v1/token', authMiddleware, (req, res) => {
  // Return token in Ace Data Cloud format so the frontend's getToken() works
  res.json({
    access_token: req.headers.authorization.split(' ')[1],
    refresh_token: 'nexior-refresh',
    expires_in: 2592000 // 30 days
  });
});

// ── User endpoint (compatible with Ace Data Cloud user format) ──
app.get('/api/v1/users/me', authMiddleware, (req, res) => {
  const user = db.prepare('SELECT id, email, created_at FROM users WHERE id = ?').get(req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({
    id: user.id,
    email: user.email,
    username: user.email.split('@')[0],
    created_at: user.created_at
  });
});

// ── Site initialization (mock) ──
app.post('/api/v1/sites/initialize', authMiddleware, (req, res) => {
  const origin = req.body.origin || req.headers.origin || 'localhost';
  res.json({
    id: 1,
    origin: origin,
    title: 'Nexior Studio',
    description: 'AI Creative Hub',
    features: {
      chatgpt: { enabled: true },
      claude: { enabled: true },
      gemini: { enabled: true },
      deepseek: { enabled: true },
      midjourney: { enabled: true },
      flux: { enabled: true },
      suno: { enabled: true },
      luma: { enabled: true },
      sora: { enabled: true },
      veo: { enabled: true },
      kling: { enabled: true },
      hailuo: { enabled: true },
      pixverse: { enabled: true },
      wan: { enabled: true },
      serp: { enabled: true },
      webextrator: { enabled: true }
    },
    admins: [{ id: req.user.id, email: req.user.email }],
    theme: { primary_color: '#0891B2' }
  });
});

app.get('/api/v1/sites', authMiddleware, (req, res) => {
  const origin = req.query.origin || req.headers.origin || 'localhost';
  res.json({
    items: [{
      id: 1,
      origin: origin,
      title: 'Nexior Studio',
      features: {
        chatgpt: { enabled: true },
        claude: { enabled: true },
        gemini: { enabled: true },
        deepseek: { enabled: true },
        midjourney: { enabled: true },
        flux: { enabled: true },
        suno: { enabled: true },
        luma: { enabled: true },
        sora: { enabled: true },
        veo: { enabled: true }
      }
    }]
  });
});

// ── Proxy to Ace Data Cloud Platform ──
// All /api/* calls that we don't handle locally are proxied to Ace Data Cloud
const platformProxy = createProxyMiddleware({
  target: 'https://platform.acedata.cloud',
  changeOrigin: true,
  on: {
    proxyReq: (proxyReq, req, res) => {
      // Forward user's auth if present, otherwise use master API key
      if (req.headers.authorization) {
        proxyReq.setHeader('Authorization', req.headers.authorization);
      }
      if (ACE_DATA_API_KEY) {
        proxyReq.setHeader('X-API-Key', ACE_DATA_API_KEY);
      }
      // Forward important headers
      if (req.headers['x-fingerprint']) proxyReq.setHeader('X-Fingerprint', req.headers['x-fingerprint']);
      if (req.headers['x-user-id']) proxyReq.setHeader('X-User-Id', req.headers['x-user-id']);
    },
    proxyRes: (proxyRes, req, res) => {
      // Allow CORS from anywhere
      proxyRes.headers['access-control-allow-origin'] = '*';
    }
  }
});

// Auth proxy (handles the Ace Data Cloud auth endpoints)
const authProxy = createProxyMiddleware({
  target: 'https://auth.acedata.cloud',
  changeOrigin: true,
  on: {
    proxyRes: (proxyRes, req, res) => {
      proxyRes.headers['access-control-allow-origin'] = '*';
    }
  }
});

// Also proxy to Ace Data Cloud API
const apiProxy = createProxyMiddleware({
  target: 'https://api.acedata.cloud',
  changeOrigin: true,
  on: {
    proxyRes: (proxyRes, req, res) => {
      proxyRes.headers['access-control-allow-origin'] = '*';
    }
  }
});

// Proxy /api/* to Ace Data Cloud (except our auth endpoints)
app.use('/api', (req, res, next) => {
  // Our local endpoints take priority
  if (req.path.startsWith('/auth/') || req.path.startsWith('/v1/users/me') || req.path.startsWith('/v1/sites')) {
    return next();
  }
  platformProxy(req, res, next);
});

// Proxy SSO to Ace Data Cloud (except our token endpoint)
app.use('/sso', (req, res, next) => {
  if (req.path === '/v1/token' && req.method === 'POST') {
    return next();
  }
  authProxy(req, res, next);
});

// Proxy auth endpoints we don't handle
app.use('/api/v1/auth', (req, res, next) => {
  if (req.path === '/register' || req.path === '/login') {
    return next();
  }
  authProxy(req, res, next);
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', users: db.prepare('SELECT COUNT(*) as count FROM users').get().count });
});

// Start
app.listen(PORT, () => {
  console.log(`Nexior Auth Proxy running on port ${PORT}`);
  console.log(`Endpoints:`);
  console.log(`  POST /api/auth/register  - Register new user`);
  console.log(`  POST /api/auth/login     - Login`);
  console.log(`  GET  /api/auth/me        - Get current user (auth required)`);
  console.log(`  POST /sso/v1/token       - Get token (auth required)`);
  console.log(`  GET  /api/v1/users/me    - Get user profile (auth required)`);
  console.log(`  POST /api/v1/sites/initialize - Initialize site`);
  console.log(`  GET  /api/v1/sites       - Get sites`);
  console.log(`  /api/*                   - Proxied to platform.acedata.cloud`);
});

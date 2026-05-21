const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const Database = require('better-sqlite3');
const { createProxyMiddleware } = require('http-proxy-middleware');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'nexior-studio-secret-change-in-production';
const ACE_DATA_API_KEY = process.env.ACE_DATA_API_KEY || '';

// ── Login page HTML ──
const LOGIN_PAGE = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Nexior Studio — Login</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:system-ui,-apple-system,sans-serif;background:#0B1120;color:#F1F5F9;display:grid;place-items:center;min-height:100vh}
.card{background:#111827;border:1px solid #1E293B;border-radius:16px;padding:40px;width:100%;max-width:400px;box-shadow:0 20px 60px rgba(0,0,0,.5)}
h1{font-size:1.5rem;margin-bottom:8px;text-align:center}
p{color:#94A3B8;text-align:center;margin-bottom:24px;font-size:.9rem}
label{display:block;margin-bottom:4px;font-size:.85rem;color:#CBD5E1}
input{width:100%;padding:12px;background:#1A2235;border:1px solid #334155;border-radius:8px;color:white;font-size:1rem;margin-bottom:12px}
input:focus{outline:none;border-color:#0891B2}
button{width:100%;padding:12px;background:linear-gradient(135deg,#2563EB,#0891B2);color:white;border:none;border-radius:8px;font-size:1rem;font-weight:600;cursor:pointer;margin-top:8px}
button:hover{opacity:.9}
button.secondary{background:#334155;margin-top:4px}
.error{color:#EF4444;text-align:center;margin-bottom:12px;font-size:.85rem}
.success{color:#10B981;text-align:center;margin-bottom:12px;font-size:.85rem}
a{color:#0891B2;text-decoration:none}
.toggle{text-align:center;margin-top:16px;font-size:.85rem;color:#94A3B8}
.forgot{text-align:right;margin-bottom:16px;font-size:.8rem}
.forgot a{color:#64748B}
.forgot a:hover{color:#0891B2}
.back{text-align:center;margin-top:12px;font-size:.8rem}
</style>
</head>
<body>
<div class="card">
<h1>Nexior Studio</h1>
<p>AI Creative Hub</p>
<div id="error" class="error" style="display:none"></div>
<div id="success" class="success" style="display:none"></div>

<!-- Login Form -->
<form id="loginForm" style="display:none">
<label>Email</label>
<input type="email" id="loginEmail" required>
<label>Password</label>
<input type="password" id="loginPassword" required minlength="6">
<div class="forgot"><a href="#" id="forgotLink">Forgot password?</a></div>
<button type="submit">Sign In</button>
</form>

<!-- Register Form -->
<form id="registerForm" style="display:none">
<label>Email</label>
<input type="email" id="registerEmail" required>
<label>Password</label>
<input type="password" id="registerPassword" required minlength="6">
<label>Confirm Password</label>
<input type="password" id="registerPasswordConfirm" required minlength="6">
<button type="submit">Create Account</button>
</form>

<!-- Forgot Password Form -->
<form id="forgotForm" style="display:none">
<label>Email</label>
<input type="email" id="forgotEmail" required>
<button type="submit">Send Reset Link</button>
<p class="back"><a href="#" id="backToLogin">← Back to login</a></p>
</form>

<!-- Reset Password Form -->
<form id="resetForm" style="display:none">
<label>New Password</label>
<input type="password" id="resetPassword" required minlength="6">
<label>Confirm New Password</label>
<input type="password" id="resetPasswordConfirm" required minlength="6">
<button type="submit">Reset Password</button>
</form>

<p class="toggle"><a href="#" id="toggleLink">Create an account</a></p>
</div>
<script>
const params=new URLSearchParams(window.location.search);
const redirect=params.get('redirect')||'/';
const site=params.get('site')||'';
const resetToken=params.get('reset_token')||'';
let mode='login';

function showError(msg){const e=document.getElementById('error');e.textContent=msg;e.style.display='block';document.getElementById('success').style.display='none'}
function showSuccess(msg){const e=document.getElementById('success');e.textContent=msg;e.style.display='block';document.getElementById('error').style.display='none'}
function hideMessages(){document.getElementById('error').style.display='none';document.getElementById('success').style.display='none'}

function showForm(name){
  document.getElementById('loginForm').style.display='none';
  document.getElementById('registerForm').style.display='none';
  document.getElementById('forgotForm').style.display='none';
  document.getElementById('resetForm').style.display='none';
  document.getElementById(name).style.display='block';
  hideMessages();
}

// Toggle login/register
document.getElementById('toggleLink').addEventListener('click',e=>{
e.preventDefault();
if(mode==='login'){mode='register';showForm('registerForm');document.getElementById('toggleLink').textContent='Already have an account?'}
else{mode='login';showForm('loginForm');document.getElementById('toggleLink').textContent='Create an account'}
});

// Forgot password link
document.getElementById('forgotLink').addEventListener('click',e=>{
e.preventDefault();
mode='forgot';
showForm('forgotForm');
document.getElementById('toggleLink').style.display='none';
});

// Back to login
document.getElementById('backToLogin').addEventListener('click',e=>{
e.preventDefault();
mode='login';
showForm('loginForm');
document.getElementById('toggleLink').style.display='block';
});

// Login submit
document.getElementById('loginForm').addEventListener('submit',async e=>{
e.preventDefault();hideMessages();
const email=document.getElementById('loginEmail').value;
const password=document.getElementById('loginPassword').value;
const res=await fetch('/api/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email,password})});
const data=await res.json();
if(!res.ok){showError(data.error||'Login failed');return}
window.location.href=redirect+(redirect.includes('?')?'&':'?')+'code='+data.token+(site?'&site='+site:'');
});

// Register submit
document.getElementById('registerForm').addEventListener('submit',async e=>{
e.preventDefault();hideMessages();
const email=document.getElementById('registerEmail').value;
const password=document.getElementById('registerPassword').value;
const confirm=document.getElementById('registerPasswordConfirm').value;
if(password!==confirm){showError('Passwords do not match');return}
const res=await fetch('/api/auth/register',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email,password,password_confirm:confirm})});
const data=await res.json();
if(!res.ok){showError(data.error||'Registration failed');return}
window.location.href=redirect+(redirect.includes('?')?'&':'?')+'code='+data.token+(site?'&site='+site:'');
});

// Forgot password submit
document.getElementById('forgotForm').addEventListener('submit',async e=>{
e.preventDefault();hideMessages();
const email=document.getElementById('forgotEmail').value;
const res=await fetch('/api/auth/forgot-password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email})});
const data=await res.json();
if(!res.ok){showError(data.error||'Request failed');return}
showSuccess(data.message||'If the email exists, a reset link has been generated.');
});

// Reset password submit
document.getElementById('resetForm').addEventListener('submit',async e=>{
e.preventDefault();hideMessages();
const password=document.getElementById('resetPassword').value;
const confirm=document.getElementById('resetPasswordConfirm').value;
if(password!==confirm){showError('Passwords do not match');return}
if(!resetToken){showError('No reset token provided');return}
const res=await fetch('/api/auth/reset-password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:resetToken,password,password_confirm:confirm})});
const data=await res.json();
if(!res.ok){showError(data.error||'Reset failed');return}
showSuccess('Password reset successfully!');
setTimeout(()=>{
mode='login';
showForm('loginForm');
document.getElementById('toggleLink').style.display='block';
},1500);
});

// Init
if(resetToken){
  mode='reset';
  showForm('resetForm');
  document.getElementById('toggleLink').style.display='none';
} else {
  showForm('loginForm');
}
</script>
</body>
</html>`;

// ── Database ──
const db = new Database('users.db');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    reset_token TEXT,
    reset_token_expires TEXT,
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

// Login page (HTML)
app.get('/auth/login', (req, res) => {
  res.send(LOGIN_PAGE);
});

// Logout
app.get('/auth/logout', (req, res) => {
  const redirect = req.query.redirect || '/';
  res.redirect(redirect);
});

// Register
app.post('/api/auth/register', async (req, res) => {
  const { email, password, password_confirm } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  }
  if (password_confirm && password !== password_confirm) {
    return res.status(400).json({ error: 'Passwords do not match' });
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

// Forgot password — generate reset token
app.post('/api/auth/forgot-password', (req, res) => {
  const { email } = req.body;
  if (!email) {
    return res.status(400).json({ error: 'Email required' });
  }
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user) {
    // Don't reveal if email exists — but still return success
    return res.json({ message: 'If this email is registered, a reset link has been generated. Check your inbox.' });
  }
  const resetToken = crypto.randomBytes(32).toString('hex');
  const expires = new Date(Date.now() + 3600000).toISOString(); // 1 hour
  db.prepare('UPDATE users SET reset_token = ?, reset_token_expires = ? WHERE id = ?').run(resetToken, expires, user.id);
  // Since we don't have email, include the reset URL in the response
  const resetUrl = `https://nexior-auth-proxy.onrender.com/auth/login?reset_token=${resetToken}`;
  res.json({
    message: 'Password reset link generated.',
    reset_url: resetUrl,
    reset_token: resetToken,
    note: 'Email delivery not configured yet. Use the reset_url to reset your password.'
  });
});

// Reset password — consume reset token
app.post('/api/auth/reset-password', async (req, res) => {
  const { token, password, password_confirm } = req.body;
  if (!token || !password) {
    return res.status(400).json({ error: 'Token and new password required' });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  }
  if (password_confirm && password !== password_confirm) {
    return res.status(400).json({ error: 'Passwords do not match' });
  }
  const user = db.prepare('SELECT * FROM users WHERE reset_token = ?').get(token);
  if (!user) {
    return res.status(400).json({ error: 'Invalid or expired reset token' });
  }
  if (user.reset_token_expires && new Date(user.reset_token_expires) < new Date()) {
    return res.status(400).json({ error: 'Reset token has expired. Please request a new one.' });
  }
  const hash = await bcrypt.hash(password, 10);
  db.prepare('UPDATE users SET password = ?, reset_token = NULL, reset_token_expires = NULL WHERE id = ?').run(hash, user.id);
  res.json({ message: 'Password reset successfully. You can now login.' });
});

// Get current user
app.get('/api/auth/me', authMiddleware, (req, res) => {
  const user = db.prepare('SELECT id, email, created_at FROM users WHERE id = ?').get(req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json(user);
});

// ── Token endpoint ──
app.post('/sso/v1/token', (req, res) => {
  const { code } = req.body;
  if (!code) {
    return res.status(400).json({ error: 'Code required' });
  }
  try {
    jwt.verify(code, JWT_SECRET);
    res.json({
      access_token: code,
      refresh_token: 'nexior-refresh',
      expires_in: 2592000
    });
  } catch (err) {
    return res.status(401).json({ error: 'Invalid code' });
  }
});

// ── User endpoint ──
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

// ── Site initialization ──
app.post('/api/v1/sites/initialize', authMiddleware, (req, res) => {
  const origin = req.body.origin || req.headers.origin || 'localhost';
  res.json({
    id: 1,
    origin: origin,
    title: 'Nexior Studio',
    description: 'AI Creative Hub',
    features: {
      chatgpt: { enabled: true }, claude: { enabled: true }, gemini: { enabled: true },
      deepseek: { enabled: true }, midjourney: { enabled: true }, flux: { enabled: true },
      suno: { enabled: true }, luma: { enabled: true }, sora: { enabled: true },
      veo: { enabled: true }, kling: { enabled: true }, hailuo: { enabled: true },
      pixverse: { enabled: true }, wan: { enabled: true }, serp: { enabled: true },
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
      id: 1, origin: origin, title: 'Nexior Studio',
      features: {
        chatgpt: { enabled: true }, claude: { enabled: true }, gemini: { enabled: true },
        deepseek: { enabled: true }, midjourney: { enabled: true }, flux: { enabled: true },
        suno: { enabled: true }, luma: { enabled: true }, sora: { enabled: true },
        veo: { enabled: true }
      }
    }]
  });
});

// ── Proxy to Ace Data Cloud ──
const platformProxy = createProxyMiddleware({
  target: 'https://platform.acedata.cloud',
  changeOrigin: true,
  on: {
    proxyReq: (proxyReq, req, res) => {
      if (req.headers.authorization) proxyReq.setHeader('Authorization', req.headers.authorization);
      if (ACE_DATA_API_KEY) proxyReq.setHeader('X-API-Key', ACE_DATA_API_KEY);
      if (req.headers['x-fingerprint']) proxyReq.setHeader('X-Fingerprint', req.headers['x-fingerprint']);
      if (req.headers['x-user-id']) proxyReq.setHeader('X-User-Id', req.headers['x-user-id']);
    },
    proxyRes: (proxyRes, req, res) => {
      proxyRes.headers['access-control-allow-origin'] = '*';
    }
  }
});

const authProxy = createProxyMiddleware({
  target: 'https://auth.acedata.cloud',
  changeOrigin: true,
  on: {
    proxyRes: (proxyRes, req, res) => {
      proxyRes.headers['access-control-allow-origin'] = '*';
    }
  }
});

app.use('/api', (req, res, next) => {
  if (req.path.startsWith('/auth/') || req.path.startsWith('/v1/users/me') || req.path.startsWith('/v1/sites')) {
    return next();
  }
  platformProxy(req, res, next);
});

app.use('/sso', (req, res, next) => {
  if (req.path === '/v1/token' && req.method === 'POST') return next();
  authProxy(req, res, next);
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', users: db.prepare('SELECT COUNT(*) as count FROM users').get().count });
});

// Start
app.listen(PORT, () => {
  console.log(`Nexior Auth Proxy running on port ${PORT}`);
});

// ═══════════════════════════════════════════════════════════════
//  IZLOM AI v2 — Backend Server (FULL)
//  npm install express nodemailer cors axios express-rate-limit
//              express-session bcryptjs uuid helmet
//  Node.js 18+
// ═══════════════════════════════════════════════════════════════

const express     = require('express');
const nodemailer  = require('nodemailer');
const cors        = require('cors');
const path        = require('path');
const bcrypt      = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const rateLimit   = require('express-rate-limit');
const session     = require('express-session');
const helmet      = require('helmet');
const axios       = require('axios');

const app  = express();
const PORT = process.env.PORT || 3000;

// ═══════════════════════════════════════════════════════════
//  ⚡ КОНФИГУРАЦИЯ — ЗАПОЛНИ ВСЁ НИЖЕ
// ═══════════════════════════════════════════════════════════

const CONFIG = {

  // ── Claude API ключи (ротация автоматически) ──
  CLAUDE_KEYS: [
    "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",
    "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",
    "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",
    "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",
  ],

  // ── SMTP ──
  SMTP: {
    host: 'connect.smtp.bz',
    port: 587,
    secure: false,
    auth: { user: 'auth@izlomc.ru', pass: 'CQH9oAhn41cQ' },
    tls: { rejectUnauthorized: false }
  },
  FROM_EMAIL: 'IZLOM AI <auth@izlomc.ru>',

  // ── Домен сайта (для ссылок в письмах и OAuth redirect) ──
  // В продакшне: 'https://izlomai.ru'
  SITE_URL: process.env.SITE_URL || `http://localhost:${PORT}`,

  // ── Google OAuth ──
  // Получить: https://console.cloud.google.com/ → APIs & Services → Credentials
  // Создать: OAuth 2.0 Client ID → Web application
  // Authorized redirect URI: https://твой-домен.com/api/auth/google/callback
  GOOGLE_CLIENT_ID:     process.env.GOOGLE_CLIENT_ID     || 'ВСТАВЬ_GOOGLE_CLIENT_ID',
  GOOGLE_CLIENT_SECRET: process.env.GOOGLE_CLIENT_SECRET || 'ВСТАВЬ_GOOGLE_CLIENT_SECRET',

  // ── Telegram Bot ──
  // Получить: написать @BotFather в Telegram → /newbot
  // Потом: /setdomain → указать домен сайта (для Login Widget)
  TELEGRAM_BOT_TOKEN: process.env.TELEGRAM_BOT_TOKEN || 'ВСТАВЬ_TELEGRAM_BOT_TOKEN',
  // Имя бота (без @): например izlomai_bot
  TELEGRAM_BOT_NAME:  process.env.TELEGRAM_BOT_NAME  || 'ВСТАВЬ_ИМЯ_БОТА',

  // ── Google reCAPTCHA v3 ──
  // Получить: https://www.google.com/recaptcha/admin/create
  // Тип: reCAPTCHA v3, домены: твой-домен.com + localhost
  RECAPTCHA_SECRET:   process.env.RECAPTCHA_SECRET   || 'ВСТАВЬ_RECAPTCHA_SECRET_KEY',
  RECAPTCHA_SITE_KEY: process.env.RECAPTCHA_SITE_KEY || 'ВСТАВЬ_RECAPTCHA_SITE_KEY',

  // ── Brave Search API (для поиска) ──
  // Получить: https://api.search.brave.com/ → бесплатно 2000 req/month
  // Если не хочешь платить — оставь '', поиск будет через DuckDuckGo (без ключа)
  BRAVE_SEARCH_KEY: process.env.BRAVE_SEARCH_KEY || '',

  // ── Session secret (любая длинная случайная строка) ──
  SESSION_SECRET: process.env.SESSION_SECRET || 'izlom_ai_super_secret_change_this_2025_' + Math.random(),
};

// ═══════════════════════════════════════════════════════════
//  IN-MEMORY DB (в продакшне замени на MongoDB/PostgreSQL)
// ═══════════════════════════════════════════════════════════
const DB = {
  users:        new Map(), // email → user object
  sessions:     new Map(), // sessionId → { userId, createdAt }
  emailTokens:  new Map(), // token → { email, type, expires }
  rateLimits:   new Map(), // ip → { count, resetAt }
};

// ═══════════════════════════════════════════════════════════
//  KEY ROTATION
// ═══════════════════════════════════════════════════════════
let keyIdx = 0;
const keyStats = CONFIG.CLAUDE_KEYS.map((_, i) => ({ i, uses: 0, errors: 0, lastError: 0 }));

function getKey() {
  for (let t = 0; t < CONFIG.CLAUDE_KEYS.length; t++) {
    const s = keyStats[keyIdx];
    keyIdx = (keyIdx + 1) % CONFIG.CLAUDE_KEYS.length;
    // Skip key if 5+ errors in last 5 min
    if (s.errors < 5 || Date.now() - s.lastError > 300000) {
      s.uses++;
      return { key: CONFIG.CLAUDE_KEYS[s.i], stat: s };
    }
  }
  keyStats.forEach(s => { s.errors = 0; });
  return { key: CONFIG.CLAUDE_KEYS[0], stat: keyStats[0] };
}

// ═══════════════════════════════════════════════════════════
//  MIDDLEWARE
// ═══════════════════════════════════════════════════════════
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: CONFIG.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, maxAge: 30 * 24 * 60 * 60 * 1000, sameSite: 'lax' }
}));
app.use(express.static(path.join(__dirname, 'public')));

// Rate limiter для auth
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 20,
  message: { error: 'Слишком много попыток. Подождите 15 минут.' }
});
const chatLimiter = rateLimit({
  windowMs: 60 * 1000, max: 30,
  message: { error: 'Слишком много запросов. Подождите минуту.' }
});

// ─── Auth middleware ───
function requireAuth(req, res, next) {
  const sid = req.headers['x-session'] || req.session?.sid;
  if (!sid || !DB.sessions.has(sid)) return res.status(401).json({ error: 'Не авторизован' });
  const s = DB.sessions.get(sid);
  if (Date.now() - s.createdAt > 30 * 24 * 60 * 60 * 1000) {
    DB.sessions.delete(sid); return res.status(401).json({ error: 'Сессия истекла' });
  }
  req.userId = s.email;
  req.user = DB.users.get(s.email);
  if (!req.user) return res.status(401).json({ error: 'Пользователь не найден' });
  next();
}

// ═══════════════════════════════════════════════════════════
//  HELPERS
// ═══════════════════════════════════════════════════════════
const mailer = nodemailer.createTransport(CONFIG.SMTP);
mailer.verify(err => {
  if (err) console.error('❌ SMTP:', err.message);
  else     console.log('✅ SMTP:', CONFIG.SMTP.host + ':' + CONFIG.SMTP.port);
});

function makeToken(len = 32) {
  return uuidv4().replace(/-/g,'') + uuidv4().replace(/-/g,'').slice(0, len - 32);
}
function makeSession(email) {
  const id = uuidv4();
  DB.sessions.set(id, { email, createdAt: Date.now() });
  return id;
}

async function verifyRecaptcha(token, ip) {
  if (!token || CONFIG.RECAPTCHA_SECRET === 'ВСТАВЬ_RECAPTCHA_SECRET_KEY') return true; // Skip if not configured
  try {
    const r = await axios.post('https://www.google.com/recaptcha/api/siteverify', null, {
      params: { secret: CONFIG.RECAPTCHA_SECRET, response: token, remoteip: ip }
    });
    return r.data.success && (r.data.score || 1) >= 0.5;
  } catch { return true; }
}

// Email templates
function emailHTML(title, body, btnUrl, btnText) {
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width"></head>
<body style="background:#080810;margin:0;padding:30px 15px;font-family:Arial,sans-serif">
<div style="max-width:520px;margin:0 auto;background:#111122;border-radius:20px;border:1px solid rgba(124,92,252,.3);overflow:hidden">
  <div style="background:linear-gradient(135deg,#7c5cfc,#e879f9);padding:28px;text-align:center">
    <div style="font-size:32px">⚡</div>
    <h1 style="color:#fff;margin:8px 0 0;font-size:26px;letter-spacing:-0.5px">IZLOM AI</h1>
    <p style="color:rgba(255,255,255,.75);margin:4px 0 0;font-size:12px;letter-spacing:1px">v2 · Intelligence Platform</p>
  </div>
  <div style="padding:30px">
    <h2 style="color:#eeeef8;margin-top:0;font-size:20px">${title}</h2>
    <div style="color:#9090b8;line-height:1.7;font-size:15px">${body}</div>
    ${btnUrl ? `<div style="text-align:center;margin-top:28px">
      <a href="${btnUrl}" style="background:linear-gradient(135deg,#7c5cfc,#9333ea);color:#fff;padding:14px 32px;border-radius:12px;text-decoration:none;font-weight:700;font-size:15px;display:inline-block">${btnText}</a>
    </div>` : ''}
  </div>
  <div style="padding:18px 30px;border-top:1px solid rgba(255,255,255,.06);text-align:center;color:#505070;font-size:12px">
    © ${new Date().getFullYear()} IZLOM AI · Все права защищены<br>
    <small>Если вы не запрашивали это письмо — просто проигнорируйте его</small>
  </div>
</div></body></html>`;
}

// ═══════════════════════════════════════════════════════════
//  AUTH ROUTES
// ═══════════════════════════════════════════════════════════

// ── Регистрация ──
app.post('/api/auth/register', authLimiter, async (req, res) => {
  try {
    const { name, email, password, captcha } = req.body;
    if (!name?.trim() || !email?.trim() || !password) return res.status(400).json({ error: 'Заполните все поля' });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'Некорректный email' });
    if (password.length < 6) return res.status(400).json({ error: 'Пароль минимум 6 символов' });
    if (DB.users.has(email.toLowerCase())) return res.status(400).json({ error: 'Email уже зарегистрирован' });

    // reCAPTCHA check
    const captchaOk = await verifyRecaptcha(captcha, req.ip);
    if (!captchaOk) return res.status(400).json({ error: 'Проверка безопасности не пройдена. Попробуйте снова.' });

    const hash = await bcrypt.hash(password, 12);
    const token = makeToken();

    DB.users.set(email.toLowerCase(), {
      name: name.trim(), email: email.toLowerCase(),
      hash, verified: false, createdAt: Date.now(),
      provider: 'email', avatar: name.trim()[0].toUpperCase()
    });
    DB.emailTokens.set(token, { email: email.toLowerCase(), type: 'verify', expires: Date.now() + 24 * 3600000 });

    const link = `${CONFIG.SITE_URL}/api/auth/verify/${token}`;
    await mailer.sendMail({
      from: CONFIG.FROM_EMAIL, to: email,
      subject: '⚡ Подтвердите email — IZLOM AI',
      html: emailHTML('Подтверждение регистрации',
        `<p>Привет, <strong>${name.trim()}</strong>! 👋</p>
         <p>Вы зарегистрировались в <strong>IZLOM AI v2</strong>. Нажмите кнопку ниже, чтобы подтвердить ваш email.</p>
         <p>Ссылка действительна <strong>24 часа</strong>.</p>`,
        link, '✅ Подтвердить Email')
    });

    res.json({ ok: true, message: `Письмо отправлено на ${email}. Проверьте почту.` });
  } catch(e) {
    console.error('Register error:', e);
    res.status(500).json({ error: 'Ошибка сервера: ' + e.message });
  }
});

// ── Подтверждение email ──
app.get('/api/auth/verify/:token', (req, res) => {
  const data = DB.emailTokens.get(req.params.token);
  if (!data || data.type !== 'verify' || Date.now() > data.expires) {
    return res.send(infoPage('❌ Ссылка недействительна', 'Ссылка истекла или уже была использована. Зарегистрируйтесь снова.', false));
  }
  const user = DB.users.get(data.email);
  if (user) { user.verified = true; }
  DB.emailTokens.delete(req.params.token);
  res.send(infoPage('✅ Email подтверждён!', 'Теперь вы можете войти в IZLOM AI v2.', true));
});

// ── Вход ──
app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const { email, password, captcha } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Введите email и пароль' });

    const captchaOk = await verifyRecaptcha(captcha, req.ip);
    if (!captchaOk) return res.status(400).json({ error: 'Проверка безопасности не пройдена.' });

    const user = DB.users.get(email.toLowerCase());
    if (!user || user.provider !== 'email') return res.status(401).json({ error: 'Неверный email или пароль' });

    const ok = await bcrypt.compare(password, user.hash);
    if (!ok) return res.status(401).json({ error: 'Неверный email или пароль' });
    if (!user.verified) return res.status(403).json({ error: 'Подтвердите email. Проверьте почту.' });

    const sid = makeSession(email.toLowerCase());
    res.json({ ok: true, session: sid, user: { name: user.name, email: user.email, avatar: user.avatar } });
  } catch(e) {
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// ── Сброс пароля — запрос ──
app.post('/api/auth/forgot', authLimiter, async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Введите email' });
    const user = DB.users.get(email.toLowerCase());
    if (!user || user.provider !== 'email') return res.json({ ok: true }); // silent

    const token = makeToken();
    DB.emailTokens.set(token, { email: email.toLowerCase(), type: 'reset', expires: Date.now() + 3600000 });
    const link = `${CONFIG.SITE_URL}/?reset=${token}`;

    await mailer.sendMail({
      from: CONFIG.FROM_EMAIL, to: email,
      subject: '🔑 Сброс пароля — IZLOM AI',
      html: emailHTML('Сброс пароля',
        `<p>Мы получили запрос на сброс пароля для аккаунта <strong>${email}</strong>.</p>
         <p>Ссылка действительна <strong>1 час</strong>. Если вы не запрашивали сброс — проигнорируйте это письмо.</p>`,
        link, '🔑 Сбросить пароль')
    });
    res.json({ ok: true });
  } catch(e) {
    res.status(500).json({ error: 'Ошибка отправки письма' });
  }
});

// ── Сброс пароля — установка ──
app.post('/api/auth/reset', authLimiter, async (req, res) => {
  const { token, password } = req.body;
  const data = DB.emailTokens.get(token);
  if (!data || data.type !== 'reset' || Date.now() > data.expires)
    return res.status(400).json({ error: 'Ссылка недействительна или истекла' });
  if (!password || password.length < 6)
    return res.status(400).json({ error: 'Пароль минимум 6 символов' });
  const user = DB.users.get(data.email);
  if (!user) return res.status(404).json({ error: 'Пользователь не найден' });
  user.hash = await bcrypt.hash(password, 12);
  DB.emailTokens.delete(token);
  res.json({ ok: true });
});

// ── Выход ──
app.post('/api/auth/logout', (req, res) => {
  const sid = req.headers['x-session'];
  if (sid) DB.sessions.delete(sid);
  res.json({ ok: true });
});

// ── Текущий пользователь ──
app.get('/api/auth/me', requireAuth, (req, res) => {
  res.json({ name: req.user.name, email: req.user.email, avatar: req.user.avatar, provider: req.user.provider });
});

// ═══════════════════════════════════════════════════════════
//  GOOGLE OAUTH
// ═══════════════════════════════════════════════════════════
// ШАГИ ДЛЯ НАСТРОЙКИ GOOGLE:
// 1. Зайди на https://console.cloud.google.com/
// 2. Создай проект (или выбери существующий)
// 3. APIs & Services → Credentials → + CREATE CREDENTIALS → OAuth 2.0 Client ID
// 4. Application type: Web application
// 5. Authorized redirect URIs: https://твой-домен.com/api/auth/google/callback
//    (и http://localhost:3000/api/auth/google/callback для теста)
// 6. Скопируй Client ID и Client Secret → вставь в CONFIG выше
// 7. APIs & Services → OAuth consent screen → заполни название "IZLOM AI"

app.get('/api/auth/google', (req, res) => {
  if (CONFIG.GOOGLE_CLIENT_ID === 'ВСТАВЬ_GOOGLE_CLIENT_ID') {
    return res.redirect('/?error=google_not_configured');
  }
  const params = new URLSearchParams({
    client_id: CONFIG.GOOGLE_CLIENT_ID,
    redirect_uri: `${CONFIG.SITE_URL}/api/auth/google/callback`,
    response_type: 'code',
    scope: 'openid email profile',
    access_type: 'offline',
    prompt: 'select_account'
  });
  res.redirect('https://accounts.google.com/o/oauth2/v2/auth?' + params);
});

app.get('/api/auth/google/callback', async (req, res) => {
  const { code, error } = req.query;
  if (error || !code) return res.redirect('/?error=google_denied');
  try {
    // Exchange code → tokens
    const tokenRes = await axios.post('https://oauth2.googleapis.com/token', {
      code, client_id: CONFIG.GOOGLE_CLIENT_ID,
      client_secret: CONFIG.GOOGLE_CLIENT_SECRET,
      redirect_uri: `${CONFIG.SITE_URL}/api/auth/google/callback`,
      grant_type: 'authorization_code'
    });
    const { access_token } = tokenRes.data;
    // Get user info
    const userRes = await axios.get('https://www.googleapis.com/oauth2/v2/userinfo', {
      headers: { Authorization: `Bearer ${access_token}` }
    });
    const { email, name, picture } = userRes.data;
    const key = email.toLowerCase();
    if (!DB.users.has(key)) {
      DB.users.set(key, { name, email: key, verified: true, provider: 'google', avatar: name[0].toUpperCase(), createdAt: Date.now(), picture });
    } else {
      DB.users.get(key).provider = 'google'; // update
    }
    const sid = makeSession(key);
    // Redirect with session in URL (frontend stores it)
    res.redirect(`/?session=${sid}&user=${encodeURIComponent(JSON.stringify({ name, email: key, avatar: name[0].toUpperCase() }))}`);
  } catch(e) {
    console.error('Google OAuth error:', e.response?.data || e.message);
    res.redirect('/?error=google_failed');
  }
});

// ═══════════════════════════════════════════════════════════
//  TELEGRAM AUTH
// ═══════════════════════════════════════════════════════════
// ШАГИ ДЛЯ НАСТРОЙКИ TELEGRAM:
// 1. Напиши @BotFather в Telegram
// 2. /newbot → придумай имя и username (например izlomai_bot)
// 3. Получишь токен — вставь в CONFIG.TELEGRAM_BOT_TOKEN
// 4. /setdomain → @твой_бот → укажи домен без https:// (например izlomai.ru)
//    ⚠️ localhost НЕ работает — нужен реальный домен с HTTPS
// 5. Вставь username в CONFIG.TELEGRAM_BOT_NAME (без @)

const crypto = require('crypto');

app.post('/api/auth/telegram', authLimiter, (req, res) => {
  if (CONFIG.TELEGRAM_BOT_TOKEN === 'ВСТАВЬ_TELEGRAM_BOT_TOKEN') {
    // Demo mode — create user without verification
    const { id, first_name, last_name, username } = req.body;
    if (!id) return res.status(400).json({ error: 'Нет данных Telegram' });
    const email = `tg_${id}@izlom.ai`;
    const name = [first_name, last_name].filter(Boolean).join(' ') || username || `TG${id}`;
    if (!DB.users.has(email)) {
      DB.users.set(email, { name, email, verified: true, provider: 'telegram', avatar: name[0].toUpperCase(), createdAt: Date.now(), telegramId: id });
    }
    const sid = makeSession(email);
    return res.json({ ok: true, session: sid, user: { name, email, avatar: name[0].toUpperCase() } });
  }

  // Real Telegram verification
  const data = req.body;
  const checkHash = data.hash;
  delete data.hash;

  const dataCheckString = Object.keys(data).sort().map(k => `${k}=${data[k]}`).join('\n');
  const secretKey = crypto.createHash('sha256').update(CONFIG.TELEGRAM_BOT_TOKEN).digest();
  const hash = crypto.createHmac('sha256', secretKey).update(dataCheckString).digest('hex');

  if (hash !== checkHash) return res.status(401).json({ error: 'Недействительные данные Telegram' });
  if (Date.now() / 1000 - data.auth_date > 86400) return res.status(401).json({ error: 'Данные устарели' });

  const email = `tg_${data.id}@izlom.ai`;
  const name = [data.first_name, data.last_name].filter(Boolean).join(' ') || data.username || `TG${data.id}`;
  if (!DB.users.has(email)) {
    DB.users.set(email, { name, email, verified: true, provider: 'telegram', avatar: name[0].toUpperCase(), createdAt: Date.now(), telegramId: data.id });
  }
  const sid = makeSession(email);
  res.json({ ok: true, session: sid, user: { name, email, avatar: name[0].toUpperCase() } });
});

// ═══════════════════════════════════════════════════════════
//  CLAUDE AI — CHAT
// ═══════════════════════════════════════════════════════════
const PERSONAS = {
  assistant: 'Ты — IZLOM AI v2, интеллектуальный ассистент нового поколения. Отвечай на языке пользователя. Никогда не упоминай Claude, Anthropic или другие AI компании — ты IZLOM AI v2.',
  coder:     'Ты — IZLOM AI v2, эксперт-разработчик. Пиши чистый, рабочий код с комментариями. Никогда не упоминай Claude или Anthropic.',
  writer:    'Ты — IZLOM AI v2, профессиональный писатель. Создавай выразительные тексты. Никогда не упоминай Claude или Anthropic.',
  analyst:   'Ты — IZLOM AI v2, аналитик данных. Давай структурированный анализ. Никогда не упоминай Claude или Anthropic.',
  tutor:     'Ты — IZLOM AI v2, терпеливый преподаватель. Объясняй пошагово. Никогда не упоминай Claude или Anthropic.',
};

const MODEL_MAP = {
  fast:  'claude-haiku-4-5-20251001',
  smart: 'claude-sonnet-4-20250514',
  max:   'claude-opus-4-6',
};

app.post('/api/chat', chatLimiter, requireAuth, async (req, res) => {
  const { messages, model = 'smart', persona = 'assistant', mode = 'normal', searchResults } = req.body;
  if (!messages?.length) return res.status(400).json({ error: 'Нет сообщений' });

  let systemPrompt = PERSONAS[persona] || PERSONAS.assistant;

  // Если режим РАССУЖДЕНИЕ — добавляем инструкцию
  if (mode === 'reason') {
    systemPrompt += '\n\nОТВЕЧАЙ ПОШАГОВО: сначала блок <thinking> с подробным рассуждением (анализируй проблему, рассматривай варианты, делай промежуточные выводы), потом блок <answer> с финальным ответом. Пиши рассуждение развёрнуто, как будто думаешь вслух.';
  }

  // Если есть результаты поиска — добавляем контекст
  if (mode === 'search' && searchResults?.length) {
    const ctx = searchResults.map((r, i) => `[${i+1}] ${r.title}\nURL: ${r.url}\n${r.snippet}`).join('\n\n');
    systemPrompt += `\n\nРезультаты поиска для ответа:\n${ctx}\n\nИспользуй эти источники в ответе. После ответа укажи номера источников в формате [[1]], [[2]] и т.д.`;
  }

  const { key, stat } = getKey();
  try {
    const r = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': key, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({
        model: MODEL_MAP[model] || MODEL_MAP.smart,
        max_tokens: mode === 'reason' ? 8000 : 4096,
        system: systemPrompt,
        messages: messages.slice(-20).map(m => ({ role: m.role, content: m.content }))
      })
    });
    const d = await r.json();
    if (d.error) {
      stat.errors++; stat.lastError = Date.now();
      return res.status(500).json({ error: 'Ошибка ИИ. Попробуйте снова.' });
    }
    stat.errors = 0;
    res.json({ content: d.content?.[0]?.text || '', model: 'IZLOM AI v2', mode });
  } catch(e) {
    stat.errors++; stat.lastError = Date.now();
    console.error('Chat error:', e);
    res.status(500).json({ error: 'Ошибка соединения.' });
  }
});

// ═══════════════════════════════════════════════════════════
//  WEB SEARCH
// ═══════════════════════════════════════════════════════════
app.post('/api/search', chatLimiter, requireAuth, async (req, res) => {
  const { query } = req.body;
  if (!query) return res.status(400).json({ error: 'Нет запроса' });

  try {
    let results = [];

    if (CONFIG.BRAVE_SEARCH_KEY && CONFIG.BRAVE_SEARCH_KEY !== '') {
      // Brave Search API (рекомендуется)
      const r = await axios.get('https://api.search.brave.com/res/v1/web/search', {
        params: { q: query, count: 8, text_decorations: false, search_lang: 'ru' },
        headers: { 'Accept': 'application/json', 'X-Subscription-Token': CONFIG.BRAVE_SEARCH_KEY }
      });
      results = (r.data.web?.results || []).map(x => ({
        title: x.title,
        url: x.url,
        snippet: x.description || '',
        favicon: `https://www.google.com/s2/favicons?domain=${new URL(x.url).hostname}&sz=32`
      }));
    } else {
      // DuckDuckGo instant answers (без ключа, бесплатно)
      const r = await axios.get('https://api.duckduckgo.com/', {
        params: { q: query, format: 'json', no_html: 1, skip_disambig: 1 }
      });
      const d = r.data;
      // Combine RelatedTopics
      const topics = (d.RelatedTopics || []).slice(0, 6);
      results = topics.filter(t => t.FirstURL).map(t => ({
        title: t.Text?.split(' - ')[0] || query,
        url: t.FirstURL,
        snippet: t.Text || '',
        favicon: `https://www.google.com/s2/favicons?domain=${new URL(t.FirstURL).hostname}&sz=32`
      }));
      // Add Abstract if exists
      if (d.AbstractURL) {
        results.unshift({ title: d.Heading || query, url: d.AbstractURL, snippet: d.AbstractText || '', favicon: `https://www.google.com/s2/favicons?domain=${new URL(d.AbstractURL).hostname}&sz=32` });
      }
    }

    res.json({ results: results.slice(0, 6), query });
  } catch(e) {
    console.error('Search error:', e.message);
    // Fallback: return empty
    res.json({ results: [], query, error: 'Поиск временно недоступен' });
  }
});

// ═══════════════════════════════════════════════════════════
//  RECAPTCHA SITE KEY (публичный — для фронтенда)
// ═══════════════════════════════════════════════════════════
app.get('/api/config', (req, res) => {
  res.json({
    recaptchaSiteKey: CONFIG.RECAPTCHA_SITE_KEY === 'ВСТАВЬ_RECAPTCHA_SITE_KEY' ? null : CONFIG.RECAPTCHA_SITE_KEY,
    telegramBotName: CONFIG.TELEGRAM_BOT_NAME === 'ВСТАВЬ_ИМЯ_БОТА' ? null : CONFIG.TELEGRAM_BOT_NAME,
    googleConfigured: CONFIG.GOOGLE_CLIENT_ID !== 'ВСТАВЬ_GOOGLE_CLIENT_ID',
  });
});

// ═══════════════════════════════════════════════════════════
//  STATUS
// ═══════════════════════════════════════════════════════════
app.get('/api/status', (req, res) => {
  res.json({
    status: 'online', version: '2.0',
    model: 'IZLOM AI v2',
    keys: CONFIG.CLAUDE_KEYS.length,
    keyStats: keyStats.map(s => ({ i: s.i, uses: s.uses, errors: s.errors })),
    users: DB.users.size,
    sessions: DB.sessions.size,
    features: {
      google: CONFIG.GOOGLE_CLIENT_ID !== 'ВСТАВЬ_GOOGLE_CLIENT_ID',
      telegram: CONFIG.TELEGRAM_BOT_TOKEN !== 'ВСТАВЬ_TELEGRAM_BOT_TOKEN',
      recaptcha: CONFIG.RECAPTCHA_SECRET !== 'ВСТАВЬ_RECAPTCHA_SECRET_KEY',
      braveSearch: !!CONFIG.BRAVE_SEARCH_KEY,
    }
  });
});

// ── Info page helper ──
function infoPage(title, msg, success) {
  return `<!DOCTYPE html><html lang="ru"><head><meta charset="UTF-8"><title>${title}</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>*{box-sizing:border-box}body{background:#080810;color:#eee;font-family:Arial,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;padding:20px}
.b{text-align:center;background:#111122;border:1px solid rgba(124,92,252,.3);border-radius:20px;padding:40px 30px;max-width:420px;width:100%}
h1{font-size:40px;margin:0 0 12px}h2{margin:0 0 10px;font-size:22px}p{color:#9090b8;margin-bottom:28px;line-height:1.6}
a{background:linear-gradient(135deg,#7c5cfc,#9333ea);color:#fff;padding:13px 28px;border-radius:12px;text-decoration:none;font-weight:700;font-size:15px;display:inline-block}</style></head>
<body><div class="b"><h1>${success ? '✅' : '❌'}</h1><h2>${title}</h2><p>${msg}</p><a href="/">Открыть IZLOM AI →</a></div></body></html>`;
}

// ═══════════════════════════════════════════════════════════
//  START
// ═══════════════════════════════════════════════════════════
app.listen(PORT, () => {
  console.log('');
  console.log('  ⚡ ═══════════════════════════════════');
  console.log('     IZLOM AI v2 — Backend запущен');
  console.log(`  🌐 http://localhost:${PORT}`);
  console.log(`  📊 http://localhost:${PORT}/api/status`);
  console.log('  ═══════════════════════════════════');
  console.log(`  🔑 Claude ключей: ${CONFIG.CLAUDE_KEYS.length}`);
  console.log(`  📧 SMTP: ${CONFIG.SMTP.host}:${CONFIG.SMTP.port}`);
  console.log(`  🔍 Google OAuth: ${CONFIG.GOOGLE_CLIENT_ID !== 'ВСТАВЬ_GOOGLE_CLIENT_ID' ? '✅' : '❌ не настроен'}`);
  console.log(`  📱 Telegram: ${CONFIG.TELEGRAM_BOT_TOKEN !== 'ВСТАВЬ_TELEGRAM_BOT_TOKEN' ? '✅' : '❌ не настроен'}`);
  console.log(`  🛡️  reCAPTCHA: ${CONFIG.RECAPTCHA_SECRET !== 'ВСТАВЬ_RECAPTCHA_SECRET_KEY' ? '✅' : '⚠️  не настроена'}`);
  console.log(`  🔍 Brave Search: ${CONFIG.BRAVE_SEARCH_KEY ? '✅' : '⚠️  DuckDuckGo fallback'}`);
  console.log('');
});

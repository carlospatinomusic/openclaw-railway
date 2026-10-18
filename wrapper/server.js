// Thin wrapper around the OpenClaw gateway for Railway deployments.
//
// Why this exists: Railway gives nobody shell access to a deployed
// container, so the normal `openclaw devices approve <id>` CLI flow (used
// to approve a new browser's first-ever Control UI connection) is
// impossible to run. This wrapper moves that approval to a real, explicit
// human action - a password-gated /setup page with an Approve button -
// instead of either (a) requiring CLI access nobody has, or (b)
// auto-approving everything with no human involved at all.
//
// Architecture: this process owns the public port. It spawns the real
// OpenClaw gateway on an internal-only loopback port and proxies
// everything (HTTP + WebSocket) through to it, except for the /setup/*
// routes, which it handles itself.
const path = require('path');
const crypto = require('crypto');
const { spawn, execFile } = require('child_process');
const express = require('express');
const httpProxy = require('http-proxy');

const PUBLIC_PORT = Number(process.env.PORT) || 18789;
const GATEWAY_PORT = Number(process.env.GATEWAY_INTERNAL_PORT) || 18799;
const SETUP_PASSWORD = process.env.SETUP_PASSWORD;

if (!SETUP_PASSWORD) {
  console.error('[wrapper] SETUP_PASSWORD is not set - refusing to start.');
  process.exit(1);
}

// Both PORT and OPENCLAW_GATEWAY_PORT get overridden here: the gateway
// subcommand binds using --port, but CLI helper commands (devices list/
// approve) appear to locate the local gateway via OPENCLAW_GATEWAY_PORT.
// Setting both consistently avoids the CLI accidentally talking to this
// wrapper's own public port instead of the real gateway.
const gatewayEnv = Object.assign({}, process.env, {
  PORT: String(GATEWAY_PORT),
  OPENCLAW_GATEWAY_PORT: String(GATEWAY_PORT),
});

let gateway = null;
let restartTimer = null;

function startGateway() {
  console.log(`[wrapper] starting gateway on 127.0.0.1:${GATEWAY_PORT}`);

  gateway = spawn(
    'node',
    ['dist/index.js', 'gateway', '--bind', 'loopback', '--port', String(GATEWAY_PORT), '--allow-unconfigured'],
    { env: gatewayEnv, stdio: 'inherit' }
  );

  gateway.on('exit', (code, signal) => {
    console.error(
      `[wrapper] gateway process exited (code ${code}, signal ${signal || 'none'}); keeping wrapper alive and restarting gateway`
    );
    gateway = null;

    // Newer OpenClaw builds can replace/restart the gateway process as part
    // of their own lifecycle. Do not kill the Railway wrapper when that
    // happens: keep the public HTTP server alive and start a fresh gateway
    // after a short grace period.
    clearTimeout(restartTimer);
    restartTimer = setTimeout(startGateway, 2000);
  });

  gateway.on('error', (err) => {
    console.error('[wrapper] gateway spawn error:', err.message);
  });
}

startGateway();

function runCli(args) {
  return new Promise((resolve) => {
    execFile(
      'node',
      ['dist/index.js', ...args, '--json'],
      { timeout: 15000, env: gatewayEnv },
      (err, stdout, stderr) => {
        if (err && !stdout) {
          resolve({ ok: false, error: (stderr || err.message || '').trim() });
          return;
        }
        try {
          resolve({ ok: true, data: JSON.parse(stdout) });
        } catch (e) {
          resolve({ ok: false, error: 'failed to parse CLI output', raw: stdout });
        }
      }
    );
  });
}

// Cookie-based session instead of HTTP Basic Auth: a plain password-only
// login form is much less confusing than the browser's native username+
// password popup (there is no username here at all), and a session cookie
// persists far more reliably across tabs/reloads than Basic Auth caching.
// Sessions are in-memory only - they reset on redeploy, which just means
// logging in again, no real cost for a single-operator setup page.
const validSessions = new Set();

function parseCookies(req) {
  const header = req.headers.cookie || '';
  const cookies = {};
  header.split(';').forEach((pair) => {
    const idx = pair.indexOf('=');
    if (idx > -1) {
      cookies[pair.slice(0, idx).trim()] = decodeURIComponent(pair.slice(idx + 1).trim());
    }
  });
  return cookies;
}

function requireSetupAuth(req, res, next) {
  const cookies = parseCookies(req);
  if (cookies.setup_session && validSessions.has(cookies.setup_session)) {
    next();
    return;
  }
  res.redirect('/setup/login');
}

const LOGIN_PAGE = (error) => `<!doctype html>
<html><head><meta charset="utf-8" /><title>OpenClaw Setup - Sign In</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #0f1115; color: #e6e6e6; max-width: 400px; margin: 80px auto; padding: 0 20px; }
  input { width: 100%; box-sizing: border-box; padding: 10px; margin: 8px 0 16px; background: #181b21; border: 1px solid #2a2e37; border-radius: 6px; color: #e6e6e6; }
  button { background: #e0554f; color: white; border: none; border-radius: 6px; padding: 10px 18px; cursor: pointer; width: 100%; }
  .error { color: #e0554f; margin-bottom: 12px; }
</style></head>
<body>
  <h2>OpenClaw Setup</h2>
  ${error ? '<p class="error">Incorrect password.</p>' : ''}
  <form method="POST" action="/setup/login">
    <label for="password">Password</label>
    <input type="password" id="password" name="password" autofocus />
    <button type="submit">Sign In</button>
  </form>
</body></html>`;

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

app.get('/setup/login', (req, res) => {
  res.send(LOGIN_PAGE(false));
});

// Simple in-memory rate limit: 5 attempts per IP per 5 minutes. This is a
// single-operator setup page, not a multi-tenant login - the goal is just
// to stop unattended password-guessing scripts, not defend against a
// determined targeted attacker.
const loginAttempts = new Map(); // ip -> { count, resetAt }
const MAX_ATTEMPTS = 5;
const WINDOW_MS = 5 * 60 * 1000;

function timingSafeEquals(a, b) {
  const bufA = Buffer.from(String(a));
  const bufB = Buffer.from(String(b));
  // Compare against a fixed-length buffer first so the length itself isn't
  // leaked via early return, then timingSafeEqual requires equal lengths.
  if (bufA.length !== bufB.length) {
    crypto.timingSafeEqual(bufA, bufA); // constant-time no-op to avoid a fast path
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}

app.post('/setup/login', (req, res) => {
  const ip = req.ip || req.socket.remoteAddress || 'unknown';
  const now = Date.now();
  const entry = loginAttempts.get(ip);
  if (entry && entry.resetAt > now && entry.count >= MAX_ATTEMPTS) {
    res.status(429).send(LOGIN_PAGE(true));
    return;
  }

  const password = req.body && req.body.password;
  if (password && timingSafeEquals(password, SETUP_PASSWORD)) {
    loginAttempts.delete(ip);
    const token = crypto.randomBytes(24).toString('hex');
    validSessions.add(token);
    res.setHeader('Set-Cookie', `setup_session=${token}; HttpOnly; Secure; Path=/; SameSite=Lax`);
    res.redirect('/setup');
    return;
  }

  if (!entry || entry.resetAt <= now) {
    loginAttempts.set(ip, { count: 1, resetAt: now + WINDOW_MS });
  } else {
    entry.count += 1;
  }
  res.status(401).send(LOGIN_PAGE(true));
});

app.get('/setup', requireSetupAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'setup.html'));
});

app.get('/setup/api/devices', requireSetupAuth, async (req, res) => {
  const result = await runCli(['devices', 'list']);
  res.json(result);
});

app.post('/setup/api/devices/approve', requireSetupAuth, async (req, res) => {
  const requestId = req.body && req.body.requestId;
  if (!requestId) {
    res.status(400).json({ ok: false, error: 'requestId is required' });
    return;
  }
  const result = await runCli(['devices', 'approve', requestId]);
  res.json(result);
});

// Served as a real file (not inlined into the Control UI HTML) because the
// gateway's own CSP is "script-src 'self'" with no 'unsafe-inline' - an
// inline <script> block gets silently blocked by the browser. A same-origin
// script file satisfies 'self' and runs normally. Listens for a signal from
// /setup (posted only after a human has genuinely clicked Approve there)
// and clicks Connect again automatically - this doesn't skip the actual
// approval decision, it only automates the mechanical reconnect that
// follows a real approval.
const RECONNECT_LISTENER_JS = `(function () {
  try {
    var channel = new BroadcastChannel('openclaw-setup');
    channel.onmessage = function (event) {
      if (event.data === 'device-approved') {
        setTimeout(function () {
          var buttons = document.querySelectorAll('button');
          for (var i = 0; i < buttons.length; i++) {
            if (buttons[i].textContent.trim() === 'Connect') {
              buttons[i].click();
              break;
            }
          }
        }, 500);
      }
    };
  } catch (e) {
    // BroadcastChannel unsupported - no-op, manual reconnect still works.
  }
})();
`;

app.get('/openclaw-railway-listener.js', (req, res) => {
  res.type('application/javascript').send(RECONNECT_LISTENER_JS);
});

// Everything else (including the actual Control UI and its WebSocket
// connection) proxies straight through to the real gateway.
const proxy = httpProxy.createProxyServer({
  target: `http://127.0.0.1:${GATEWAY_PORT}`,
  ws: true,
  changeOrigin: false, // preserve the real Host/Origin so allowedOrigins still matches upstream
});

// OpenClaw 2026.10 requires explicit proxy attribution. The only proxy the
// gateway trusts is this local wrapper, and the wrapper rebuilds forwarded
// headers from the actual socket instead of passing client-supplied values.
function applyForwardedHeaders(proxyReq, req) {
  const remote = req.socket && req.socket.remoteAddress ? req.socket.remoteAddress : '127.0.0.1';
  proxyReq.setHeader('x-forwarded-for', remote);
  proxyReq.setHeader('x-forwarded-proto', 'https');
  proxyReq.setHeader('x-forwarded-host', req.headers.host || process.env.RAILWAY_PUBLIC_DOMAIN || '');
}

proxy.on('proxyReq', applyForwardedHeaders);
proxy.on('proxyReqWs', applyForwardedHeaders);

proxy.on('error', (err, req, res) => {
  console.error('[wrapper] proxy error:', err.message);
  if (res && res.writeHead) {
    res.writeHead(502);
    res.end('Gateway unavailable');
  }
});

app.use((req, res) => {
  proxy.web(req, res);
});

const server = app.listen(PUBLIC_PORT, () => {
  console.log(`[wrapper] listening on ${PUBLIC_PORT}, proxying to gateway on 127.0.0.1:${GATEWAY_PORT}`);
});

server.on('upgrade', (req, socket, head) => {
  proxy.ws(req, socket, head);
});

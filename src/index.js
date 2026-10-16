const crypto = require('crypto');
const express = require('express');
const cors = require('cors');
const config = require('./config');
const { forward } = require('./forward');
const { TargetError, parseTarget, assertTargetAllowed } = require('./target');

const app = express();
app.disable('x-powered-by');

app.use(
  cors({
    origin: config.corsOrigins.includes('*') ? '*' : config.corsOrigins,
    maxAge: 600,
  })
);

app.get('/health', (req, res) => res.json({ ok: true }));

// Optional shared-secret check.
function requireKey(req, res, next) {
  if (!config.apiKey) return next();
  const given = Buffer.from(String(req.headers['x-proxy-key'] || ''));
  const expected = Buffer.from(config.apiKey);
  const valid = given.length === expected.length && crypto.timingSafeEqual(given, expected);
  if (!valid) return res.status(401).json({ error: 'Unauthorized', message: 'Missing or invalid X-Proxy-Key header' });
  return next();
}

/**
 * Target comes from  /forward?url=<target>  or the  X-Target-URL  header.
 * For the query form, everything after "url=" is the target, so the target's own
 * query string can be written as-is or URL-encoded.
 */
function getTargetUrl(req) {
  const queryStart = req.originalUrl.indexOf('?');
  const rawQuery = queryStart === -1 ? '' : req.originalUrl.slice(queryStart + 1);
  if (rawQuery.startsWith('url=')) {
    const value = rawQuery.slice(4);
    return /^https?%3A/i.test(value) ? decodeURIComponent(value) : value;
  }
  return req.headers['x-target-url'];
}

app.all('/forward', requireKey, (req, res) => {
  const raw = getTargetUrl(req);
  if (!raw) {
    return res.status(400).json({
      error: 'Bad Request',
      message: 'Send the target as ?url=https://example.com/path or in the X-Target-URL header',
    });
  }

  try {
    const target = parseTarget(raw);
    assertTargetAllowed(target, config);
    return forward(req, res, target, config);
  } catch (err) {
    if (err instanceof TargetError) {
      return res.status(err.status).json({ error: err.status === 403 ? 'Forbidden' : 'Bad Request', message: err.message });
    }
    console.error(err);
    return res.status(500).json({ error: 'Internal Server Error', message: 'Unexpected proxy error' });
  }
});

app.use((req, res) => res.status(404).json({ error: 'Not Found', message: 'Use /forward?url=<target>' }));

const server = app.listen(config.port, () => {
  console.log(`Forward proxy listening on port ${config.port}`);
  console.log(`  allowed hosts : ${config.allowedHosts.join(', ') || 'any public host'}`);
  console.log(`  api key       : ${config.apiKey ? 'required' : 'NOT set'}`);
  console.log(`  private targets: ${config.allowPrivateTargets ? 'allowed' : 'blocked'}`);
  if (!config.allowedHosts.length && !config.apiKey) {
    console.warn('WARNING: no ALLOWED_HOSTS and no PROXY_API_KEY. Anyone who finds this server can use it.');
  }
});

function shutdown() {
  console.log('Shutting down...');
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(1), 5000).unref();
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

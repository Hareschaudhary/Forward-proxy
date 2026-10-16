require('dotenv').config();

const list = (value) =>
  (value || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);

module.exports = {
  port: Number(process.env.PORT) || 3000,
  allowedHosts: list(process.env.ALLOWED_HOSTS).map((h) => h.toLowerCase()),
  apiKey: process.env.PROXY_API_KEY || '',
  allowPrivateTargets: process.env.ALLOW_PRIVATE_TARGETS === 'true',
  timeoutMs: Number(process.env.REQUEST_TIMEOUT_MS) || 15_000,
  corsOrigins: list(process.env.CORS_ORIGIN || '*'),
};

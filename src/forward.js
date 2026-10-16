/**
 * Streams one incoming request to the target and streams the answer back.
 * Nothing is buffered, redirects are not followed, status codes pass through unchanged.
 */
const http = require('http');
const https = require('https');
const { createGuardedLookup } = require('./target');

// Headers that only make sense for a single network hop.
const HOP_BY_HOP = [
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
];
// Headers we never pass on to the target.
const STRIP_FROM_REQUEST = new Set([...HOP_BY_HOP, 'host', 'origin', 'referer', 'x-target-url', 'x-proxy-key']);
// The proxy sets its own CORS headers, so the target's are dropped.
const STRIP_FROM_RESPONSE = (name) => HOP_BY_HOP.includes(name) || name.startsWith('access-control-');

function sendError(res, status, error, message) {
  if (res.headersSent) return res.destroy();
  res.status(status).json({ error, message });
}

function forward(req, res, target, { timeoutMs, allowPrivateTargets }) {
  const client = target.protocol === 'https:' ? https : http;
  const startedAt = Date.now();
  let timedOut = false;

  const headers = {};
  for (const [name, value] of Object.entries(req.headers)) {
    if (!STRIP_FROM_REQUEST.has(name)) headers[name] = value;
  }

  const proxyReq = client.request({
    protocol: target.protocol,
    hostname: target.hostname.replace(/^\[|\]$/g, ''),
    port: target.port || undefined,
    path: target.pathname + target.search,
    method: req.method,
    headers,
    timeout: timeoutMs,
    lookup: createGuardedLookup(allowPrivateTargets),
  });

  proxyReq.on('response', (proxyRes) => {
    const responseHeaders = {};
    for (const [name, value] of Object.entries(proxyRes.headers)) {
      if (!STRIP_FROM_RESPONSE(name)) responseHeaders[name] = value;
    }
    responseHeaders['x-proxy-target'] = target.host;
    // Let the browser read every header the target sent.
    responseHeaders['access-control-expose-headers'] = Object.keys(responseHeaders).join(', ');

    res.writeHead(proxyRes.statusCode, responseHeaders);
    proxyRes.pipe(res);

    res.on('finish', () => {
      console.log(
        `[${new Date().toISOString()}] ${req.method} ${target.origin}${target.pathname} -> ${proxyRes.statusCode} (${Date.now() - startedAt} ms)`
      );
    });
  });

  proxyReq.on('timeout', () => {
    timedOut = true;
    proxyReq.destroy();
  });

  proxyReq.on('error', (err) => {
    let status = 502;
    let error = 'Bad Gateway';
    let message = 'Could not reach the target';

    if (timedOut) {
      status = 504;
      error = 'Gateway Timeout';
      message = `Target did not respond within ${timeoutMs} ms`;
    } else if (err.code === 'ETARGET_BLOCKED') {
      status = 403;
      error = 'Forbidden';
      message = err.message;
    } else if (err.code === 'ENOTFOUND') {
      message = `Host "${target.hostname}" was not found`;
    } else if (err.code === 'ECONNREFUSED') {
      message = 'Connection refused by the target';
    } else if (err.code === 'ECONNRESET') {
      message = 'Connection was reset by the target';
    }

    console.warn(`[${new Date().toISOString()}] ${req.method} ${target.origin}${target.pathname} -> ${status} ${err.code || err.message}`);
    sendError(res, status, error, message);
  });

  // If the caller disconnects, stop talking to the target.
  res.on('close', () => {
    if (!res.writableEnded) proxyReq.destroy();
  });

  req.pipe(proxyReq); // sends the request body (if any) as-is
}

module.exports = { forward };

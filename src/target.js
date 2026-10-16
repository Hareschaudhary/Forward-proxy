/**
 * Everything about deciding whether a target URL is acceptable.
 */
const dns = require('dns');
const net = require('net');

class TargetError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function isPrivateIPv4(ip) {
  const [a, b] = ip.split('.').map(Number);
  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 100 && b >= 64 && b <= 127) || // carrier-grade NAT
    (a === 169 && b === 254) || // link-local + cloud metadata
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    a >= 224 // multicast / reserved
  );
}

function isPrivateIp(ip) {
  if (net.isIPv4(ip)) return isPrivateIPv4(ip);
  if (net.isIPv6(ip)) {
    const l = ip.toLowerCase();
    if (l === '::' || l === '::1') return true;
    const mapped = l.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    if (mapped) return isPrivateIPv4(mapped[1]);
    if (l.startsWith('::ffff:')) return true; // hex-form mapped address: be safe
    return /^f[cd]/.test(l) || /^fe[89ab]/.test(l); // unique-local, link-local
  }
  return true;
}

/** Parse and validate the URL syntax. */
function parseTarget(raw) {
  let url;
  try {
    url = new URL(raw);
  } catch {
    throw new TargetError(400, 'Invalid target URL. Use a full URL like https://example.com/path');
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new TargetError(400, 'Only http:// and https:// targets are supported');
  }
  if (url.username || url.password) {
    throw new TargetError(400, 'Credentials inside the target URL are not allowed');
  }
  return url;
}

function matchesAllowList(url, allowedHosts) {
  if (allowedHosts.length === 0) return true;
  return allowedHosts.some((entry) => {
    if (entry.startsWith('*.')) return url.hostname.endsWith(entry.slice(1));
    return entry === url.host || entry === url.hostname;
  });
}

/** Check the target against the allowlist and (for IP literals) the private-range rule. */
function assertTargetAllowed(url, { allowedHosts, allowPrivateTargets }) {
  if (!matchesAllowList(url, allowedHosts)) {
    throw new TargetError(403, `Host "${url.host}" is not in ALLOWED_HOSTS`);
  }
  const bareHost = url.hostname.replace(/^\[|\]$/g, '');
  if (!allowPrivateTargets && net.isIP(bareHost) && isPrivateIp(bareHost)) {
    throw new TargetError(403, 'Private or local addresses are blocked');
  }
}

/**
 * DNS lookup used for the actual connection. It checks the address we are about
 * to connect to, which also stops DNS tricks (a public name that resolves to 127.0.0.1).
 */
function createGuardedLookup(allowPrivateTargets) {
  return (hostname, options, callback) => {
    dns.lookup(hostname, options, (err, address, family) => {
      if (err) return callback(err);
      const addresses = Array.isArray(address) ? address.map((a) => a.address) : [address];
      if (!allowPrivateTargets && addresses.some(isPrivateIp)) {
        const blocked = new Error('Target resolves to a private or local address');
        blocked.code = 'ETARGET_BLOCKED';
        return callback(blocked);
      }
      return callback(null, address, family);
    });
  };
}

module.exports = { TargetError, parseTarget, assertTargetAllowed, createGuardedLookup };

import { lookup } from 'node:dns/promises';
import net from 'node:net';
import type { SignedEpochDirectory } from './crypto.ts';

export interface RelayTargetPolicyOptions {
  allowLoopback?: boolean;
  allowPrivateNetwork?: boolean;
}

export class RelaySecurityError extends Error {
  public readonly status: number;
  public readonly code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = 'RelaySecurityError';
    this.status = status;
    this.code = code;
  }
}

function parseIpv4Int(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let val = 0;
  for (const part of parts) {
    if (!/^\d+$/.test(part)) return null;
    const n = Number(part);
    if (n < 0 || n > 255) return null;
    val = (val << 8) | n;
  }
  return val >>> 0;
}

function isIpv4InCidr(ipInt: number, baseStr: string, prefixLen: number): boolean {
  const base = parseIpv4Int(baseStr);
  if (base === null) return false;
  const mask = prefixLen === 0 ? 0 : (0xffffffff << (32 - prefixLen)) >>> 0;
  return (ipInt & mask) === (base & mask);
}

export function isBlockedIpAddress(
  rawIp: string,
  options: RelayTargetPolicyOptions = {},
): { blocked: boolean; reason?: string } {
  const allowLoopback = options.allowLoopback ?? false;
  const allowPrivateNetwork = options.allowPrivateNetwork ?? false;

  const trimmed = rawIp.trim().replace(/^\[|\]$/g, '').split('%')[0] ?? '';
  const ipVer = net.isIP(trimmed);
  if (ipVer === 0) {
    return { blocked: true, reason: 'INVALID_IP_ADDRESS' };
  }

  // Handle IPv4-mapped IPv6 addresses (e.g., ::ffff:127.0.0.1, ::ffff:7f00:1)
  const lower = trimmed.toLowerCase();
  if (ipVer === 6 && lower.startsWith('::ffff:')) {
    const suffix = lower.slice(7);
    if (net.isIPv4(suffix)) {
      return isBlockedIpAddress(suffix, options);
    }
    const hexGroups = suffix.split(':');
    if (hexGroups.length === 2) {
      const hi = parseInt(hexGroups[0]!, 16);
      const lo = parseInt(hexGroups[1]!, 16);
      if (Number.isFinite(hi) && Number.isFinite(lo)) {
        const ipv4 = `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
        return isBlockedIpAddress(ipv4, options);
      }
    }
  }

  if (ipVer === 4) {
    const ipInt = parseIpv4Int(trimmed);
    if (ipInt === null) return { blocked: true, reason: 'INVALID_IPV4' };

    if (isIpv4InCidr(ipInt, '0.0.0.0', 8)) {
      return { blocked: true, reason: 'UNSPECIFIED_RANGE_BLOCKED' };
    }
    // Cloud metadata & APIPA link-local is ALWAYS blocked even when loopback is permitted
    if (isIpv4InCidr(ipInt, '169.254.0.0', 16)) {
      return { blocked: true, reason: 'LINK_LOCAL_METADATA_BLOCKED' };
    }
    if (isIpv4InCidr(ipInt, '100.64.0.0', 10)) {
      return { blocked: true, reason: 'CGNAT_RANGE_BLOCKED' };
    }
    if (isIpv4InCidr(ipInt, '224.0.0.0', 4) || isIpv4InCidr(ipInt, '240.0.0.0', 4)) {
      return { blocked: true, reason: 'MULTICAST_OR_RESERVED_BLOCKED' };
    }
    if (isIpv4InCidr(ipInt, '127.0.0.0', 8)) {
      return allowLoopback ? { blocked: false } : { blocked: true, reason: 'LOOPBACK_BLOCKED' };
    }
    if (
      isIpv4InCidr(ipInt, '10.0.0.0', 8) ||
      isIpv4InCidr(ipInt, '172.16.0.0', 12) ||
      isIpv4InCidr(ipInt, '192.168.0.0', 16)
    ) {
      return allowPrivateNetwork
        ? { blocked: false }
        : { blocked: true, reason: 'RFC1918_PRIVATE_BLOCKED' };
    }
    return { blocked: false };
  }

  // IPv6 checks
  if (lower === '::' || lower === '0:0:0:0:0:0:0:0') {
    return { blocked: true, reason: 'UNSPECIFIED_IPV6_BLOCKED' };
  }
  if (lower.startsWith('fe8') || lower.startsWith('fe9') || lower.startsWith('fea') || lower.startsWith('feb')) {
    return { blocked: true, reason: 'LINK_LOCAL_IPV6_BLOCKED' };
  }
  if (lower.startsWith('ff')) {
    return { blocked: true, reason: 'MULTICAST_IPV6_BLOCKED' };
  }
  if (lower === '::1' || lower === '0:0:0:0:0:0:0:1') {
    return allowLoopback ? { blocked: false } : { blocked: true, reason: 'LOOPBACK_IPV6_BLOCKED' };
  }
  if (lower.startsWith('fc') || lower.startsWith('fd')) {
    return allowPrivateNetwork
      ? { blocked: false }
      : { blocked: true, reason: 'ULA_PRIVATE_IPV6_BLOCKED' };
  }
  return { blocked: false };
}

export async function assertRelayTargetAllowed(
  rawUrl: string,
  activeDirectory: SignedEpochDirectory | null,
  slashedPeers: ReadonlySet<string>,
  options: RelayTargetPolicyOptions = {},
): Promise<string> {
  if (!activeDirectory) {
    throw new RelaySecurityError(503, 'NO_ACTIVE_EPOCH_DIRECTORY', 'Relay has no active signed directory');
  }

  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new RelaySecurityError(400, 'INVALID_RELAY_TARGET_URL', 'Malformed target URL in onion header');
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new RelaySecurityError(403, 'RELAY_PROTOCOL_FORBIDDEN', `Unsupported relay protocol: ${parsed.protocol}`);
  }
  if (parsed.username || parsed.password || parsed.search || parsed.hash) {
    throw new RelaySecurityError(403, 'RELAY_URL_CREDENTIALS_FORBIDDEN', 'Credentials/query not permitted in relay target');
  }
  if (parsed.pathname !== '/' && parsed.pathname !== '') {
    throw new RelaySecurityError(403, 'RELAY_URL_PATH_FORBIDDEN', 'Arbitrary paths not permitted in onion target origin');
  }

  const normalizedOrigin = parsed.origin;
  const activeMatch = activeDirectory.members.find((m) => {
    if (slashedPeers.has(m.peerId)) return false;
    try {
      return new URL(m.endpoint).origin === normalizedOrigin;
    } catch {
      return false;
    }
  });
  if (!activeMatch) {
    throw new RelaySecurityError(
      403,
      'RELAY_TARGET_NOT_IN_DIRECTORY',
      `Target ${normalizedOrigin} is not an active member of signed epoch ${activeDirectory.epoch}`,
    );
  }

  const hostname = parsed.hostname.replace(/^\[|\]$/g, '');
  if (net.isIP(hostname) !== 0) {
    const check = isBlockedIpAddress(hostname, options);
    if (check.blocked) {
      throw new RelaySecurityError(
        403,
        'BLOCKED_PRIVATE_OR_LINK_LOCAL_TARGET',
        `Relay target IP ${hostname} blocked (${check.reason})`,
      );
    }
    return normalizedOrigin;
  }

  if (hostname.toLowerCase() === 'localhost' && !options.allowLoopback) {
    throw new RelaySecurityError(
      403,
      'BLOCKED_PRIVATE_OR_LINK_LOCAL_TARGET',
      'Localhost relay target blocked',
    );
  }

  let resolved: Array<{ address: string }>;
  try {
    resolved = await lookup(hostname, { all: true });
  } catch {
    throw new RelaySecurityError(
      502,
      'RELAY_DNS_RESOLUTION_FAILED',
      `Unable to resolve relay target host ${hostname}`,
    );
  }
  if (resolved.length === 0) {
    throw new RelaySecurityError(502, 'RELAY_DNS_RESOLUTION_FAILED', `No addresses for ${hostname}`);
  }

  for (const record of resolved) {
    const check = isBlockedIpAddress(record.address, options);
    if (check.blocked) {
      throw new RelaySecurityError(
        403,
        'BLOCKED_PRIVATE_OR_LINK_LOCAL_TARGET',
        `Resolved relay target ${hostname} -> ${record.address} blocked (${check.reason})`,
      );
    }
  }

  return normalizedOrigin;
}

export async function fetchWithTimeoutAndCap(
  url: string,
  init: RequestInit,
  options: { timeoutMs: number; maxResponseBytes: number },
): Promise<{ status: number; contentType: string; bodyText: string }> {
  const signal = AbortSignal.timeout(options.timeoutMs);
  let resp: Response;
  try {
    resp = await fetch(url, {
      ...init,
      redirect: 'error',
      signal,
    });
  } catch (err) {
    if (err instanceof Error && (err.name === 'TimeoutError' || err.name === 'AbortError')) {
      throw new RelaySecurityError(504, 'RELAY_UPSTREAM_TIMEOUT', `Upstream ${url} timed out`);
    }
    throw new RelaySecurityError(502, 'RELAY_UPSTREAM_FETCH_FAILED', `Upstream fetch failed: ${String(err)}`);
  }

  const declaredLen = resp.headers.get('content-length');
  if (declaredLen !== null) {
    const parsedLen = Number(declaredLen);
    if (Number.isFinite(parsedLen) && parsedLen > options.maxResponseBytes) {
      throw new RelaySecurityError(
        502,
        'RELAY_UPSTREAM_RESPONSE_TOO_LARGE',
        `Upstream Content-Length ${parsedLen} exceeds cap ${options.maxResponseBytes}`,
      );
    }
  }

  const contentType = resp.headers.get('content-type') || 'application/json';
  if (!resp.body) {
    return { status: resp.status, contentType, bodyText: '' };
  }

  const reader = resp.body.getReader();
  const chunks: Buffer[] = [];
  let totalBytes = 0;

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value) {
      totalBytes += value.byteLength;
      if (totalBytes > options.maxResponseBytes) {
        await reader.cancel('Response cap exceeded');
        throw new RelaySecurityError(
          502,
          'RELAY_UPSTREAM_RESPONSE_TOO_LARGE',
          `Upstream response exceeded cap ${options.maxResponseBytes} bytes`,
        );
      }
      chunks.push(Buffer.from(value));
    }
  }

  return {
    status: resp.status,
    contentType,
    bodyText: Buffer.concat(chunks, totalBytes).toString('utf8'),
  };
}

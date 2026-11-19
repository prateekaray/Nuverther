import http from 'node:http';
import { randomBytes } from 'node:crypto';
import type { AddressInfo } from 'node:net';
import { Pool } from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  CHUNK_FRAME_HEADER_SIZE,
  NuvertherNode,
  createSignedEpochDirectory,
  deriveChunkMsgId,
  generateNodeKeypair,
  isBlockedIpAddress,
  sha3Digest,
  wrapOnionPacket,
  type EpochWitnessMember,
  type NodeKeypair,
  type OnionHopTarget,
  type SignedEpochDirectory,
} from '@nuverther/node';
import {
  broadcastEpochDirectory,
  sendCoverTrafficCell,
  sendViaThreeHopOnion,
} from '@nuverther/client';

const DATABASE_URL =
  process.env.DATABASE_URL ?? 'postgresql://postgres:postgres@127.0.0.1:5432/postgres';

const SCHEMA_PREFIX = 'nuv_net_';

function toMember(n: NuvertherNode): EpochWitnessMember {
  const id = n.getSignedIdentity();
  return {
    peerId: id.peerId,
    endpoint: id.endpoint,
    ed25519PkHex: id.ed25519PkHex,
    mldsa65PkB64: id.mldsa65PkB64,
    x25519PkHex: id.x25519PkHex,
    joinedEpoch: 0,
  };
}

describe('Phase 3 Network Hardening Suite (SSRF, PoW, Replay Guard, Authenticated Chunking, Caps)', () => {
  let adminPool: Pool;
  let govKeypair: NodeKeypair;
  const nodes: NuvertherNode[] = [];
  let members: EpochWitnessMember[] = [];
  let prodStrictRelay!: NuvertherNode;
  let strictDirectory!: SignedEpochDirectory;
  let slowOrGiantServer!: http.Server;
  let slowServerUrl = '';
  let unlistedServer!: http.Server;
  let unlistedHits = 0;
  let unlistedServerUrl = '';

  beforeAll(async () => {
    adminPool = new Pool({ connectionString: DATABASE_URL });
    for (let i = 1; i <= 5; i++) {
      await adminPool.query(`DROP SCHEMA IF EXISTS "${SCHEMA_PREFIX}${i}" CASCADE`);
    }

    govKeypair = generateNodeKeypair('net-gov', Buffer.from('nuv-net-gov-seed', 'utf8'));
    const trustedGovernanceKeys = [
      {
        ed25519PkHex: Buffer.from(govKeypair.ed25519Pk).toString('hex'),
        mldsa65PkB64: Buffer.from(govKeypair.mldsa65Pk).toString('base64'),
      },
    ];

    // Boot 3 relay nodes with tight memory/time caps & loopback enabled for local circuit tests
    for (let i = 1; i <= 3; i++) {
      const peerId = `net-relay-${i}`;
      const kp = generateNodeKeypair(peerId, Buffer.from(`net-seed-${i}`, 'utf8'));
      const node = new NuvertherNode({
        peerId,
        host: '127.0.0.1',
        port: 0,
        databaseUrl: DATABASE_URL,
        dbSchema: `${SCHEMA_PREFIX}${i}`,
        keypair: kp,
        trustedGovernanceKeys,
        governanceThreshold: 1,
        relayPowBits: 10,
        relayTimeoutMs: 400,
        maxRelayResponseBytes: 4096,
        relayJitterMaxMs: 2,
        allowLoopbackPeers: true,
        reassemblyTtlMs: 300,
        maxReassemblyEntries: 2,
        maxReassemblyTotalBytes: 32_768,
        rateLimitCapacity: 5, // Intentionally tiny IP bucket to prove onion /v1/relay does not break
        rateLimitRefillPerSec: 1,
        logLevel: 'silent',
      });
      await node.start();
      nodes.push(node);
    }

    // Boot a strict production-policy node (allowLoopbackPeers = false, allowPrivateNetworkPeers = false)
    const strictKp = generateNodeKeypair('strict-relay', Buffer.from('strict-relay-seed', 'utf8'));
    prodStrictRelay = new NuvertherNode({
      peerId: 'strict-relay',
      host: '127.0.0.1',
      port: 0,
      databaseUrl: DATABASE_URL,
      dbSchema: `${SCHEMA_PREFIX}4`,
      keypair: strictKp,
      trustedGovernanceKeys,
      governanceThreshold: 1,
      relayPowBits: 10,
      allowLoopbackPeers: false,
      allowPrivateNetworkPeers: false,
      logLevel: 'silent',
    });
    await prodStrictRelay.start();

    // Unlisted trap HTTP server (must NEVER be dialed by relay)
    unlistedServer = http.createServer((_req, res) => {
      unlistedHits++;
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ leaked: true }));
    });
    await new Promise<void>((resolve) => {
      unlistedServer.listen(0, '127.0.0.1', () => {
        const addr = unlistedServer.address() as AddressInfo;
        unlistedServerUrl = `http://127.0.0.1:${addr.port}`;
        resolve();
      });
    });

    // Adversarial slow / giant HTTP server registered as a directory member for timeout & cap tests
    slowOrGiantServer = http.createServer((req, res) => {
      if (req.url === '/v1/slow') {
        setTimeout(() => {
          if (!res.writableEnded) {
            res.writeHead(200);
            res.end('{}');
          }
        }, 1200);
        return;
      }
      if (req.url === '/v1/giant') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('A'.repeat(16_384));
        return;
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true }));
    });
    await new Promise<void>((resolve) => {
      slowOrGiantServer.listen(0, '127.0.0.1', () => {
        const addr = slowOrGiantServer.address() as AddressInfo;
        slowServerUrl = `http://127.0.0.1:${addr.port}`;
        resolve();
      });
    });

    const slowTrapMember: EpochWitnessMember = {
      ...toMember(nodes[2]!),
      peerId: 'adversarial-upstream',
      endpoint: slowServerUrl,
    };

    members = nodes.map(toMember);
    const dir = createSignedEpochDirectory({
      epoch: 0,
      quorumSize: 2,
      previousDirectorySha256: '0'.repeat(64),
      members: [...members, slowTrapMember],
      governanceSigners: [govKeypair],
    });
    await broadcastEpochDirectory(
      nodes.map((n) => n.endpoint),
      dir,
    );

    strictDirectory = createSignedEpochDirectory({
      epoch: 0,
      quorumSize: 1,
      previousDirectorySha256: '0'.repeat(64),
      members: [
        { ...toMember(nodes[0]!), peerId: 'meta-imds', endpoint: 'http://169.254.169.254' },
        { ...toMember(nodes[1]!), peerId: 'rfc1918-lan', endpoint: 'http://10.0.0.15:4101' },
        { ...toMember(nodes[2]!), peerId: 'loopback-v4', endpoint: 'http://127.0.0.1:4102' },
        toMember(prodStrictRelay),
      ],
      governanceSigners: [govKeypair],
    });
    await broadcastEpochDirectory([prodStrictRelay.endpoint], strictDirectory);
  });

  afterAll(async () => {
    await Promise.all([
      ...nodes.map((n) => n.stop()),
      prodStrictRelay.stop(),
      new Promise<void>((r) => slowOrGiantServer.close(() => r())),
      new Promise<void>((r) => unlistedServer.close(() => r())),
    ]);
    for (let i = 1; i <= 5; i++) {
      await adminPool.query(`DROP SCHEMA IF EXISTS "${SCHEMA_PREFIX}${i}" CASCADE`);
    }
    await adminPool.end();
  });

  it('1. Blocks private, loopback, CGNAT, ULA, and IPv4-mapped metadata IPs in CIDR classifier and strict relay', async () => {
    expect(isBlockedIpAddress('169.254.169.254', { allowLoopback: true, allowPrivateNetwork: true }).blocked).toBe(true);
    expect(isBlockedIpAddress('::ffff:169.254.169.254', { allowLoopback: true }).blocked).toBe(true);
    expect(isBlockedIpAddress('::ffff:127.0.0.1', { allowLoopback: false }).blocked).toBe(true);
    expect(isBlockedIpAddress('10.10.1.5', { allowLoopback: true, allowPrivateNetwork: false }).blocked).toBe(true);
    expect(isBlockedIpAddress('172.16.5.5', { allowLoopback: false }).blocked).toBe(true);
    expect(isBlockedIpAddress('192.168.1.1', { allowLoopback: false }).blocked).toBe(true);
    expect(isBlockedIpAddress('100.64.0.1', { allowLoopback: true, allowPrivateNetwork: true }).blocked).toBe(true);
    expect(isBlockedIpAddress('fc00::1', { allowPrivateNetwork: false }).blocked).toBe(true);
    expect(isBlockedIpAddress('fe80::1', { allowPrivateNetwork: true }).blocked).toBe(true);
    expect(isBlockedIpAddress('93.184.216.34', { allowLoopback: false, allowPrivateNetwork: false }).blocked).toBe(false);

    const strictM = toMember(prodStrictRelay);
    const hops: [OnionHopTarget, OnionHopTarget, OnionHopTarget] = [
      { x25519PkHex: strictM.x25519PkHex, hopUrl: strictM.endpoint },
      { x25519PkHex: strictM.x25519PkHex, hopUrl: strictM.endpoint },
      { x25519PkHex: strictM.x25519PkHex, hopUrl: strictM.endpoint },
    ];

    // Even if listed in directory, production strict relay blocks metadata / RFC1918 / loopback
    for (const badTarget of ['http://169.254.169.254', 'http://10.0.0.15:4101', 'http://127.0.0.1:4102']) {
      const pkt = wrapOnionPacket(
        hops,
        badTarget,
        Buffer.concat([
          Buffer.from([0x01]),
          Buffer.from(JSON.stringify({ method: 'GET', path: '/v1/issuance' })),
        ]),
        { relayPowBits: 10 },
      );
      const res = await fetch(`${prodStrictRelay.endpoint}/v1/relay`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/octet-stream' },
        body: Buffer.from(pkt),
      });
      expect(res.status).toBe(403);
      expect(await res.json()).toMatchObject({ error: 'BLOCKED_PRIVATE_OR_LINK_LOCAL_TARGET' });
    }
  });

  it('2. Rejects SSRF to unlisted external or local URLs in both intermediate and terminal onion layers', async () => {
    const hops: [OnionHopTarget, OnionHopTarget, OnionHopTarget] = [
      { x25519PkHex: members[0]!.x25519PkHex, hopUrl: members[0]!.endpoint },
      { x25519PkHex: members[1]!.x25519PkHex, hopUrl: members[1]!.endpoint },
      { x25519PkHex: members[2]!.x25519PkHex, hopUrl: members[2]!.endpoint },
    ];

    // 2a. Terminal SSRF against unlisted server
    const ssrfTerminalPkt = wrapOnionPacket(
      hops,
      unlistedServerUrl,
      Buffer.concat([
        Buffer.from([0x01]),
        Buffer.from(JSON.stringify({ method: 'GET', path: '/v1/issuance' })),
      ]),
      { relayPowBits: 10 },
    );
    const termRes = await fetch(`${nodes[0]!.endpoint}/v1/relay`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/octet-stream' },
      body: Buffer.from(ssrfTerminalPkt),
    });
    expect(termRes.status).toBe(403);
    expect(await termRes.json()).toMatchObject({ error: 'RELAY_TARGET_NOT_IN_DIRECTORY' });

    // 2b. Intermediate Hop 1 -> unlisted URL
    const rogueHopTargets: [OnionHopTarget, OnionHopTarget, OnionHopTarget] = [
      { x25519PkHex: members[0]!.x25519PkHex, hopUrl: members[0]!.endpoint },
      { x25519PkHex: members[1]!.x25519PkHex, hopUrl: unlistedServerUrl },
      { x25519PkHex: members[2]!.x25519PkHex, hopUrl: members[2]!.endpoint },
    ];
    const ssrfHopPkt = wrapOnionPacket(
      rogueHopTargets,
      members[2]!.endpoint,
      Buffer.concat([Buffer.from([0x03]), randomBytes(64)]),
      { relayPowBits: 10 },
    );
    const hopRes = await fetch(`${nodes[0]!.endpoint}/v1/relay`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/octet-stream' },
      body: Buffer.from(ssrfHopPkt),
    });
    expect(hopRes.status).toBe(403);
    expect(await hopRes.json()).toMatchObject({ error: 'RELAY_TARGET_NOT_IN_DIRECTORY' });

    // Confirm trap server was NEVER touched
    expect(unlistedHits).toBe(0);

    // 2c. Path traversal inside terminal envelope -> 400 INVALID_TERMINAL_ENVELOPE
    const traversalPkt = wrapOnionPacket(
      hops,
      members[0]!.endpoint,
      Buffer.concat([
        Buffer.from([0x01]),
        Buffer.from(JSON.stringify({ method: 'GET', path: '/v1/../../etc/passwd' })),
      ]),
      { relayPowBits: 10 },
    );
    const travRes = await fetch(`${nodes[0]!.endpoint}/v1/relay`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/octet-stream' },
      body: Buffer.from(traversalPkt),
    });
    expect(travRes.status).toBe(400);
    expect(await travRes.json()).toMatchObject({ error: 'INVALID_TERMINAL_ENVELOPE' });
  });

  it('3. Enforces upstream timeouts and response byte caps', async () => {
    const hops: [OnionHopTarget, OnionHopTarget, OnionHopTarget] = [
      { x25519PkHex: members[0]!.x25519PkHex, hopUrl: members[0]!.endpoint },
      { x25519PkHex: members[1]!.x25519PkHex, hopUrl: members[1]!.endpoint },
      { x25519PkHex: members[2]!.x25519PkHex, hopUrl: members[2]!.endpoint },
    ];

    const slowPkt = wrapOnionPacket(
      hops,
      slowServerUrl,
      Buffer.concat([
        Buffer.from([0x01]),
        Buffer.from(JSON.stringify({ method: 'GET', path: '/v1/slow' })),
      ]),
      { relayPowBits: 10 },
    );
    const slowRes = await fetch(`${nodes[0]!.endpoint}/v1/relay`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/octet-stream' },
      body: Buffer.from(slowPkt),
    });
    expect(slowRes.status).toBe(504);
    expect(await slowRes.json()).toMatchObject({ error: 'RELAY_UPSTREAM_TIMEOUT' });

    const giantPkt = wrapOnionPacket(
      hops,
      slowServerUrl,
      Buffer.concat([
        Buffer.from([0x01]),
        Buffer.from(JSON.stringify({ method: 'GET', path: '/v1/giant' })),
      ]),
      { relayPowBits: 10 },
    );
    const giantRes = await fetch(`${nodes[0]!.endpoint}/v1/relay`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/octet-stream' },
      body: Buffer.from(giantPkt),
    });
    expect(giantRes.status).toBe(502);
    expect(await giantRes.json()).toMatchObject({ error: 'RELAY_UPSTREAM_RESPONSE_TOO_LARGE' });
  });

  it('4. Rejects weak/missing Relay PoW, packet replays, unauthenticated chunk injections, and bounds reassembly memory', async () => {
    const hops: [OnionHopTarget, OnionHopTarget, OnionHopTarget] = [
      { x25519PkHex: members[0]!.x25519PkHex, hopUrl: members[0]!.endpoint },
      { x25519PkHex: members[1]!.x25519PkHex, hopUrl: members[1]!.endpoint },
      { x25519PkHex: members[2]!.x25519PkHex, hopUrl: members[2]!.endpoint },
    ];

    // 4a. Missing/weak PoW -> 429 INVALID_RELAY_POW
    const noPowPkt = wrapOnionPacket(
      hops,
      members[0]!.endpoint,
      Buffer.concat([Buffer.from([0x03]), randomBytes(32)]),
      { relayPowBits: 0 },
    );
    // Guarantee slot0 PoW fails 10-bit check by mutating nonce bits until verify fails or check status
    const noPowRes = await fetch(`${nodes[0]!.endpoint}/v1/relay`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/octet-stream' },
      body: Buffer.from(noPowPkt),
    });
    // ~99.9% of random 0-bit nonces fail 10-bit CLZ; if lucky hit (1/1024) retry once
    if (noPowRes.status === 204) {
      const noPowPkt2 = wrapOnionPacket(
        hops,
        members[0]!.endpoint,
        Buffer.concat([Buffer.from([0x03]), randomBytes(32)]),
        { relayPowBits: 0 },
      );
      const r2 = await fetch(`${nodes[0]!.endpoint}/v1/relay`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/octet-stream' },
        body: Buffer.from(noPowPkt2),
      });
      expect(r2.status).toBe(429);
    } else {
      expect(noPowRes.status).toBe(429);
      expect(await noPowRes.json()).toMatchObject({ error: 'INVALID_RELAY_POW' });
    }

    // 4b. Packet replay -> 409 RELAY_PACKET_REPLAY
    const validCover = wrapOnionPacket(
      hops,
      members[0]!.endpoint,
      Buffer.concat([Buffer.from([0x03]), randomBytes(32)]),
      { relayPowBits: 10 },
    );
    const first = await fetch(`${nodes[0]!.endpoint}/v1/relay`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/octet-stream' },
      body: Buffer.from(validCover),
    });
    expect(first.status).toBe(204);
    const replay = await fetch(`${nodes[0]!.endpoint}/v1/relay`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/octet-stream' },
      body: Buffer.from(validCover),
    });
    expect(replay.status).toBe(409);
    expect(await replay.json()).toMatchObject({ error: 'RELAY_PACKET_REPLAY' });

    // 4c. Unauthenticated chunk injection -> 400 INVALID_CHUNK_AUTH
    const fakeChunk = Buffer.alloc(CHUNK_FRAME_HEADER_SIZE + 32);
    fakeChunk[0] = 0x02;
    randomBytes(16).copy(fakeChunk, 1); // wrong msgId != deriveChunkMsgId(msgSecret)
    fakeChunk[17] = 0;
    fakeChunk[18] = 2;
    randomBytes(32).copy(fakeChunk, 19);
    randomBytes(32).copy(fakeChunk, 51);
    const badChunkPkt = wrapOnionPacket(hops, members[0]!.endpoint, fakeChunk, { relayPowBits: 10 });
    const badChunkRes = await fetch(`${nodes[0]!.endpoint}/v1/relay`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/octet-stream' },
      body: Buffer.from(badChunkPkt),
    });
    expect(badChunkRes.status).toBe(400);
    expect(await badChunkRes.json()).toMatchObject({ error: 'INVALID_CHUNK_AUTH' });

    // 4d. Mismatched chunk secret / digest poisoning -> 400 CHUNK_AUTH_MISMATCH
    const envelope = Buffer.from(JSON.stringify({ method: 'GET', path: '/v1/issuance' }), 'utf8');
    const sec1 = randomBytes(32);
    const msgId = Buffer.from(deriveChunkMsgId(sec1));
    const digest = Buffer.from(sha3Digest(envelope));
    const c0 = Buffer.alloc(CHUNK_FRAME_HEADER_SIZE + 10);
    c0[0] = 0x02;
    msgId.copy(c0, 1);
    c0[17] = 0;
    c0[18] = 2;
    sec1.copy(c0, 19);
    digest.copy(c0, 51);
    envelope.subarray(0, 10).copy(c0, CHUNK_FRAME_HEADER_SIZE);

    const c1Poison = Buffer.alloc(CHUNK_FRAME_HEADER_SIZE + envelope.length - 10);
    c1Poison[0] = 0x02;
    msgId.copy(c1Poison, 1);
    c1Poison[17] = 1;
    c1Poison[18] = 2;
    sec1.copy(c1Poison, 19);
    Buffer.from(sha3Digest(Buffer.from('forged-digest'))).copy(c1Poison, 51);
    envelope.subarray(10).copy(c1Poison, CHUNK_FRAME_HEADER_SIZE);

    const p0Res = await fetch(`${nodes[0]!.endpoint}/v1/relay`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/octet-stream' },
      body: Buffer.from(wrapOnionPacket(hops, members[0]!.endpoint, c0, { relayPowBits: 10 })),
    });
    expect(p0Res.status).toBe(202);

    const p1Res = await fetch(`${nodes[0]!.endpoint}/v1/relay`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/octet-stream' },
      body: Buffer.from(wrapOnionPacket(hops, members[0]!.endpoint, c1Poison, { relayPowBits: 10 })),
    });
    expect(p1Res.status).toBe(400);
    expect(await p1Res.json()).toMatchObject({ error: 'CHUNK_AUTH_MISMATCH' });

    // 4e. Memory cap: maxReassemblyEntries = 2, wait > reassemblyTtlMs (300ms) -> auto-evicts!
    const sec2 = randomBytes(32);
    const cAlt = Buffer.alloc(CHUNK_FRAME_HEADER_SIZE + 10);
    cAlt[0] = 0x02;
    Buffer.from(deriveChunkMsgId(sec2)).copy(cAlt, 1);
    cAlt[17] = 0;
    cAlt[18] = 2;
    sec2.copy(cAlt, 19);
    digest.copy(cAlt, 51);
    expect(
      (
        await fetch(`${nodes[0]!.endpoint}/v1/relay`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/octet-stream' },
          body: Buffer.from(wrapOnionPacket(hops, members[0]!.endpoint, cAlt, { relayPowBits: 10 })),
        })
      ).status,
    ).toBe(202);

    const sec3 = randomBytes(32);
    const cOverflow = Buffer.alloc(CHUNK_FRAME_HEADER_SIZE + 10);
    cOverflow[0] = 0x02;
    Buffer.from(deriveChunkMsgId(sec3)).copy(cOverflow, 1);
    cOverflow[17] = 0;
    cOverflow[18] = 2;
    sec3.copy(cOverflow, 19);
    digest.copy(cOverflow, 51);
    const fullRes = await fetch(`${nodes[0]!.endpoint}/v1/relay`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/octet-stream' },
      body: Buffer.from(wrapOnionPacket(hops, members[0]!.endpoint, cOverflow, { relayPowBits: 10 })),
    });
    expect(fullRes.status).toBe(503);
    expect(await fullRes.json()).toMatchObject({ error: 'REASSEMBLY_BUFFER_FULL' });

    // Wait for 300ms TTL to prune stale buffers -> now succeeds!
    await new Promise((r) => setTimeout(r, 380));
    const afterPruneRes = await fetch(`${nodes[0]!.endpoint}/v1/relay`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/octet-stream' },
      body: Buffer.from(wrapOnionPacket(hops, members[0]!.endpoint, cOverflow, { relayPowBits: 10 })),
    });
    expect(afterPruneRes.status).toBe(202);
  });

  it('5. Supports bursts of PoW-authenticated onion traffic and cover cells without IP false-positives', async () => {
    const statuses = await Promise.all(
      Array.from({ length: 12 }, async (_, idx) => {
        if (idx % 2 === 0) {
          return sendCoverTrafficCell({ peers: members, relayPowBits: 10 });
        }
        const res = await sendViaThreeHopOnion({
          peers: members,
          targetPeer: members[idx % members.length]!,
          method: 'GET',
          path: '/v1/issuance',
          relayPowBits: 10,
        });
        return res.status;
      }),
    );
    expect(statuses.filter((s) => s === 204)).toHaveLength(6);
    expect(statuses.filter((s) => s === 200)).toHaveLength(6);
  });
});

import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import {
  generateNodeKeypair,
  type HybridPublicKeys,
  type SignedEpochDirectory,
} from './crypto.ts';
import { NuvertherNode } from './server.ts';

function requireEnv(name: string, fallback?: string): string {
  const val = process.env[name] ?? fallback;
  if (!val) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return val;
}

async function main(): Promise<void> {
  const peerId = requireEnv('NUVERTHER_PEER_ID', 'witness-01');
  const host = requireEnv('NUVERTHER_HOST', '0.0.0.0');
  const port = Number(process.env.NUVERTHER_PORT ?? process.env.PORT ?? '3000');
  const databaseUrl = requireEnv(
    'DATABASE_URL',
    'postgresql://postgres:postgres@127.0.0.1:5432/postgres',
  );
  const dbSchema = requireEnv('NUVERTHER_DB_SCHEMA', peerId.replace(/[^a-zA-Z0-9_]/g, '_'));
  const publicEndpoint = process.env.NUVERTHER_PUBLIC_ENDPOINT;
  const hashcashBits = Number(process.env.NUVERTHER_HASHCASH_BITS ?? '12');

  const seedSecret = process.env.NUVERTHER_NODE_SEED;
  const seed = seedSecret
    ? new Uint8Array(createHash('sha256').update(`${seedSecret}:${peerId}`).digest())
    : undefined;
  const keypair = generateNodeKeypair(peerId, seed);

  const tlsCertPath = process.env.NUVERTHER_TLS_CERT;
  const tlsKeyPath = process.env.NUVERTHER_TLS_KEY;
  const tls =
    tlsCertPath && tlsKeyPath
      ? { cert: readFileSync(tlsCertPath), key: readFileSync(tlsKeyPath) }
      : undefined;

  const trustedGovernanceKeys = process.env.NUVERTHER_TRUSTED_GOV_KEYS_JSON
    ? (JSON.parse(process.env.NUVERTHER_TRUSTED_GOV_KEYS_JSON) as HybridPublicKeys[])
    : undefined;
  const governanceThreshold = process.env.NUVERTHER_GOV_THRESHOLD
    ? Number(process.env.NUVERTHER_GOV_THRESHOLD)
    : undefined;
  const initialEpochDirectory = process.env.NUVERTHER_INITIAL_EPOCH_DIR_FILE
    ? (JSON.parse(
        readFileSync(process.env.NUVERTHER_INITIAL_EPOCH_DIR_FILE, 'utf8'),
      ) as SignedEpochDirectory)
    : undefined;

  const node = new NuvertherNode({
    peerId,
    host,
    port,
    publicEndpoint,
    databaseUrl,
    dbSchema,
    keypair,
    trustedGovernanceKeys,
    governanceThreshold,
    initialEpochDirectory,
    hashcashBits,
    relayPowBits: process.env.NUVERTHER_RELAY_POW_BITS
      ? Number(process.env.NUVERTHER_RELAY_POW_BITS)
      : undefined,
    relayTimeoutMs: process.env.NUVERTHER_RELAY_TIMEOUT_MS
      ? Number(process.env.NUVERTHER_RELAY_TIMEOUT_MS)
      : undefined,
    maxRelayResponseBytes: process.env.NUVERTHER_MAX_RELAY_RESPONSE_BYTES
      ? Number(process.env.NUVERTHER_MAX_RELAY_RESPONSE_BYTES)
      : undefined,
    relayJitterMaxMs: process.env.NUVERTHER_RELAY_JITTER_MS
      ? Number(process.env.NUVERTHER_RELAY_JITTER_MS)
      : undefined,
    allowLoopbackPeers: process.env.NUVERTHER_ALLOW_LOOPBACK_PEERS === 'true',
    allowPrivateNetworkPeers: process.env.NUVERTHER_ALLOW_PRIVATE_PEERS === 'true',
    tls,
    logLevel: process.env.LOG_LEVEL ?? 'info',
  });

  await node.start();

  const shutdown = async (signal: string) => {
    node.logger.info({ signal }, 'Received shutdown signal');
    await node.stop();
    process.exit(0);
  };

  process.on('SIGTERM', () => {
    void shutdown('SIGTERM');
  });
  process.on('SIGINT', () => {
    void shutdown('SIGINT');
  });
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

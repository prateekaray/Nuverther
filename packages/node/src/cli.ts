import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { generateNodeKeypair } from './crypto.ts';
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

  const node = new NuvertherNode({
    peerId,
    host,
    port,
    publicEndpoint,
    databaseUrl,
    dbSchema,
    keypair,
    hashcashBits,
    tls,
    logLevel: process.env.LOG_LEVEL ?? 'info',
  });

  const endpoint = await node.start();

  // Bootstrap peers if comma-separated NUVERTHER_BOOTSTRAP_PEERS provided
  const bootstrap = (process.env.NUVERTHER_BOOTSTRAP_PEERS ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);

  if (bootstrap.length > 0) {
    const selfRecord = node.getSignedIdentity();
    for (const peerUrl of bootstrap) {
      if (peerUrl === endpoint) continue;
      for (let attempt = 0; attempt < 5; attempt++) {
        try {
          const resp = await fetch(`${peerUrl}/v1/peers`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(selfRecord),
          });
          if (resp.ok) break;
        } catch {
          await new Promise((r) => setTimeout(r, 1000 * (attempt + 1)));
        }
      }
    }
  }

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

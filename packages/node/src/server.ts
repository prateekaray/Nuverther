import http from 'node:http';
import https from 'node:https';
import type { AddressInfo } from 'node:net';
import express, { type Express, type Request, type Response } from 'express';
import helmet from 'helmet';
import pino from 'pino';
import { Counter, Histogram, Registry, collectDefaultMetrics } from 'prom-client';
import { z } from 'zod';
import {
  bytesToFieldScalar,
  normalizeFieldHex,
  verifySpendProof,
  type SpendProofBundle,
  type SpendPublicSignals,
} from '@nuverther/zk';
import {
  ONION_PACKET_SIZE,
  createSignedPeerRecord,
  sha3Digest,
  sha3Hex,
  signHybrid,
  unwrapOnionLayer,
  verifyHybrid,
  verifySignedPeerRecord,
  type HybridSignature,
  type NodeKeypair,
  type SignedPeerRecord,
} from './crypto.ts';
import { NuvertherDatabase } from './db.ts';
import { TokenBucketRateLimiter } from './rateLimit.ts';

export interface NuvertherNodeConfig {
  peerId: string;
  host?: string;
  port?: number;
  publicEndpoint?: string;
  databaseUrl: string;
  dbSchema?: string;
  keypair: NodeKeypair;
  hashcashBits?: number;
  rateLimitCapacity?: number;
  rateLimitRefillPerSec?: number;
  tls?: {
    cert: string | Buffer;
    key: string | Buffer;
  };
  logLevel?: string;
}

export interface WitnessAttestation {
  peerId: string;
  ed25519PkHex: string;
  mldsa65PkB64: string;
  nullifiers: [string, string];
  proofSha256: string;
  txBinding: string;
  issuedAt: string;
  sig: HybridSignature;
}

export function computeExpectedTxBinding(params: {
  ed25519PkHex: string;
  mldsa65PkB64: string;
  outputCommitments: [string, string];
  feeCommitment: string;
}): string {
  const canonical = JSON.stringify([
    'NUV_TX_BIND_V1',
    params.ed25519PkHex,
    params.mldsa65PkB64,
    params.outputCommitments.map((x) => normalizeFieldHex(x)),
    normalizeFieldHex(params.feeCommitment),
  ]);
  return normalizeFieldHex(bytesToFieldScalar(sha3Digest(canonical)));
}

export function spendStatementPayload(signals: SpendPublicSignals): string {
  return JSON.stringify([
    'NUV_SPEND_V1',
    signals.inputCommitments.map((x) => normalizeFieldHex(x)),
    signals.nullifiers.map((x) => normalizeFieldHex(x)),
    signals.outputCommitments.map((x) => normalizeFieldHex(x)),
    normalizeFieldHex(signals.feeCommitment),
    normalizeFieldHex(signals.txBinding),
  ]);
}

export function attestationSigningPayload(att: {
  peerId: string;
  nullifiers: [string, string];
  proofSha256: string;
  txBinding: string;
  issuedAt: string;
}): string {
  return JSON.stringify([
    'NUV_ATTEST_V1',
    att.peerId,
    att.nullifiers,
    att.proofSha256,
    att.txBinding,
    att.issuedAt,
  ]);
}

export function computeShardMacTag(params: {
  shardId: string;
  threadDigest: string;
  shareIndex: number;
  nonceHex: string;
  ciphertextB64: string;
}): string {
  return sha3Hex(
    JSON.stringify([
      'NUV_SHARD_V1',
      params.shardId,
      params.threadDigest,
      params.shareIndex,
      params.nonceHex,
      params.ciphertextB64,
    ]),
  );
}

const FieldHexSchema = z.string().regex(/^0x[0-9a-fA-F]{1,64}$/);

const AttestRequestSchema = z.object({
  proofBundle: z.object({
    proofBase64: z.string().min(64).max(128_000),
    publicInputs: z.array(FieldHexSchema).length(8),
    publicSignals: z.object({
      inputCommitments: z.tuple([FieldHexSchema, FieldHexSchema]),
      nullifiers: z.tuple([FieldHexSchema, FieldHexSchema]),
      outputCommitments: z.tuple([FieldHexSchema, FieldHexSchema]),
      feeCommitment: FieldHexSchema,
      txBinding: FieldHexSchema,
    }),
    vkSha256: z.string().regex(/^[0-9a-f]{64}$/),
  }),
  spenderPub: z.object({
    ed25519PkHex: z.string().regex(/^[0-9a-fA-F]{64}$/),
    mldsa65PkB64: z.string().min(100),
  }),
  spenderSig: z.object({
    ed25519Hex: z.string().regex(/^[0-9a-fA-F]{128}$/),
    mldsa65B64: z.string().min(100),
  }),
});

const StoreShardSchema = z.object({
  shardId: z.string().regex(/^[0-9a-fA-F]{32,128}$/),
  threadDigest: z.string().regex(/^[0-9a-fA-F]{64}$/),
  shareIndex: z.number().int().min(1).max(3),
  nonceHex: z.string().regex(/^[0-9a-fA-F]{48}$/),
  ciphertextB64: z.string().min(16).max(200_000),
  macTagHex: z.string().regex(/^[0-9a-fA-F]{64}$/),
});

const RegisterPeerSchema = z.object({
  peerId: z.string().min(3).max(64),
  endpoint: z.string().url(),
  ed25519PkHex: z.string().regex(/^[0-9a-fA-F]{64}$/),
  mldsa65PkB64: z.string().min(100),
  x25519PkHex: z.string().regex(/^[0-9a-fA-F]{64}$/),
  hashcashNonce: z.string().min(1).max(64),
  hashcashBits: z.number().int().min(1).max(64),
  selfSigEd25519Hex: z.string().regex(/^[0-9a-fA-F]{128}$/),
  selfSigMldsa65B64: z.string().min(100),
});

interface ReassemblyBuffer {
  totalChunks: number;
  chunks: Map<number, Buffer>;
  createdAtMs: number;
}

export class NuvertherNode {
  public readonly app: Express;
  public readonly db: NuvertherDatabase;
  public readonly logger: pino.Logger;
  public readonly registry: Registry;
  private readonly rateLimiter: TokenBucketRateLimiter;
  private readonly config: NuvertherNodeConfig;
  private readonly hashcashBits: number;
  private readonly reassembly = new Map<string, ReassemblyBuffer>();
  private readonly reassemblyTimer: NodeJS.Timeout;
  private server: http.Server | https.Server | null = null;
  private boundEndpoint: string | null = null;

  private readonly attestCounter: Counter<string>;
  private readonly relayCounter: Counter<string>;
  private readonly attestDuration: Histogram<string>;

  constructor(config: NuvertherNodeConfig) {
    this.config = config;
    this.hashcashBits = config.hashcashBits ?? 12;
    this.db = new NuvertherDatabase(config.databaseUrl, config.dbSchema ?? 'public');
    this.logger = pino({
      level: config.logLevel ?? 'info',
      base: { peerId: config.peerId },
      redact: ['req.headers.x-forwarded-for', 'req.remoteAddress'],
    });
    this.rateLimiter = new TokenBucketRateLimiter({
      capacity: config.rateLimitCapacity ?? 500,
      refillPerSecond: config.rateLimitRefillPerSec ?? 250,
    });

    this.registry = new Registry();
    collectDefaultMetrics({ register: this.registry, prefix: 'nuverther_' });
    this.attestCounter = new Counter({
      name: 'nuverther_witness_attestations_total',
      help: 'Total witness attestation outcomes',
      labelNames: ['outcome'],
      registers: [this.registry],
    });
    this.relayCounter = new Counter({
      name: 'nuverther_onion_relay_packets_total',
      help: 'Total 16KB onion packets processed',
      labelNames: ['mode'],
      registers: [this.registry],
    });
    this.attestDuration = new Histogram({
      name: 'nuverther_witness_attest_seconds',
      help: 'Duration of ZK + PQ verification and serializable DB commit',
      registers: [this.registry],
    });

    this.reassemblyTimer = setInterval(() => this.pruneReassembly(), 15_000);
    this.reassemblyTimer.unref();

    this.app = this.buildExpressApp();
  }

  get endpoint(): string {
    return this.boundEndpoint ?? this.config.publicEndpoint ?? `http://127.0.0.1:${this.config.port ?? 0}`;
  }

  getSignedIdentity(): SignedPeerRecord {
    return createSignedPeerRecord(this.config.keypair, this.endpoint, this.hashcashBits);
  }

  private buildExpressApp(): Express {
    const app = express();
    app.disable('x-powered-by');
    app.use(helmet());
    app.use(this.rateLimiter.middleware());

    // Root status & endpoint directory
    app.get('/', (_req: Request, res: Response) => {
      res.status(200).json({
        service: 'nuverther-node',
        peerId: this.config.peerId,
        hashcashBits: this.hashcashBits,
        endpoints: [
          '/healthz',
          '/readyz',
          '/metrics',
          '/v1/identity',
          '/v1/peers',
          '/v1/relay',
          '/v1/witness/attest',
          '/v1/shards',
        ],
      });
    });

    // Health and readiness probes
    app.get('/healthz', (_req: Request, res: Response) => {
      res.status(200).json({ status: 'ok', peerId: this.config.peerId });
    });

    app.get('/readyz', async (_req: Request, res: Response) => {
      const dbOk = await this.db.ping();
      if (!dbOk) {
        res.status(503).json({ status: 'not_ready', peerId: this.config.peerId });
        return;
      }
      res.status(200).json({ status: 'ready', peerId: this.config.peerId });
    });

    app.get('/metrics', async (_req: Request, res: Response) => {
      res.setHeader('Content-Type', this.registry.contentType);
      res.status(200).send(await this.registry.metrics());
    });

    app.get('/v1/identity', (_req: Request, res: Response) => {
      res.status(200).json(this.getSignedIdentity());
    });

    app.get('/v1/peers', async (_req: Request, res: Response) => {
      try {
        const peers = await this.db.listWitnessPeers();
        res.status(200).json({ peers });
      } catch (err) {
        this.logger.error({ err }, 'Failed to list peers');
        res.status(500).json({ error: 'INTERNAL_ERROR' });
      }
    });

    app.post('/v1/peers', express.json({ limit: '64kb' }), async (req: Request, res: Response) => {
      const parsed = RegisterPeerSchema.safeParse(req.body);
      if (!parsed.success) {
        res.status(400).json({ error: 'INVALID_PEER_SCHEMA', details: parsed.error.issues });
        return;
      }
      const record: SignedPeerRecord = parsed.data;
      if (!verifySignedPeerRecord(record, this.hashcashBits)) {
        res.status(403).json({ error: 'INVALID_HASHCASH_OR_SIGNATURE' });
        return;
      }
      await this.db.upsertWitnessPeer(record);
      res.status(201).json({ registered: true, peerId: record.peerId });
    });

    // Stateless 3-Hop Onion Relay: strictly 16,384-byte binary packets
    app.post(
      '/v1/relay',
      express.raw({ type: 'application/octet-stream', limit: '32kb' }),
      async (req: Request, res: Response) => {
        try {
          const body = req.body;
          if (!Buffer.isBuffer(body) || body.length !== ONION_PACKET_SIZE) {
            res.status(400).json({
              error: 'INVALID_ONION_PACKET_SIZE',
              expectedBytes: ONION_PACKET_SIZE,
              actualBytes: Buffer.isBuffer(body) ? body.length : 0,
            });
            return;
          }

          const unwrapped = unwrapOnionLayer(
            new Uint8Array(body),
            this.config.keypair.x25519Sk,
            this.config.keypair.x25519Pk,
          );

          if (unwrapped.mode === 'relay') {
            this.relayCounter.inc({ mode: 'relay' });
            const upstream = await fetch(`${unwrapped.nextHopUrl}/v1/relay`, {
              method: 'POST',
              headers: {
                'Content-Type': 'application/octet-stream',
                'Content-Length': String(ONION_PACKET_SIZE),
              },
              body: Buffer.from(unwrapped.nextPacket),
            });
            const upstreamText = await upstream.text();
            res
              .status(upstream.status)
              .type(upstream.headers.get('content-type') || 'application/json')
              .send(upstreamText);
            return;
          }

          // Terminal hop execution (never forwards originating client IP)
          this.relayCounter.inc({ mode: 'terminal' });
          const payloadBuf = Buffer.from(unwrapped.payload);
          const frameType = payloadBuf[0];
          let envelopeBytes: Buffer | null = null;

          if (frameType === 0x01) {
            envelopeBytes = payloadBuf.subarray(1);
          } else if (frameType === 0x02 && payloadBuf.length >= 19) {
            const msgId = payloadBuf.subarray(1, 17).toString('hex');
            const chunkIndex = payloadBuf[17]!;
            const totalChunks = payloadBuf[18]!;
            const chunkData = payloadBuf.subarray(19);

            if (totalChunks < 1 || totalChunks > 16 || chunkIndex >= totalChunks) {
              res.status(400).json({ error: 'INVALID_ONION_CHUNK_HEADER' });
              return;
            }

            let entry = this.reassembly.get(msgId);
            if (!entry) {
              entry = { totalChunks, chunks: new Map(), createdAtMs: Date.now() };
              this.reassembly.set(msgId, entry);
            }
            entry.chunks.set(chunkIndex, chunkData);

            if (entry.chunks.size < entry.totalChunks) {
              res.status(202).json({
                accepted: true,
                chunkIndex,
                received: entry.chunks.size,
                totalChunks: entry.totalChunks,
              });
              return;
            }

            const ordered: Buffer[] = [];
            for (let i = 0; i < entry.totalChunks; i++) {
              const part = entry.chunks.get(i);
              if (!part) {
                res.status(400).json({ error: 'MISSING_ONION_CHUNK' });
                return;
              }
              ordered.push(part);
            }
            this.reassembly.delete(msgId);
            envelopeBytes = Buffer.concat(ordered);
          } else {
            res.status(400).json({ error: 'INVALID_TERMINAL_FRAME' });
            return;
          }

          const envelope = JSON.parse(envelopeBytes.toString('utf8')) as {
            method: 'GET' | 'POST';
            path: string;
            body?: unknown;
          };

          if (
            typeof envelope.path !== 'string' ||
            !envelope.path.startsWith('/v1/') ||
            (envelope.method !== 'GET' && envelope.method !== 'POST')
          ) {
            res.status(400).json({ error: 'INVALID_TERMINAL_ENVELOPE' });
            return;
          }

          const targetResp = await fetch(`${unwrapped.targetUrl}${envelope.path}`, {
            method: envelope.method,
            headers: envelope.method === 'POST' ? { 'Content-Type': 'application/json' } : undefined,
            body: envelope.method === 'POST' ? JSON.stringify(envelope.body ?? {}) : undefined,
          });
          const targetBody = await targetResp.text();
          res
            .status(targetResp.status)
            .type(targetResp.headers.get('content-type') || 'application/json')
            .send(targetBody);
        } catch (err) {
          this.logger.warn({ err }, 'Onion relay unwrap/forward rejected');
          res.status(400).json({ error: 'ONION_DECRYPT_OR_FORWARD_FAILED' });
        }
      },
    );

    // Witness Attestation Endpoint (ZK Proof + Hybrid Ed25519/ML-DSA-65 + SERIALIZABLE Nullifier DB)
    app.post(
      '/v1/witness/attest',
      express.json({ limit: '256kb' }),
      async (req: Request, res: Response) => {
        const stopTimer = this.attestDuration.startTimer();
        try {
          const parsed = AttestRequestSchema.safeParse(req.body);
          if (!parsed.success) {
            this.attestCounter.inc({ outcome: 'invalid_schema' });
            res.status(400).json({ error: 'INVALID_ATTEST_SCHEMA', details: parsed.error.issues });
            return;
          }

          const { proofBundle, spenderPub, spenderSig } = parsed.data;
          const normalizedBundle: SpendProofBundle = {
            proofBase64: proofBundle.proofBase64,
            publicInputs: proofBundle.publicInputs.map((x) => normalizeFieldHex(x)),
            publicSignals: {
              inputCommitments: [
                normalizeFieldHex(proofBundle.publicSignals.inputCommitments[0]),
                normalizeFieldHex(proofBundle.publicSignals.inputCommitments[1]),
              ],
              nullifiers: [
                normalizeFieldHex(proofBundle.publicSignals.nullifiers[0]),
                normalizeFieldHex(proofBundle.publicSignals.nullifiers[1]),
              ],
              outputCommitments: [
                normalizeFieldHex(proofBundle.publicSignals.outputCommitments[0]),
                normalizeFieldHex(proofBundle.publicSignals.outputCommitments[1]),
              ],
              feeCommitment: normalizeFieldHex(proofBundle.publicSignals.feeCommitment),
              txBinding: normalizeFieldHex(proofBundle.publicSignals.txBinding),
            },
            vkSha256: proofBundle.vkSha256,
          };

          // 1. Verify txBinding cryptographically binds spender PQ public keys + outputs
          const expectedTxBinding = computeExpectedTxBinding({
            ed25519PkHex: spenderPub.ed25519PkHex,
            mldsa65PkB64: spenderPub.mldsa65PkB64,
            outputCommitments: normalizedBundle.publicSignals.outputCommitments,
            feeCommitment: normalizedBundle.publicSignals.feeCommitment,
          });
          if (normalizedBundle.publicSignals.txBinding !== expectedTxBinding) {
            this.attestCounter.inc({ outcome: 'tx_binding_mismatch' });
            res.status(403).json({ error: 'TX_BINDING_MISMATCH' });
            return;
          }

          // 2. Verify Hybrid Ed25519 + ML-DSA-65 spender authorization signature
          const sigOk = verifyHybrid(
            spendStatementPayload(normalizedBundle.publicSignals),
            spenderSig,
            spenderPub,
          );
          if (!sigOk) {
            this.attestCounter.inc({ outcome: 'invalid_pq_signature' });
            res.status(403).json({ error: 'INVALID_HYBRID_PQ_SIGNATURE' });
            return;
          }

          // 3. Verify Noir UltraHonk proof against pinned deterministic VK
          const zkOk = await verifySpendProof(normalizedBundle);
          if (!zkOk) {
            this.attestCounter.inc({ outcome: 'invalid_zk_proof' });
            res.status(403).json({ error: 'INVALID_ZK_PROOF' });
            return;
          }

          // 4. Sign Witness attestation receipt BEFORE atomic PostgreSQL claim
          const proofSha256 = sha3Hex(Buffer.from(normalizedBundle.proofBase64, 'base64'));
          const issuedAt = new Date().toISOString();
          const attestationBody = {
            peerId: this.config.peerId,
            nullifiers: normalizedBundle.publicSignals.nullifiers,
            proofSha256,
            txBinding: normalizedBundle.publicSignals.txBinding,
            issuedAt,
          };
          const witnessSig = signHybrid(
            attestationSigningPayload(attestationBody),
            this.config.keypair.ed25519Sk,
            this.config.keypair.mldsa65Sk,
          );

          // 5. Atomic SERIALIZABLE INSERT ... ON CONFLICT DO NOTHING in PostgreSQL
          const claim = await this.db.claimNullifiersAtomic({
            nullifiers: normalizedBundle.publicSignals.nullifiers,
            txBinding: normalizedBundle.publicSignals.txBinding,
            proofSha256,
            attestationEd25519: witnessSig.ed25519Hex,
            attestationMldsa65: witnessSig.mldsa65B64,
          });

          if (!claim.ok) {
            this.attestCounter.inc({ outcome: 'double_spend' });
            res.status(409).json({ error: 'ERR_DOUBLE_SPEND' });
            return;
          }

          this.attestCounter.inc({ outcome: 'attested' });
          const receipt: WitnessAttestation = {
            ...attestationBody,
            ed25519PkHex: Buffer.from(this.config.keypair.ed25519Pk).toString('hex'),
            mldsa65PkB64: Buffer.from(this.config.keypair.mldsa65Pk).toString('base64'),
            sig: witnessSig,
          };
          res.status(200).json({ attestation: receipt });
        } catch (err) {
          this.attestCounter.inc({ outcome: 'error' });
          this.logger.error({ err }, 'Witness attestation failed');
          res.status(500).json({ error: 'INTERNAL_ERROR' });
        } finally {
          stopTimer();
        }
      },
    );

    // Blind Shard Storage (XChaCha20-Poly1305 encrypted Shamir shares only)
    app.post('/v1/shards', express.json({ limit: '256kb' }), async (req: Request, res: Response) => {
      const parsed = StoreShardSchema.safeParse(req.body);
      if (!parsed.success) {
        res.status(400).json({ error: 'INVALID_SHARD_SCHEMA', details: parsed.error.issues });
        return;
      }
      const shard = parsed.data;
      const expectedMac = computeShardMacTag(shard);
      if (shard.macTagHex !== expectedMac) {
        res.status(400).json({ error: 'TAMPERED_SHARD_MAC' });
        return;
      }
      await this.db.storeBlindShard(shard);
      res.status(201).json({ stored: true, shardId: shard.shardId, shareIndex: shard.shareIndex });
    });

    app.get('/v1/shards/:shardId', async (req: Request, res: Response) => {
      const shardId = String(req.params.shardId ?? '');
      if (!/^[0-9a-fA-F]{32,128}$/.test(shardId)) {
        res.status(400).json({ error: 'INVALID_SHARD_ID' });
        return;
      }
      const shard = await this.db.getBlindShard(shardId);
      if (!shard) {
        res.status(404).json({ error: 'SHARD_NOT_FOUND' });
        return;
      }
      const expectedMac = computeShardMacTag(shard);
      if (shard.macTagHex !== expectedMac) {
        res.status(500).json({ error: 'CORRUPTED_SHARD_INTEGRITY' });
        return;
      }
      res.status(200).json({ shard });
    });

    return app;
  }

  private pruneReassembly(): void {
    const cutoff = Date.now() - 30_000;
    for (const [key, entry] of this.reassembly.entries()) {
      if (entry.createdAtMs < cutoff) {
        this.reassembly.delete(key);
      }
    }
  }

  async start(): Promise<string> {
    await this.db.migrate();
    const host = this.config.host ?? '127.0.0.1';
    const port = this.config.port ?? 0;

    await new Promise<void>((resolveStart, rejectStart) => {
      const server = this.config.tls
        ? https.createServer({ cert: this.config.tls.cert, key: this.config.tls.key }, this.app)
        : http.createServer(this.app);

      server.once('error', rejectStart);
      server.listen(port, host, () => {
        server.off('error', rejectStart);
        this.server = server;
        const addr = server.address() as AddressInfo;
        const protocol = this.config.tls ? 'https' : 'http';
        this.boundEndpoint =
          this.config.publicEndpoint ?? `${protocol}://${host === '0.0.0.0' ? '127.0.0.1' : host}:${addr.port}`;
        resolveStart();
      });
    });

    const selfRecord = this.getSignedIdentity();
    await this.db.upsertWitnessPeer(selfRecord);
    this.logger.info({ endpoint: this.boundEndpoint }, 'Nuverther node started');
    return this.endpoint;
  }

  async stop(): Promise<void> {
    clearInterval(this.reassemblyTimer);
    this.rateLimiter.stop();
    if (this.server) {
      await new Promise<void>((resolveClose, rejectClose) => {
        this.server!.close((err) => {
          if (err) rejectClose(err);
          else resolveClose();
        });
      });
      this.server = null;
    }
    await this.db.close();
    this.logger.info('Nuverther node stopped gracefully');
  }
}

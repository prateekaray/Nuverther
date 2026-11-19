import http from 'node:http';
import https from 'node:https';
import { randomInt } from 'node:crypto';
import type { AddressInfo } from 'node:net';
import express, { type Express, type Request, type Response } from 'express';
import helmet from 'helmet';
import pino from 'pino';
import { Counter, Histogram, Registry, collectDefaultMetrics } from 'prom-client';
import { z } from 'zod';
import {
  MAX_U64,
  Poseidon2MerkleTree,
  bytesToFieldScalar,
  computeCommitment,
  computeLeaf,
  normalizeFieldHex,
  verifySpendProof,
  type SpendProofBundle,
  type SpendPublicSignals,
} from '@nuverther/zk';
import {
  CHUNK_FRAME_HEADER_SIZE,
  DEFAULT_QUORUM_SIZE,
  DEFAULT_RELAY_POW_BITS,
  ONION_PACKET_SIZE,
  abortRequestSigningPayload,
  computeAuthPkHash,
  computeChainedCheckpointHash,
  computeEpochDirectoryHash,
  createSignedPeerRecord,
  deriveChunkMsgId,
  extractOnionSlot0AuthPrefix,
  issuanceSigningPayload,
  prepareVoteSigningPayload,
  rootCheckpointSigningPayload,
  selectWitnessQuorumForEpoch,
  sha3Digest,
  sha3Hex,
  signHybrid,
  unwrapOnionLayer,
  verifyEquivocationProof,
  verifyHybrid,
  verifyRelaySlotPoW,
  verifySignedEpochDirectory,
  type ChainedWitnessCheckpoint,
  type EquivocationProof,
  type HybridPublicKeys,
  type HybridSignature,
  type NodeKeypair,
  type PrepareVote,
  type SignedEpochDirectory,
  type SignedIssuanceRecord,
  type SignedPeerRecord,
} from './crypto.ts';
import { NuvertherDatabase } from './db.ts';
import { TokenBucketRateLimiter } from './rateLimit.ts';
import {
  RelaySecurityError,
  assertRelayTargetAllowed,
  fetchWithTimeoutAndCap,
} from './ssrf.ts';

export interface NuvertherNodeConfig {
  peerId: string;
  host?: string;
  port?: number;
  publicEndpoint?: string;
  databaseUrl: string;
  dbSchema?: string;
  keypair: NodeKeypair;
  trustedIssuers?: HybridPublicKeys[];
  trustedGovernanceKeys?: HybridPublicKeys[];
  governanceThreshold?: number;
  initialEpochDirectory?: SignedEpochDirectory;
  prepareLeaseMs?: number;
  hashcashBits?: number;
  relayPowBits?: number;
  relayTimeoutMs?: number;
  maxRelayResponseBytes?: number;
  relayJitterMaxMs?: number;
  allowLoopbackPeers?: boolean;
  allowPrivateNetworkPeers?: boolean;
  reassemblyTtlMs?: number;
  maxReassemblyEntries?: number;
  maxReassemblyTotalBytes?: number;
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
  authPkHash: string;
  merkleRoot: string;
  outputCommitments: [string, string];
  feeCommitment: string;
}): string {
  const canonical = JSON.stringify([
    'NUV_TX_BIND_V2',
    normalizeFieldHex(params.authPkHash),
    normalizeFieldHex(params.merkleRoot),
    params.outputCommitments.map((x) => normalizeFieldHex(x)),
    normalizeFieldHex(params.feeCommitment),
  ]);
  return normalizeFieldHex(bytesToFieldScalar(sha3Digest(canonical)));
}

export function spendStatementPayload(signals: SpendPublicSignals): string {
  return JSON.stringify([
    'NUV_SPEND_V2',
    normalizeFieldHex(signals.merkleRoot),
    signals.nullifiers.map((x) => normalizeFieldHex(x)),
    signals.outputCommitments.map((x) => normalizeFieldHex(x)),
    normalizeFieldHex(signals.feeCommitment),
    normalizeFieldHex(signals.authPkHash),
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

const HybridPubSchema = z.object({
  ed25519PkHex: z.string().regex(/^[0-9a-fA-F]{64}$/),
  mldsa65PkB64: z.string().min(100),
});

const HybridSigSchema = z.object({
  ed25519Hex: z.string().regex(/^[0-9a-fA-F]{128}$/),
  mldsa65B64: z.string().min(100),
});

const PublicSignalsSchema = z.object({
  merkleRoot: FieldHexSchema,
  nullifiers: z.tuple([FieldHexSchema, FieldHexSchema]),
  outputCommitments: z.tuple([FieldHexSchema, FieldHexSchema]),
  feeCommitment: FieldHexSchema,
  authPkHash: FieldHexSchema,
  txBinding: FieldHexSchema,
});

const AttestRequestSchema = z.object({
  proofBundle: z.object({
    proofBase64: z.string().min(64).max(128_000),
    publicInputs: z.array(FieldHexSchema).length(8),
    publicSignals: PublicSignalsSchema,
    vkSha256: z.string().regex(/^[0-9a-f]{64}$/),
  }),
  spenderPub: HybridPubSchema,
  spenderSig: HybridSigSchema,
});

const IssuanceSchema = z.object({
  issuanceId: z.string().min(4).max(128),
  epoch: z.number().int().min(0),
  txKind: z.enum(['genesis', 'mint']),
  amount: z.string().regex(/^\d+$/),
  ownerPkHex: FieldHexSchema,
  blindingHex: FieldHexSchema,
  noteCommitmentHex: FieldHexSchema,
  leafIndex: z.number().int().min(0),
  issuerPub: HybridPubSchema,
  issuerSig: HybridSigSchema,
});

const CommitOutputsSchema = z.object({
  epoch: z.number().int().min(0),
  publicSignals: PublicSignalsSchema,
  attestations: z
    .array(
      z.object({
        peerId: z.string().min(3).max(64),
        ed25519PkHex: z.string().regex(/^[0-9a-fA-F]{64}$/),
        mldsa65PkB64: z.string().min(100),
        nullifiers: z.tuple([FieldHexSchema, FieldHexSchema]),
        proofSha256: z.string().regex(/^[0-9a-f]{64}$/),
        txBinding: FieldHexSchema,
        issuedAt: z.string().min(10),
        sig: HybridSigSchema,
      }),
    )
    .min(DEFAULT_QUORUM_SIZE),
});

const PrepareVoteSchema = z.object({
  peerId: z.string().min(3).max(64),
  epoch: z.number().int().min(0),
  nullifiers: z.tuple([FieldHexSchema, FieldHexSchema]),
  proofSha256: z.string().regex(/^[0-9a-f]{64}$/),
  txBinding: FieldHexSchema,
  expiresAt: z.string().min(10),
  ed25519PkHex: z.string().regex(/^[0-9a-fA-F]{64}$/),
  mldsa65PkB64: z.string().min(100),
  sig: HybridSigSchema,
});

const PrepareRequestSchema = z.object({
  epoch: z.number().int().min(0).default(0),
  leaseMs: z.number().int().min(1000).max(120_000).optional(),
  proofBundle: AttestRequestSchema.shape.proofBundle,
  spenderPub: HybridPubSchema,
  spenderSig: HybridSigSchema,
});

const CommitRequestSchema = z.object({
  epoch: z.number().int().min(0).default(0),
  proofBundle: AttestRequestSchema.shape.proofBundle,
  spenderPub: HybridPubSchema,
  spenderSig: HybridSigSchema,
  prepareVotes: z.array(PrepareVoteSchema).min(1),
});

const AbortRequestSchema = z.object({
  epoch: z.number().int().min(0),
  txBinding: FieldHexSchema,
  spenderPub: HybridPubSchema,
  spenderSig: HybridSigSchema,
});

const EpochDirectorySchema = z.object({
  version: z.literal(1),
  epoch: z.number().int().min(0),
  quorumSize: z.number().int().min(1),
  nullifierEpochRetention: z.number().int().min(1),
  validFrom: z.string().min(10),
  expiresAt: z.string().min(10),
  previousDirectorySha256: z.string().regex(/^[0-9a-f]{64}$/),
  members: z
    .array(
      z.object({
        peerId: z.string().min(3).max(64),
        endpoint: z.string().url(),
        ed25519PkHex: z.string().regex(/^[0-9a-fA-F]{64}$/),
        mldsa65PkB64: z.string().min(100),
        x25519PkHex: z.string().regex(/^[0-9a-fA-F]{64}$/),
        joinedEpoch: z.number().int().min(0),
      }),
    )
    .min(1),
  revokedPeers: z.array(
    z.object({
      peerId: z.string().min(3).max(64),
      revokedAtEpoch: z.number().int().min(0),
      reason: z.string().min(1),
      equivocationProofHash: z.string().optional(),
    }),
  ),
  governanceApprovals: z
    .array(
      z.object({
        signerId: z.string().min(1),
        pub: HybridPubSchema,
        sig: HybridSigSchema,
      }),
    )
    .min(1),
});

const ChainedCheckpointSchema = z.object({
  epoch: z.number().int().min(0),
  seq: z.number().int().min(0),
  prevHash: z.string().regex(/^[0-9a-f]{64}$/),
  stateRoot: FieldHexSchema,
  txBinding: FieldHexSchema,
  treeSize: z.number().int().min(0),
  witnessPeerId: z.string().min(3).max(64),
  checkpointHash: z.string().regex(/^[0-9a-f]{64}$/),
  ed25519PkHex: z.string().regex(/^[0-9a-fA-F]{64}$/),
  mldsa65PkB64: z.string().min(100),
  sig: HybridSigSchema,
  createdAt: z.string().min(10),
});

const EquivocationProofSchema = z.discriminatedUnion('kind', [
  z.object({
    kind: z.literal('CHECKPOINT_FORK'),
    witnessPeerId: z.string().min(3).max(64),
    first: ChainedCheckpointSchema,
    second: ChainedCheckpointSchema,
  }),
  z.object({
    kind: z.literal('PREPARE_CONFLICT'),
    witnessPeerId: z.string().min(3).max(64),
    first: PrepareVoteSchema,
    second: PrepareVoteSchema,
  }),
]);

const StoreShardSchema = z.object({
  shardId: z.string().regex(/^[0-9a-fA-F]{32,128}$/),
  threadDigest: z.string().regex(/^[0-9a-fA-F]{64}$/),
  shareIndex: z.number().int().min(1).max(3),
  nonceHex: z.string().regex(/^[0-9a-fA-F]{48}$/),
  ciphertextB64: z.string().min(16).max(200_000),
  macTagHex: z.string().regex(/^[0-9a-fA-F]{64}$/),
});

interface ReassemblyBuffer {
  totalChunks: number;
  msgSecretHex: string;
  msgSha3Hex: string;
  totalBytes: number;
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
  private readonly relayPowBits: number;
  private readonly relayTimeoutMs: number;
  private readonly maxRelayResponseBytes: number;
  private readonly relayJitterMaxMs: number;
  private readonly allowLoopbackPeers: boolean;
  private readonly allowPrivateNetworkPeers: boolean;
  private readonly reassemblyTtlMs: number;
  private readonly maxReassemblyEntries: number;
  private readonly maxReassemblyTotalBytes: number;
  private readonly trustedIssuers: HybridPublicKeys[];
  private readonly trustedGovernanceKeys: HybridPublicKeys[];
  private readonly governanceThreshold: number;
  private readonly prepareLeaseMs: number;
  private readonly reassembly = new Map<string, ReassemblyBuffer>();
  private reassemblyBytes = 0;
  private readonly seenRelayEphemPks = new Map<string, number>();
  private readonly reassemblyTimer: NodeJS.Timeout;
  private activeDirectory: SignedEpochDirectory | null = null;
  private activeDirectoryHash: string | null = null;
  private slashedPeers = new Set<string>();
  private merkleTree: Poseidon2MerkleTree | null = null;
  private treeQueue: Promise<unknown> = Promise.resolve();
  private server: http.Server | https.Server | null = null;
  private boundEndpoint: string | null = null;

  private readonly attestCounter: Counter<string>;
  private readonly relayCounter: Counter<string>;
  private readonly equivocationCounter: Counter<string>;
  private readonly attestDuration: Histogram<string>;

  constructor(config: NuvertherNodeConfig) {
    this.config = config;
    this.hashcashBits = config.hashcashBits ?? 12;
    this.relayPowBits = config.relayPowBits ?? DEFAULT_RELAY_POW_BITS;
    this.relayTimeoutMs = config.relayTimeoutMs ?? 10_000;
    this.maxRelayResponseBytes = config.maxRelayResponseBytes ?? 512 * 1024;
    this.relayJitterMaxMs = config.relayJitterMaxMs ?? 0;
    this.allowLoopbackPeers = config.allowLoopbackPeers ?? false;
    this.allowPrivateNetworkPeers = config.allowPrivateNetworkPeers ?? false;
    this.reassemblyTtlMs = config.reassemblyTtlMs ?? 5_000;
    this.maxReassemblyEntries = config.maxReassemblyEntries ?? 64;
    this.maxReassemblyTotalBytes = config.maxReassemblyTotalBytes ?? 4 * 1024 * 1024;
    const selfPub: HybridPublicKeys = {
      ed25519PkHex: Buffer.from(config.keypair.ed25519Pk).toString('hex'),
      mldsa65PkB64: Buffer.from(config.keypair.mldsa65Pk).toString('base64'),
    };
    this.trustedIssuers = config.trustedIssuers ?? [selfPub];
    this.trustedGovernanceKeys = config.trustedGovernanceKeys ?? [selfPub];
    this.governanceThreshold = config.governanceThreshold ?? 1;
    this.prepareLeaseMs = config.prepareLeaseMs ?? 15_000;
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
    this.equivocationCounter = new Counter({
      name: 'nuverther_witness_equivocations_total',
      help: 'Total proven witness equivocation events',
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

  private withTreeLock<T>(fn: (tree: Poseidon2MerkleTree) => Promise<T>): Promise<T> {
    const next = this.treeQueue.then(() => {
      if (!this.merkleTree) {
        throw new Error('Node Merkle tree not initialized');
      }
      return fn(this.merkleTree);
    });
    this.treeQueue = next.catch(() => undefined);
    return next;
  }

  private isTrustedIssuer(pub: HybridPublicKeys): boolean {
    const targetEd = pub.ed25519PkHex.toLowerCase();
    return this.trustedIssuers.some(
      (i) => i.ed25519PkHex.toLowerCase() === targetEd && i.mldsa65PkB64 === pub.mldsa65PkB64,
    );
  }

  private signRootCheckpoint(epoch: number, treeSize: number, merkleRootHex: string): HybridSignature {
    return signHybrid(
      rootCheckpointSigningPayload({
        epoch,
        treeSize,
        merkleRootHex,
        witnessPeerId: this.config.peerId,
      }),
      this.config.keypair.ed25519Sk,
      this.config.keypair.mldsa65Sk,
    );
  }

  private async recordChainedCheckpoint(
    epoch: number,
    stateRoot: string,
    txBinding: string,
    treeSize: number,
  ): Promise<ChainedWitnessCheckpoint> {
    const last = await this.db.getLastCheckpoint(epoch);
    const seq = last ? last.seq + 1 : 0;
    const prevHash = last ? last.checkpointHash : '0'.repeat(64);
    const checkpointBase = {
      epoch,
      seq,
      prevHash,
      stateRoot: normalizeFieldHex(stateRoot),
      txBinding: normalizeFieldHex(txBinding),
      treeSize,
      witnessPeerId: this.config.peerId,
    };
    const checkpointHash = computeChainedCheckpointHash(checkpointBase);
    const sig = signHybrid(
      JSON.stringify([
        'NUV_CHECKPOINT_CHAIN_V1',
        checkpointBase.epoch,
        checkpointBase.seq,
        checkpointBase.prevHash,
        checkpointBase.stateRoot,
        checkpointBase.txBinding,
        checkpointBase.treeSize,
        checkpointBase.witnessPeerId,
      ]),
      this.config.keypair.ed25519Sk,
      this.config.keypair.mldsa65Sk,
    );
    const cp: ChainedWitnessCheckpoint = {
      ...checkpointBase,
      checkpointHash,
      ed25519PkHex: Buffer.from(this.config.keypair.ed25519Pk).toString('hex'),
      mldsa65PkB64: Buffer.from(this.config.keypair.mldsa65Pk).toString('base64'),
      sig,
      createdAt: new Date().toISOString(),
    };
    await this.db.appendWitnessCheckpoint(cp);
    return cp;
  }

  private async getDirectoryForSpendEpoch(
    epoch: number,
  ): Promise<{ ok: true; directory: SignedEpochDirectory } | { ok: false; status: number; error: string }> {
    if (!this.activeDirectory) {
      return { ok: false, status: 503, error: 'NO_ACTIVE_EPOCH_DIRECTORY' };
    }
    const minRetained = Math.max(0, this.activeDirectory.epoch - this.activeDirectory.nullifierEpochRetention);
    if (epoch < minRetained) {
      return { ok: false, status: 403, error: 'EPOCH_EXPIRED' };
    }
    if (epoch > this.activeDirectory.epoch) {
      return { ok: false, status: 403, error: 'FUTURE_EPOCH_NOT_ACTIVE' };
    }
    const dirRecord =
      epoch === this.activeDirectory.epoch
        ? { directory: this.activeDirectory }
        : await this.db.getEpochDirectory(epoch);
    const directory = dirRecord?.directory ?? this.activeDirectory;
    return { ok: true, directory };
  }

  private verifyQuorumMembership(
    epoch: number,
    nullifier0: string,
    directory: SignedEpochDirectory,
  ): { inQuorum: boolean; quorumPeerIds: string[] } {
    const activeMembers = directory.members.filter((m) => !this.slashedPeers.has(m.peerId));
    if (activeMembers.length < directory.quorumSize) {
      return { inQuorum: false, quorumPeerIds: [] };
    }
    const quorum = selectWitnessQuorumForEpoch(
      epoch,
      nullifier0,
      activeMembers,
      directory.quorumSize,
    );
    const quorumPeerIds = quorum.map((m) => m.peerId);
    return {
      inQuorum: !this.slashedPeers.has(this.config.peerId) && quorumPeerIds.includes(this.config.peerId),
      quorumPeerIds,
    };
  }

  private buildExpressApp(): Express {
    const app = express();
    app.disable('x-powered-by');
    app.use(helmet());
    const ipRateLimiter = this.rateLimiter.middleware();
    app.use((req, res, next) => {
      // Onion relay traffic arrives from peer relays, so IP limiting is bypassed here
      // in favor of per-hop Relay PoW + ephemPk replay defense on POST /v1/relay.
      if (req.path === '/v1/relay') {
        next();
        return;
      }
      ipRateLimiter(req, res, next);
    });

    app.get('/', (_req: Request, res: Response) => {
      res.status(200).json({
        service: 'nuverther-node',
        peerId: this.config.peerId,
        activeEpoch: this.activeDirectory?.epoch ?? null,
        endpoints: [
          '/healthz',
          '/readyz',
          '/metrics',
          '/v1/identity',
          '/v1/peers',
          '/v1/governance/epoch',
          '/v1/governance/equivocation',
          '/v1/witness/checkpoints',
          '/v1/witness/prepare',
          '/v1/witness/commit',
          '/v1/witness/abort',
          '/v1/witness/attest',
          '/v1/issuance',
          '/v1/tree/root',
          '/v1/tree/commitments',
          '/v1/tree/commit-outputs',
          '/v1/relay',
          '/v1/shards',
        ],
      });
    });

    app.get('/healthz', (_req: Request, res: Response) => {
      res.status(200).json({ status: 'ok', peerId: this.config.peerId });
    });

    app.get('/readyz', async (_req: Request, res: Response) => {
      const dbOk = await this.db.ping();
      if (!dbOk || !this.merkleTree) {
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
        if (this.activeDirectory) {
          res.status(200).json({
            epoch: this.activeDirectory.epoch,
            directoryHash: this.activeDirectoryHash,
            quorumSize: this.activeDirectory.quorumSize,
            directory: this.activeDirectory,
            peers: this.activeDirectory.members,
          });
          return;
        }
        res.status(200).json({ epoch: null, directoryHash: null, quorumSize: DEFAULT_QUORUM_SIZE, peers: [] });
      } catch (err) {
        this.logger.error({ err }, 'Failed to list peers');
        res.status(500).json({ error: 'INTERNAL_ERROR' });
      }
    });

    // Free-form self-admission replaced by governance-signed epoch directories
    app.post('/v1/peers', (_req: Request, res: Response) => {
      res.status(410).json({
        error: 'FREEFORM_PEER_REGISTRATION_REMOVED',
        message: 'Peer set is governed by signed epoch directories at POST /v1/governance/epoch',
      });
    });

    app.get('/v1/governance/epoch', async (_req: Request, res: Response) => {
      const equivocations = await this.db.listEquivocationProofs();
      res.status(200).json({
        activeEpoch: this.activeDirectory?.epoch ?? null,
        directoryHash: this.activeDirectoryHash,
        directory: this.activeDirectory,
        slashedPeers: [...this.slashedPeers],
        equivocations,
      });
    });

    app.post('/v1/governance/epoch', express.json({ limit: '128kb' }), async (req: Request, res: Response) => {
      const parsed = EpochDirectorySchema.safeParse(req.body);
      if (!parsed.success) {
        res.status(400).json({ error: 'INVALID_EPOCH_DIRECTORY_SCHEMA', details: parsed.error.issues });
        return;
      }
      const dir: SignedEpochDirectory = parsed.data;
      if (!verifySignedEpochDirectory(dir, this.trustedGovernanceKeys, this.governanceThreshold)) {
        res.status(403).json({ error: 'INVALID_GOVERNANCE_SIGNATURE' });
        return;
      }

      if (this.activeDirectory) {
        if (dir.epoch < this.activeDirectory.epoch) {
          res.status(409).json({
            error: 'STALE_EPOCH_DIRECTORY',
            activeEpoch: this.activeDirectory.epoch,
            receivedEpoch: dir.epoch,
          });
          return;
        }
        if (dir.epoch === this.activeDirectory.epoch) {
          const incomingHash = computeEpochDirectoryHash(dir);
          if (incomingHash === this.activeDirectoryHash) {
            res.status(200).json({
              activatedEpoch: dir.epoch,
              directoryHash: incomingHash,
              idempotent: true,
              prunedNullifiers: 0,
            });
            return;
          }
          res.status(409).json({ error: 'CONFLICTING_SAME_EPOCH_DIRECTORY' });
          return;
        }
        if (this.activeDirectoryHash && dir.previousDirectorySha256 !== this.activeDirectoryHash) {
          res.status(409).json({ error: 'EPOCH_HASH_CHAIN_MISMATCH' });
          return;
        }
      }

      // Reject activation if directory attempts to admit a witness with a proven equivocation on record
      const slashedInDir = dir.members.find((m) => this.slashedPeers.has(m.peerId));
      if (slashedInDir) {
        res.status(403).json({
          error: 'SLASHED_WITNESS_IN_DIRECTORY',
          peerId: slashedInDir.peerId,
        });
        return;
      }

      const dirHash = computeEpochDirectoryHash(dir);
      await this.db.saveEpochDirectory(dir, dirHash);
      this.activeDirectory = dir;
      this.activeDirectoryHash = dirHash;

      const minRetained = Math.max(0, dir.epoch - dir.nullifierEpochRetention);
      const prunedNullifiers = await this.db.pruneExpiredNullifierEpochs(minRetained);

      res.status(201).json({
        activatedEpoch: dir.epoch,
        directoryHash: dirHash,
        memberCount: dir.members.length,
        quorumSize: dir.quorumSize,
        prunedNullifiers,
      });
    });

    app.get('/v1/witness/checkpoints', async (req: Request, res: Response) => {
      const epochParam = req.query.epoch;
      const epoch = epochParam !== undefined ? Number(epochParam) : undefined;
      const checkpoints = await this.db.listWitnessCheckpoints(
        Number.isFinite(epoch) ? epoch : undefined,
      );
      res.status(200).json({ peerId: this.config.peerId, checkpoints });
    });

    app.post('/v1/governance/equivocation', express.json({ limit: '128kb' }), async (req: Request, res: Response) => {
      const parsed = EquivocationProofSchema.safeParse(req.body);
      if (!parsed.success) {
        res.status(400).json({ error: 'INVALID_EQUIVOCATION_SCHEMA', details: parsed.error.issues });
        return;
      }
      const proof: EquivocationProof = parsed.data;
      const member = this.activeDirectory?.members.find((m) => m.peerId === proof.witnessPeerId);
      const expectedPub: HybridPublicKeys | null = member
        ? { ed25519PkHex: member.ed25519PkHex, mldsa65PkB64: member.mldsa65PkB64 }
        : proof.kind === 'CHECKPOINT_FORK'
          ? {
              ed25519PkHex: proof.first.ed25519PkHex,
              mldsa65PkB64: proof.first.mldsa65PkB64,
            }
          : {
              ed25519PkHex: proof.first.ed25519PkHex,
              mldsa65PkB64: proof.first.mldsa65PkB64,
            };

      const verification = verifyEquivocationProof(proof, expectedPub);
      if (!verification.valid) {
        res.status(400).json({ error: 'INVALID_EQUIVOCATION_PROOF', reason: verification.reason });
        return;
      }

      await this.db.recordEquivocationProof({
        proofHash: verification.proofHash,
        proof,
        reason: verification.reason,
      });
      this.slashedPeers.add(proof.witnessPeerId);
      this.equivocationCounter.inc();

      res.status(201).json({
        slashed: true,
        offendingPeerId: proof.witnessPeerId,
        proofHash: verification.proofHash,
        reason: verification.reason,
      });
    });

    // Public per-epoch issuance totals and supply auditability
    app.get('/v1/issuance', async (_req: Request, res: Response) => {
      try {
        const [epochs, latestRoot] = await Promise.all([
          this.db.listEpochIssuanceTotals(),
          this.db.getLatestSignedRoot(),
        ]);
        res.status(200).json({
          peerId: this.config.peerId,
          treeSize: this.merkleTree?.size ?? 0,
          merkleRoot: this.merkleTree?.getRootHex() ?? null,
          latestSignedRoot: latestRoot,
          epochs,
        });
      } catch (err) {
        this.logger.error({ err }, 'Failed to query issuance totals');
        res.status(500).json({ error: 'INTERNAL_ERROR' });
      }
    });

    // Signed Genesis / Mint Issuance Path
    app.post('/v1/issuance', express.json({ limit: '64kb' }), async (req: Request, res: Response) => {
      const parsed = IssuanceSchema.safeParse(req.body);
      if (!parsed.success) {
        res.status(400).json({ error: 'INVALID_ISSUANCE_SCHEMA', details: parsed.error.issues });
        return;
      }
      const rec: SignedIssuanceRecord = parsed.data;
      if (!this.isTrustedIssuer(rec.issuerPub)) {
        res.status(403).json({ error: 'UNTRUSTED_ISSUER' });
        return;
      }

      const amount = BigInt(rec.amount);
      if (amount <= 0n || amount > MAX_U64) {
        res.status(400).json({ error: 'ISSUANCE_AMOUNT_OUT_OF_U64_RANGE' });
        return;
      }

      const sigOk = verifyHybrid(issuanceSigningPayload(rec), rec.issuerSig, rec.issuerPub);
      if (!sigOk) {
        res.status(403).json({ error: 'INVALID_ISSUER_SIGNATURE' });
        return;
      }

      const expectedCommitment = normalizeFieldHex(
        await computeCommitment(amount, BigInt(rec.ownerPkHex), BigInt(rec.blindingHex)),
      );
      if (expectedCommitment !== normalizeFieldHex(rec.noteCommitmentHex)) {
        res.status(400).json({ error: 'ISSUANCE_COMMITMENT_MISMATCH' });
        return;
      }

      try {
        const outcome = await this.withTreeLock(async (tree) => {
          if (rec.leafIndex < tree.size) {
            const existing = await this.db.listNoteCommitments();
            const match = existing.find((c) => c.leafIndex === rec.leafIndex);
            if (match && match.noteCommitment === expectedCommitment) {
              return {
                leafIndex: rec.leafIndex,
                merkleRoot: tree.getRootHex(),
                treeSize: tree.size,
                idempotent: true,
              };
            }
            throw new Error(`LEAF_INDEX_CONFLICT: expected ${tree.size}, got ${rec.leafIndex}`);
          }
          if (rec.leafIndex !== tree.size) {
            throw new Error(`NON_SEQUENTIAL_LEAF_INDEX: expected ${tree.size}, got ${rec.leafIndex}`);
          }

          const appended = await tree.appendCommitment(BigInt(expectedCommitment));
          const merkleRootHex = normalizeFieldHex(appended.root);
          const leafHashHex = normalizeFieldHex(appended.leaf);
          const sig = this.signRootCheckpoint(rec.epoch, tree.size, merkleRootHex);

          await this.db.recordIssuanceAtomic({
            issuanceId: rec.issuanceId,
            epoch: rec.epoch,
            txKind: rec.txKind,
            amount: rec.amount,
            noteCommitment: expectedCommitment,
            leafHash: leafHashHex,
            leafIndex: rec.leafIndex,
            merkleRoot: merkleRootHex,
            witnessPeerId: this.config.peerId,
            sigEd25519: sig.ed25519Hex,
            sigMldsa65: sig.mldsa65B64,
          });
          await this.recordChainedCheckpoint(rec.epoch, merkleRootHex, expectedCommitment, tree.size);

          return {
            leafIndex: appended.leafIndex,
            merkleRoot: merkleRootHex,
            treeSize: tree.size,
            idempotent: false,
          };
        });

        res.status(outcome.idempotent ? 200 : 201).json(outcome);
      } catch (err) {
        const message = err instanceof Error ? err.message : 'ISSUANCE_FAILED';
        res.status(409).json({ error: message });
      }
    });

    app.get('/v1/tree/root', async (_req: Request, res: Response) => {
      const latest = await this.db.getLatestSignedRoot();
      res.status(200).json({
        peerId: this.config.peerId,
        treeSize: this.merkleTree?.size ?? 0,
        merkleRoot: this.merkleTree?.getRootHex() ?? null,
        signedCheckpoint: latest,
      });
    });

    app.get('/v1/tree/commitments', async (_req: Request, res: Response) => {
      const rows = await this.db.listNoteCommitments();
      res.status(200).json({
        treeSize: rows.length,
        merkleRoot: this.merkleTree?.getRootHex() ?? null,
        commitments: rows.map((r) => ({
          leafIndex: r.leafIndex,
          epoch: r.epoch,
          noteCommitment: r.noteCommitment,
          txKind: r.txKind,
        })),
      });
    });

    // Finalizes 8-of-11 Witness-attested output commitments into the Note Registry Merkle Tree
    app.post(
      '/v1/tree/commit-outputs',
      express.json({ limit: '256kb' }),
      async (req: Request, res: Response) => {
        const parsed = CommitOutputsSchema.safeParse(req.body);
        if (!parsed.success) {
          res.status(400).json({ error: 'INVALID_COMMIT_OUTPUTS_SCHEMA', details: parsed.error.issues });
          return;
        }
        const { epoch, publicSignals, attestations } = parsed.data;

        const dirCheck = await this.getDirectoryForSpendEpoch(epoch);
        if (!dirCheck.ok) {
          res.status(dirCheck.status).json({ error: dirCheck.error });
          return;
        }
        const activeMembers = dirCheck.directory.members.filter(
          (m) => !this.slashedPeers.has(m.peerId),
        );
        const nullifierPair: [string, string] = [
          normalizeFieldHex(publicSignals.nullifiers[0]),
          normalizeFieldHex(publicSignals.nullifiers[1]),
        ];
        const expectedQuorum = selectWitnessQuorumForEpoch(
          epoch,
          nullifierPair[0],
          activeMembers,
          dirCheck.directory.quorumSize,
        );
        const quorumMap = new Map(expectedQuorum.map((m) => [m.peerId, m]));
        const seenPeers = new Set<string>();
        const txBinding = normalizeFieldHex(publicSignals.txBinding);

        for (const att of attestations) {
          if (seenPeers.has(att.peerId)) continue;
          const peer = quorumMap.get(att.peerId);
          if (!peer) continue;
          if (
            peer.ed25519PkHex !== att.ed25519PkHex ||
            peer.mldsa65PkB64 !== att.mldsa65PkB64 ||
            normalizeFieldHex(att.txBinding) !== txBinding ||
            normalizeFieldHex(att.nullifiers[0]) !== nullifierPair[0] ||
            normalizeFieldHex(att.nullifiers[1]) !== nullifierPair[1]
          ) {
            continue;
          }
          const ok = verifyHybrid(
            attestationSigningPayload({
              peerId: att.peerId,
              nullifiers: att.nullifiers,
              proofSha256: att.proofSha256,
              txBinding: att.txBinding,
              issuedAt: att.issuedAt,
            }),
            att.sig,
            { ed25519PkHex: peer.ed25519PkHex, mldsa65PkB64: peer.mldsa65PkB64 },
          );
          if (ok) {
            seenPeers.add(att.peerId);
          }
        }

        if (seenPeers.size < dirCheck.directory.quorumSize) {
          res.status(403).json({
            error: 'INSUFFICIENT_QUORUM_ATTESTATIONS',
            verified: seenPeers.size,
            required: dirCheck.directory.quorumSize,
          });
          return;
        }

        const out0 = normalizeFieldHex(publicSignals.outputCommitments[0]);
        const out1 = normalizeFieldHex(publicSignals.outputCommitments[1]);

        const committed = await this.withTreeLock(async (tree) => {
          const existingRows = await this.db.listNoteCommitments();
          const already0 = existingRows.find((r) => r.txRef === txBinding && r.noteCommitment === out0);
          const already1 = existingRows.find((r) => r.txRef === txBinding && r.noteCommitment === out1);
          if (already0 && already1) {
            return {
              leafIndices: [already0.leafIndex, already1.leafIndex] as [number, number],
              merkleRoot: tree.getRootHex(),
              treeSize: tree.size,
            };
          }

          const app0 = await tree.appendCommitment(BigInt(out0));
          const app1 = await tree.appendCommitment(BigInt(out1));
          const newRootHex = normalizeFieldHex(app1.root);
          const sig = this.signRootCheckpoint(epoch, tree.size, newRootHex);

          const saved = await this.db.recordSpendOutputsAtomic({
            txBinding,
            epoch,
            leafIndex0: app0.leafIndex,
            leafIndex1: app1.leafIndex,
            outCommit0: out0,
            outCommit1: out1,
            leafHash0: normalizeFieldHex(await computeLeaf(BigInt(out0), app0.leafIndex)),
            leafHash1: normalizeFieldHex(await computeLeaf(BigInt(out1), app1.leafIndex)),
            merkleRoot: newRootHex,
            witnessPeerId: this.config.peerId,
            sigEd25519: sig.ed25519Hex,
            sigMldsa65: sig.mldsa65B64,
          });
          await this.recordChainedCheckpoint(epoch, newRootHex, txBinding, tree.size);

          return {
            leafIndices: [saved.leafIndex0, saved.leafIndex1] as [number, number],
            merkleRoot: saved.merkleRoot,
            treeSize: tree.size,
          };
        });

        res.status(200).json(committed);
      },
    );

    // Hardened Stateless 3-Hop Onion Relay: strictly 16,384 B binary cells,
    // per-hop PoW + replay defense, directory-only SSRF protection, timeouts, size caps,
    // and authenticated memory-bounded chunk reassembly.
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

          const prefix = extractOnionSlot0AuthPrefix(body);
          if (!prefix) {
            res.status(400).json({ error: 'INVALID_ONION_HEADER_VERSION' });
            return;
          }
          if (!verifyRelaySlotPoW(prefix.ephemPk, prefix.headerNonce, this.relayPowBits)) {
            res.status(429).json({ error: 'INVALID_RELAY_POW', requiredBits: this.relayPowBits });
            return;
          }
          const nowMs = Date.now();
          if (this.seenRelayEphemPks.has(prefix.ephemPkHex)) {
            res.status(409).json({ error: 'RELAY_PACKET_REPLAY' });
            return;
          }
          if (this.seenRelayEphemPks.size > 20_000) {
            const expiry = nowMs - 60_000;
            for (const [k, ts] of this.seenRelayEphemPks.entries()) {
              if (ts < expiry) this.seenRelayEphemPks.delete(k);
            }
          }
          this.seenRelayEphemPks.set(prefix.ephemPkHex, nowMs);

          const unwrapped = unwrapOnionLayer(
            new Uint8Array(body),
            this.config.keypair.x25519Sk,
            this.config.keypair.x25519Pk,
          );

          const policyOpts = {
            allowLoopback: this.allowLoopbackPeers,
            allowPrivateNetwork: this.allowPrivateNetworkPeers,
          };

          if (unwrapped.mode === 'relay') {
            this.relayCounter.inc({ mode: 'relay' });
            const allowedOrigin = await assertRelayTargetAllowed(
              unwrapped.nextHopUrl,
              this.activeDirectory,
              this.slashedPeers,
              policyOpts,
            );
            if (this.relayJitterMaxMs > 0) {
              await new Promise((r) => setTimeout(r, randomInt(0, this.relayJitterMaxMs + 1)));
            }
            const upstream = await fetchWithTimeoutAndCap(
              `${allowedOrigin}/v1/relay`,
              {
                method: 'POST',
                headers: {
                  'Content-Type': 'application/octet-stream',
                  'Content-Length': String(ONION_PACKET_SIZE),
                },
                body: Buffer.from(unwrapped.nextPacket),
              },
              {
                timeoutMs: this.relayTimeoutMs,
                maxResponseBytes: this.maxRelayResponseBytes,
              },
            );
            res.status(upstream.status).type(upstream.contentType).send(upstream.bodyText);
            return;
          }

          this.relayCounter.inc({ mode: 'terminal' });
          const payloadBuf = Buffer.from(unwrapped.payload);
          const frameType = payloadBuf[0];
          let envelopeBytes: Buffer | null = null;

          if (frameType === 0x03) {
            // Authenticated fixed-size dummy cover traffic cell terminated silently at Hop 3
            res.status(204).end();
            return;
          } else if (frameType === 0x01) {
            envelopeBytes = payloadBuf.subarray(1);
          } else if (frameType === 0x02 && payloadBuf.length >= CHUNK_FRAME_HEADER_SIZE) {
            this.pruneReassembly();
            const msgIdBuf = payloadBuf.subarray(1, 17);
            const msgId = msgIdBuf.toString('hex');
            const chunkIndex = payloadBuf[17]!;
            const totalChunks = payloadBuf[18]!;
            const msgSecret = payloadBuf.subarray(19, 51);
            const msgSha3Hex = payloadBuf.subarray(51, 83).toString('hex');
            const chunkData = payloadBuf.subarray(CHUNK_FRAME_HEADER_SIZE);

            if (totalChunks < 1 || totalChunks > 16 || chunkIndex >= totalChunks) {
              res.status(400).json({ error: 'INVALID_ONION_CHUNK_HEADER' });
              return;
            }
            const expectedId = Buffer.from(deriveChunkMsgId(msgSecret));
            if (!expectedId.equals(msgIdBuf)) {
              res.status(400).json({ error: 'INVALID_CHUNK_AUTH' });
              return;
            }
            const msgSecretHex = msgSecret.toString('hex');

            let entry = this.reassembly.get(msgId);
            if (!entry) {
              if (this.reassembly.size >= this.maxReassemblyEntries) {
                res.status(503).json({ error: 'REASSEMBLY_BUFFER_FULL' });
                return;
              }
              if (this.reassemblyBytes + chunkData.length > this.maxReassemblyTotalBytes) {
                res.status(503).json({ error: 'REASSEMBLY_MEMORY_LIMIT' });
                return;
              }
              entry = {
                totalChunks,
                msgSecretHex,
                msgSha3Hex,
                totalBytes: 0,
                chunks: new Map(),
                createdAtMs: Date.now(),
              };
              this.reassembly.set(msgId, entry);
            } else {
              if (
                entry.msgSecretHex !== msgSecretHex ||
                entry.msgSha3Hex !== msgSha3Hex ||
                entry.totalChunks !== totalChunks
              ) {
                res.status(400).json({ error: 'CHUNK_AUTH_MISMATCH' });
                return;
              }
            }

            const existingChunk = entry.chunks.get(chunkIndex);
            if (existingChunk) {
              if (!existingChunk.equals(chunkData)) {
                res.status(400).json({ error: 'CONFLICTING_ONION_CHUNK' });
                return;
              }
            } else {
              if (this.reassemblyBytes + chunkData.length > this.maxReassemblyTotalBytes) {
                res.status(503).json({ error: 'REASSEMBLY_MEMORY_LIMIT' });
                return;
              }
              const copy = Buffer.from(chunkData);
              entry.chunks.set(chunkIndex, copy);
              entry.totalBytes += copy.length;
              this.reassemblyBytes += copy.length;
            }

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
            this.reassemblyBytes = Math.max(0, this.reassemblyBytes - entry.totalBytes);
            envelopeBytes = Buffer.concat(ordered);

            if (sha3Hex(envelopeBytes) !== entry.msgSha3Hex) {
              res.status(400).json({ error: 'CHUNK_DIGEST_MISMATCH' });
              return;
            }
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
            envelope.path.includes('..') ||
            envelope.path.includes('//') ||
            envelope.path.includes('\\') ||
            envelope.path.includes('@') ||
            (envelope.method !== 'GET' && envelope.method !== 'POST')
          ) {
            res.status(400).json({ error: 'INVALID_TERMINAL_ENVELOPE' });
            return;
          }

          const allowedTargetOrigin = await assertRelayTargetAllowed(
            unwrapped.targetUrl,
            this.activeDirectory,
            this.slashedPeers,
            policyOpts,
          );
          if (this.relayJitterMaxMs > 0) {
            await new Promise((r) => setTimeout(r, randomInt(0, this.relayJitterMaxMs + 1)));
          }

          const targetResp = await fetchWithTimeoutAndCap(
            `${allowedTargetOrigin}${envelope.path}`,
            {
              method: envelope.method,
              headers: envelope.method === 'POST' ? { 'Content-Type': 'application/json' } : undefined,
              body: envelope.method === 'POST' ? JSON.stringify(envelope.body ?? {}) : undefined,
            },
            {
              timeoutMs: this.relayTimeoutMs,
              maxResponseBytes: this.maxRelayResponseBytes,
            },
          );
          res.status(targetResp.status).type(targetResp.contentType).send(targetResp.bodyText);
        } catch (err) {
          if (err instanceof RelaySecurityError) {
            res.status(err.status).json({ error: err.code });
            return;
          }
          this.logger.warn({ err }, 'Onion relay unwrap/forward rejected');
          res.status(400).json({ error: 'ONION_DECRYPT_OR_FORWARD_FAILED' });
        }
      },
    );

    // Two-Phase Witness Prepare Endpoint (Quorum self-check + ZK + PQ + Lease reservation)
    app.post(
      '/v1/witness/prepare',
      express.json({ limit: '256kb' }),
      async (req: Request, res: Response) => {
        const stopTimer = this.attestDuration.startTimer();
        try {
          const parsed = PrepareRequestSchema.safeParse(req.body);
          if (!parsed.success) {
            this.attestCounter.inc({ outcome: 'invalid_schema' });
            res.status(400).json({ error: 'INVALID_PREPARE_SCHEMA', details: parsed.error.issues });
            return;
          }
          const { epoch, leaseMs, proofBundle, spenderPub, spenderSig } = parsed.data;
          const dirCheck = await this.getDirectoryForSpendEpoch(epoch);
          if (!dirCheck.ok) {
            res.status(dirCheck.status).json({ error: dirCheck.error });
            return;
          }

          const nullifiers: [string, string] = [
            normalizeFieldHex(proofBundle.publicSignals.nullifiers[0]),
            normalizeFieldHex(proofBundle.publicSignals.nullifiers[1]),
          ];
          const qCheck = this.verifyQuorumMembership(epoch, nullifiers[0], dirCheck.directory);
          if (!qCheck.inQuorum) {
            res.status(403).json({
              error: 'NOT_IN_QUORUM',
              peerId: this.config.peerId,
              quorumPeerIds: qCheck.quorumPeerIds,
            });
            return;
          }

          const normalizedBundle: SpendProofBundle = {
            proofBase64: proofBundle.proofBase64,
            publicInputs: proofBundle.publicInputs.map((x) => normalizeFieldHex(x)),
            publicSignals: {
              merkleRoot: normalizeFieldHex(proofBundle.publicSignals.merkleRoot),
              nullifiers,
              outputCommitments: [
                normalizeFieldHex(proofBundle.publicSignals.outputCommitments[0]),
                normalizeFieldHex(proofBundle.publicSignals.outputCommitments[1]),
              ],
              feeCommitment: normalizeFieldHex(proofBundle.publicSignals.feeCommitment),
              authPkHash: normalizeFieldHex(proofBundle.publicSignals.authPkHash),
              txBinding: normalizeFieldHex(proofBundle.publicSignals.txBinding),
            },
            vkSha256: proofBundle.vkSha256,
          };

          const expectedAuthPkHash = computeAuthPkHash(spenderPub);
          if (normalizedBundle.publicSignals.authPkHash !== expectedAuthPkHash) {
            res.status(403).json({ error: 'AUTH_PK_HASH_MISMATCH' });
            return;
          }
          const expectedTxBinding = computeExpectedTxBinding({
            authPkHash: expectedAuthPkHash,
            merkleRoot: normalizedBundle.publicSignals.merkleRoot,
            outputCommitments: normalizedBundle.publicSignals.outputCommitments,
            feeCommitment: normalizedBundle.publicSignals.feeCommitment,
          });
          if (normalizedBundle.publicSignals.txBinding !== expectedTxBinding) {
            res.status(403).json({ error: 'TX_BINDING_MISMATCH' });
            return;
          }
          const recentRootOk = await this.db.isRecentSignedMerkleRoot(
            normalizedBundle.publicSignals.merkleRoot,
            64,
          );
          if (!recentRootOk) {
            res.status(403).json({ error: 'UNKNOWN_OR_STALE_MERKLE_ROOT' });
            return;
          }
          if (!verifyHybrid(spendStatementPayload(normalizedBundle.publicSignals), spenderSig, spenderPub)) {
            res.status(403).json({ error: 'INVALID_HYBRID_PQ_SIGNATURE' });
            return;
          }
          if (!(await verifySpendProof(normalizedBundle))) {
            res.status(403).json({ error: 'INVALID_ZK_PROOF' });
            return;
          }

          const proofSha256 = sha3Hex(Buffer.from(normalizedBundle.proofBase64, 'base64'));
          const expiresAt = new Date(Date.now() + (leaseMs ?? this.prepareLeaseMs)).toISOString();
          const voteBase = {
            peerId: this.config.peerId,
            epoch,
            nullifiers,
            proofSha256,
            txBinding: normalizedBundle.publicSignals.txBinding,
            expiresAt,
          };
          const voteSig = signHybrid(
            prepareVoteSigningPayload(voteBase),
            this.config.keypair.ed25519Sk,
            this.config.keypair.mldsa65Sk,
          );

          const prep = await this.db.prepareNullifiersAtomic({
            epoch,
            nullifiers,
            txBinding: normalizedBundle.publicSignals.txBinding,
            authPkHash: expectedAuthPkHash,
            proofSha256,
            expiresAt,
            prepareEd25519: voteSig.ed25519Hex,
            prepareMldsa65: voteSig.mldsa65B64,
          });

          if (!prep.ok) {
            this.attestCounter.inc({ outcome: 'double_spend' });
            res.status(409).json({
              error: prep.reason === 'DOUBLE_SPEND_RESERVED' ? 'ERR_DOUBLE_SPEND_RESERVED' : 'ERR_DOUBLE_SPEND',
            });
            return;
          }

          const prepareVote: PrepareVote = {
            ...voteBase,
            expiresAt: prep.expiresAt,
            ed25519PkHex: Buffer.from(this.config.keypair.ed25519Pk).toString('hex'),
            mldsa65PkB64: Buffer.from(this.config.keypair.mldsa65Pk).toString('base64'),
            sig: { ed25519Hex: prep.sigEd25519, mldsa65B64: prep.sigMldsa65 },
          };
          res.status(200).json({ state: prep.state, prepareVote });
        } catch (err) {
          this.attestCounter.inc({ outcome: 'error' });
          this.logger.error({ err }, 'Witness prepare failed');
          res.status(500).json({ error: 'INTERNAL_ERROR' });
        } finally {
          stopTimer();
        }
      },
    );

    // Two-Phase Witness Commit Endpoint (Requires quorum PrepareVotes; idempotent by txBinding)
    app.post(
      '/v1/witness/commit',
      express.json({ limit: '512kb' }),
      async (req: Request, res: Response) => {
        const stopTimer = this.attestDuration.startTimer();
        try {
          const parsed = CommitRequestSchema.safeParse(req.body);
          if (!parsed.success) {
            res.status(400).json({ error: 'INVALID_COMMIT_SCHEMA', details: parsed.error.issues });
            return;
          }
          const { epoch, proofBundle, spenderPub, spenderSig, prepareVotes } = parsed.data;
          const dirCheck = await this.getDirectoryForSpendEpoch(epoch);
          if (!dirCheck.ok) {
            res.status(dirCheck.status).json({ error: dirCheck.error });
            return;
          }

          const nullifiers: [string, string] = [
            normalizeFieldHex(proofBundle.publicSignals.nullifiers[0]),
            normalizeFieldHex(proofBundle.publicSignals.nullifiers[1]),
          ];
          const qCheck = this.verifyQuorumMembership(epoch, nullifiers[0], dirCheck.directory);
          if (!qCheck.inQuorum) {
            res.status(403).json({
              error: 'NOT_IN_QUORUM',
              peerId: this.config.peerId,
              quorumPeerIds: qCheck.quorumPeerIds,
            });
            return;
          }

          const txBinding = normalizeFieldHex(proofBundle.publicSignals.txBinding);
          const expectedAuthPkHash = computeAuthPkHash(spenderPub);
          if (normalizeFieldHex(proofBundle.publicSignals.authPkHash) !== expectedAuthPkHash) {
            res.status(403).json({ error: 'AUTH_PK_HASH_MISMATCH' });
            return;
          }

          const normalizedBundle: SpendProofBundle = {
            proofBase64: proofBundle.proofBase64,
            publicInputs: proofBundle.publicInputs.map((x) => normalizeFieldHex(x)),
            publicSignals: {
              merkleRoot: normalizeFieldHex(proofBundle.publicSignals.merkleRoot),
              nullifiers,
              outputCommitments: [
                normalizeFieldHex(proofBundle.publicSignals.outputCommitments[0]),
                normalizeFieldHex(proofBundle.publicSignals.outputCommitments[1]),
              ],
              feeCommitment: normalizeFieldHex(proofBundle.publicSignals.feeCommitment),
              authPkHash: expectedAuthPkHash,
              txBinding,
            },
            vkSha256: proofBundle.vkSha256,
          };

          if (!verifyHybrid(spendStatementPayload(normalizedBundle.publicSignals), spenderSig, spenderPub)) {
            res.status(403).json({ error: 'INVALID_HYBRID_PQ_SIGNATURE' });
            return;
          }
          if (!(await verifySpendProof(normalizedBundle))) {
            res.status(403).json({ error: 'INVALID_ZK_PROOF' });
            return;
          }

          const proofSha256 = sha3Hex(Buffer.from(normalizedBundle.proofBase64, 'base64'));
          const quorumSet = new Map(
            dirCheck.directory.members
              .filter((m) => qCheck.quorumPeerIds.includes(m.peerId))
              .map((m) => [m.peerId, m]),
          );
          const validVotes = new Set<string>();
          for (const v of prepareVotes) {
            if (validVotes.has(v.peerId)) continue;
            const member = quorumSet.get(v.peerId);
            if (!member) continue;
            if (
              v.epoch !== epoch ||
              normalizeFieldHex(v.txBinding) !== txBinding ||
              normalizeFieldHex(v.nullifiers[0]) !== nullifiers[0] ||
              normalizeFieldHex(v.nullifiers[1]) !== nullifiers[1] ||
              v.proofSha256 !== proofSha256 ||
              member.ed25519PkHex !== v.ed25519PkHex ||
              member.mldsa65PkB64 !== v.mldsa65PkB64
            ) {
              continue;
            }
            if (
              verifyHybrid(
                prepareVoteSigningPayload(v),
                v.sig,
                { ed25519PkHex: member.ed25519PkHex, mldsa65PkB64: member.mldsa65PkB64 },
              )
            ) {
              validVotes.add(v.peerId);
            }
          }

          if (validVotes.size < dirCheck.directory.quorumSize) {
            res.status(403).json({
              error: 'INSUFFICIENT_PREPARE_VOTES',
              verified: validVotes.size,
              required: dirCheck.directory.quorumSize,
            });
            return;
          }

          const issuedAt = new Date().toISOString();
          const attestationBody = {
            peerId: this.config.peerId,
            nullifiers,
            proofSha256,
            txBinding,
            issuedAt,
          };
          const witnessSig = signHybrid(
            attestationSigningPayload(attestationBody),
            this.config.keypair.ed25519Sk,
            this.config.keypair.mldsa65Sk,
          );

          const claim = await this.db.claimNullifiersAtomic({
            epoch,
            nullifiers,
            txBinding,
            proofSha256,
            issuedAtIso: issuedAt,
            attestationEd25519: witnessSig.ed25519Hex,
            attestationMldsa65: witnessSig.mldsa65B64,
          });
          if (!claim.ok) {
            this.attestCounter.inc({ outcome: 'double_spend' });
            res.status(409).json({ error: 'ERR_DOUBLE_SPEND' });
            return;
          }

          await this.recordChainedCheckpoint(
            epoch,
            normalizedBundle.publicSignals.merkleRoot,
            txBinding,
            this.merkleTree?.size ?? 0,
          );

          this.attestCounter.inc({ outcome: 'attested' });
          const receipt: WitnessAttestation = {
            ...attestationBody,
            issuedAt: claim.issuedAtIso || issuedAt,
            ed25519PkHex: Buffer.from(this.config.keypair.ed25519Pk).toString('hex'),
            mldsa65PkB64: Buffer.from(this.config.keypair.mldsa65Pk).toString('base64'),
            sig: {
              ed25519Hex: claim.attestationEd25519,
              mldsa65B64: claim.attestationMldsa65,
            },
          };
          res.status(200).json({ idempotent: Boolean(claim.idempotent), attestation: receipt });
        } catch (err) {
          this.attestCounter.inc({ outcome: 'error' });
          this.logger.error({ err }, 'Witness commit failed');
          res.status(500).json({ error: 'INTERNAL_ERROR' });
        } finally {
          stopTimer();
        }
      },
    );

    // Two-Phase Witness Abort Endpoint (Releases un-committed reservations without burning nullifiers)
    app.post(
      '/v1/witness/abort',
      express.json({ limit: '64kb' }),
      async (req: Request, res: Response) => {
        const parsed = AbortRequestSchema.safeParse(req.body);
        if (!parsed.success) {
          res.status(400).json({ error: 'INVALID_ABORT_SCHEMA', details: parsed.error.issues });
          return;
        }
        const { epoch, txBinding, spenderPub, spenderSig } = parsed.data;
        const ok = verifyHybrid(
          abortRequestSigningPayload({ epoch, txBinding }),
          spenderSig,
          spenderPub,
        );
        if (!ok) {
          res.status(403).json({ error: 'INVALID_ABORT_SIGNATURE' });
          return;
        }
        const authPkHash = computeAuthPkHash(spenderPub);
        const releasedRows = await this.db.abortNullifierReservations(
          normalizeFieldHex(txBinding),
          authPkHash,
        );
        res.status(200).json({ aborted: true, releasedRows });
      },
    );

    // Witness Attestation Endpoint (Quorum membership + authPkHash + Recent Signed Merkle Root + ZK + Hybrid PQ + SERIALIZABLE Nullifier DB)
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
          const spendEpoch =
            typeof (req.body as { epoch?: unknown }).epoch === 'number'
              ? (req.body as { epoch: number }).epoch
              : (this.activeDirectory?.epoch ?? 0);

          const dirCheck = await this.getDirectoryForSpendEpoch(spendEpoch);
          if (!dirCheck.ok) {
            res.status(dirCheck.status).json({ error: dirCheck.error });
            return;
          }

          const normalizedBundle: SpendProofBundle = {
            proofBase64: proofBundle.proofBase64,
            publicInputs: proofBundle.publicInputs.map((x) => normalizeFieldHex(x)),
            publicSignals: {
              merkleRoot: normalizeFieldHex(proofBundle.publicSignals.merkleRoot),
              nullifiers: [
                normalizeFieldHex(proofBundle.publicSignals.nullifiers[0]),
                normalizeFieldHex(proofBundle.publicSignals.nullifiers[1]),
              ],
              outputCommitments: [
                normalizeFieldHex(proofBundle.publicSignals.outputCommitments[0]),
                normalizeFieldHex(proofBundle.publicSignals.outputCommitments[1]),
              ],
              feeCommitment: normalizeFieldHex(proofBundle.publicSignals.feeCommitment),
              authPkHash: normalizeFieldHex(proofBundle.publicSignals.authPkHash),
              txBinding: normalizeFieldHex(proofBundle.publicSignals.txBinding),
            },
            vkSha256: proofBundle.vkSha256,
          };

          // 1. Verify authPkHash cryptographically matches spenderPub (bound into owner_pk inside circuit)
          const expectedAuthPkHash = computeAuthPkHash(spenderPub);
          if (normalizedBundle.publicSignals.authPkHash !== expectedAuthPkHash) {
            this.attestCounter.inc({ outcome: 'auth_pk_hash_mismatch' });
            res.status(403).json({ error: 'AUTH_PK_HASH_MISMATCH' });
            return;
          }

          // 2. Verify txBinding binds authPkHash, merkleRoot, outputs, and fee commitment
          const expectedTxBinding = computeExpectedTxBinding({
            authPkHash: expectedAuthPkHash,
            merkleRoot: normalizedBundle.publicSignals.merkleRoot,
            outputCommitments: normalizedBundle.publicSignals.outputCommitments,
            feeCommitment: normalizedBundle.publicSignals.feeCommitment,
          });
          if (normalizedBundle.publicSignals.txBinding !== expectedTxBinding) {
            this.attestCounter.inc({ outcome: 'tx_binding_mismatch' });
            res.status(403).json({ error: 'TX_BINDING_MISMATCH' });
            return;
          }

          // 3. Reject unknown or stale Merkle roots not in the recent signed root window
          const recentRootOk = await this.db.isRecentSignedMerkleRoot(
            normalizedBundle.publicSignals.merkleRoot,
            64,
          );
          if (!recentRootOk) {
            this.attestCounter.inc({ outcome: 'unknown_merkle_root' });
            res.status(403).json({ error: 'UNKNOWN_OR_STALE_MERKLE_ROOT' });
            return;
          }

          // 4. Verify Hybrid Ed25519 + ML-DSA-65 spender authorization signature
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

          // 5. Verify Noir UltraHonk proof against pinned deterministic VK
          const zkOk = await verifySpendProof(normalizedBundle);
          if (!zkOk) {
            this.attestCounter.inc({ outcome: 'invalid_zk_proof' });
            res.status(403).json({ error: 'INVALID_ZK_PROOF' });
            return;
          }

          // 6. Witness self-verifies deterministic quorum membership for (spendEpoch, nullifier0)
          const qCheck = this.verifyQuorumMembership(
            spendEpoch,
            normalizedBundle.publicSignals.nullifiers[0],
            dirCheck.directory,
          );
          if (!qCheck.inQuorum) {
            this.attestCounter.inc({ outcome: 'not_in_quorum' });
            res.status(403).json({
              error: 'NOT_IN_QUORUM',
              peerId: this.config.peerId,
              quorumPeerIds: qCheck.quorumPeerIds,
            });
            return;
          }

          // 7. Sign Witness attestation receipt BEFORE atomic PostgreSQL claim
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

          // 8. Atomic SERIALIZABLE INSERT ... ON CONFLICT DO NOTHING in PostgreSQL (idempotent by txBinding)
          const claim = await this.db.claimNullifiersAtomic({
            epoch: spendEpoch,
            nullifiers: normalizedBundle.publicSignals.nullifiers,
            txBinding: normalizedBundle.publicSignals.txBinding,
            proofSha256,
            issuedAtIso: issuedAt,
            attestationEd25519: witnessSig.ed25519Hex,
            attestationMldsa65: witnessSig.mldsa65B64,
          });

          if (!claim.ok) {
            this.attestCounter.inc({ outcome: 'double_spend' });
            res.status(409).json({ error: 'ERR_DOUBLE_SPEND' });
            return;
          }

          await this.recordChainedCheckpoint(
            spendEpoch,
            normalizedBundle.publicSignals.merkleRoot,
            normalizedBundle.publicSignals.txBinding,
            this.merkleTree?.size ?? 0,
          );

          this.attestCounter.inc({ outcome: 'attested' });
          const receipt: WitnessAttestation = {
            ...attestationBody,
            issuedAt: claim.issuedAtIso || issuedAt,
            ed25519PkHex: Buffer.from(this.config.keypair.ed25519Pk).toString('hex'),
            mldsa65PkB64: Buffer.from(this.config.keypair.mldsa65Pk).toString('base64'),
            sig: {
              ed25519Hex: claim.attestationEd25519,
              mldsa65B64: claim.attestationMldsa65,
            },
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
    const cutoff = Date.now() - this.reassemblyTtlMs;
    for (const [key, entry] of this.reassembly.entries()) {
      if (entry.createdAtMs < cutoff) {
        this.reassembly.delete(key);
        this.reassemblyBytes = Math.max(0, this.reassemblyBytes - entry.totalBytes);
      }
    }
    const replayCutoff = Date.now() - 60_000;
    for (const [k, ts] of this.seenRelayEphemPks.entries()) {
      if (ts < replayCutoff) {
        this.seenRelayEphemPks.delete(k);
      }
    }
  }

  async start(): Promise<string> {
    await this.db.migrate();
    const commitments = await this.db.listNoteCommitments();
    this.merkleTree = await Poseidon2MerkleTree.create(
      commitments.map((c) => BigInt(c.noteCommitment)),
    );
    this.slashedPeers = new Set(await this.db.listSlashedPeers());

    const storedDir = await this.db.getLatestEpochDirectory();
    if (storedDir) {
      this.activeDirectory = storedDir.directory;
      this.activeDirectoryHash = storedDir.directoryHash;
    } else if (
      this.config.initialEpochDirectory &&
      verifySignedEpochDirectory(
        this.config.initialEpochDirectory,
        this.trustedGovernanceKeys,
        this.governanceThreshold,
      )
    ) {
      const hash = computeEpochDirectoryHash(this.config.initialEpochDirectory);
      await this.db.saveEpochDirectory(this.config.initialEpochDirectory, hash);
      this.activeDirectory = this.config.initialEpochDirectory;
      this.activeDirectoryHash = hash;
    }

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
    this.logger.info(
      {
        endpoint: this.boundEndpoint,
        treeSize: this.merkleTree.size,
        activeEpoch: this.activeDirectory?.epoch ?? null,
      },
      'Nuverther node started',
    );
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

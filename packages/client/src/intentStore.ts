import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import type { SpendProofBundle } from '@nuverther/zk';
import type {
  HybridPublicKeys,
  HybridSignature,
  PrepareVote,
  WitnessAttestation,
} from '@nuverther/node';

export type SpendIntentStatus =
  | 'CREATED'
  | 'PREPARED'
  | 'COMMITTED'
  | 'OUTPUTS_COMMITTED'
  | 'ABORTED';

export interface SpendIntentThreadSpec {
  amount: string;
  recipientOwnerPk: string;
  blinding: string;
  memo?: string;
}

export interface SpendIntentShardPointer {
  peerId: string;
  endpoint: string;
  shardId: string;
  shareIndex: number;
  shareKeyHex: string;
}

export interface SpendIntentRecord {
  version: 1;
  txBinding: string;
  epoch: number;
  status: SpendIntentStatus;
  quorumPeerIds: string[];
  proofBundle: SpendProofBundle;
  spenderPub: HybridPublicKeys;
  spenderSig: HybridSignature;
  prepareVotes: PrepareVote[];
  attestations: WitnessAttestation[];
  outputSpecs?: [SpendIntentThreadSpec, SpendIntentThreadSpec];
  outputLeafIndices?: [number, number];
  newMerkleRoot?: string;
  threadKeyHex?: string;
  threadDigest?: string;
  shardPointers?: SpendIntentShardPointer[];
  lastError?: string;
  createdAt: string;
  updatedAt: string;
}

interface SerializedIntentJournal {
  version: 1;
  intents: Record<string, SpendIntentRecord>;
}

export class SpendIntentStore {
  private readonly filePath: string;
  private readonly intents = new Map<string, SpendIntentRecord>();

  constructor(filePath: string) {
    this.filePath = filePath;
    this.loadFromDisk();
  }

  private loadFromDisk(): void {
    if (!existsSync(this.filePath)) {
      return;
    }
    const raw = readFileSync(this.filePath, 'utf8').trim();
    if (!raw) return;
    const parsed = JSON.parse(raw) as SerializedIntentJournal;
    if (parsed && parsed.intents && typeof parsed.intents === 'object') {
      for (const [key, rec] of Object.entries(parsed.intents)) {
        this.intents.set(key, rec);
      }
    }
  }

  private flushToDisk(): void {
    const dir = dirname(this.filePath);
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true, mode: 0o700 });
    }
    const payload: SerializedIntentJournal = {
      version: 1,
      intents: Object.fromEntries(this.intents.entries()),
    };
    const tmpPath = `${this.filePath}.tmp.${process.pid}.${Date.now()}`;
    writeFileSync(tmpPath, JSON.stringify(payload, null, 2), {
      encoding: 'utf8',
      mode: 0o600,
    });
    renameSync(tmpPath, this.filePath);
  }

  upsert(record: SpendIntentRecord): SpendIntentRecord {
    const updated: SpendIntentRecord = {
      ...record,
      updatedAt: new Date().toISOString(),
    };
    this.intents.set(updated.txBinding, updated);
    this.flushToDisk();
    return updated;
  }

  get(txBinding: string): SpendIntentRecord | undefined {
    return this.intents.get(txBinding);
  }

  list(): SpendIntentRecord[] {
    return [...this.intents.values()].sort((a, b) => a.createdAt.localeCompare(b.createdAt));
  }

  listIncomplete(): SpendIntentRecord[] {
    return this.list().filter(
      (rec) => rec.status !== 'OUTPUTS_COMMITTED' && rec.status !== 'ABORTED',
    );
  }
}

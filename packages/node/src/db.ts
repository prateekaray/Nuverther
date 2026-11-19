import { Pool } from 'pg';
import type {
  ChainedWitnessCheckpoint,
  EquivocationProof,
  SignedEpochDirectory,
  SignedPeerRecord,
} from './crypto.ts';

export interface SpentNullifierRecord {
  nullifier: string;
  epoch: number;
  txBinding: string;
  proofSha256: string;
  attestationEd25519: string;
  attestationMldsa65: string;
  spentAt: string;
}

export interface BlindShardRecord {
  shardId: string;
  threadDigest: string;
  shareIndex: number;
  nonceHex: string;
  ciphertextB64: string;
  macTagHex: string;
  createdAt: string;
}

export interface NoteCommitmentRow {
  leafIndex: number;
  epoch: number;
  noteCommitment: string;
  leafHash: string;
  txKind: string;
  txRef: string;
  createdAt: string;
}

export interface EpochIssuanceTotalRow {
  epoch: number;
  genesisTotal: string;
  mintTotal: string;
  totalIssued: string;
  issuanceCount: number;
  updatedAt: string;
}

export interface SignedMerkleRootRow {
  id: number;
  epoch: number;
  treeSize: number;
  merkleRoot: string;
  witnessPeerId: string;
  sigEd25519: string;
  sigMldsa65: string;
  createdAt: string;
}

export type ClaimNullifierResult =
  | {
      ok: true;
      idempotent?: boolean;
      issuedAtIso: string;
      attestationEd25519: string;
      attestationMldsa65: string;
    }
  | { ok: false; reason: 'DOUBLE_SPEND' };

export type PrepareNullifierResult =
  | {
      ok: true;
      state: 'PREPARED' | 'ALREADY_COMMITTED';
      sigEd25519: string;
      sigMldsa65: string;
      expiresAt: string;
    }
  | { ok: false; reason: 'DOUBLE_SPEND' | 'DOUBLE_SPEND_RESERVED' };

function sanitizeIdentifier(name: string): string {
  if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(name)) {
    throw new Error(`Invalid PostgreSQL schema identifier: ${name}`);
  }
  return name;
}

export class NuvertherDatabase {
  public readonly pool: Pool;
  public readonly schema: string;

  constructor(databaseUrl: string, schema = 'public') {
    this.schema = sanitizeIdentifier(schema);
    this.pool = new Pool({
      connectionString: databaseUrl,
      max: 25,
      idleTimeoutMillis: 30_000,
      connectionTimeoutMillis: 10_000,
    });
  }

  private q(table: string): string {
    return `"${this.schema}"."${table}"`;
  }

  async migrate(): Promise<void> {
    const client = await this.pool.connect();
    try {
      if (this.schema !== 'public') {
        await client.query(`CREATE SCHEMA IF NOT EXISTS "${this.schema}"`);
      }

      await client.query(`
        CREATE TABLE IF NOT EXISTS ${this.q('spent_nullifiers')} (
          nullifier TEXT PRIMARY KEY,
          epoch INTEGER NOT NULL DEFAULT 0,
          tx_binding TEXT NOT NULL,
          proof_sha256 TEXT NOT NULL,
          issued_at_iso TEXT NOT NULL DEFAULT '',
          attestation_ed25519 TEXT NOT NULL,
          attestation_mldsa65 TEXT NOT NULL,
          spent_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
      `);

      await client.query(`
        ALTER TABLE ${this.q('spent_nullifiers')}
        ADD COLUMN IF NOT EXISTS epoch INTEGER NOT NULL DEFAULT 0
      `);

      await client.query(`
        ALTER TABLE ${this.q('spent_nullifiers')}
        ADD COLUMN IF NOT EXISTS issued_at_iso TEXT NOT NULL DEFAULT ''
      `);

      await client.query(`
        CREATE INDEX IF NOT EXISTS idx_spent_nullifiers_epoch_${this.schema}
        ON ${this.q('spent_nullifiers')} (epoch)
      `);

      await client.query(`
        CREATE TABLE IF NOT EXISTS ${this.q('nullifier_reservations')} (
          nullifier TEXT PRIMARY KEY,
          epoch INTEGER NOT NULL,
          tx_binding TEXT NOT NULL,
          auth_pk_hash TEXT NOT NULL,
          proof_sha256 TEXT NOT NULL,
          expires_at TIMESTAMPTZ NOT NULL,
          expires_at_iso TEXT NOT NULL,
          prepare_ed25519 TEXT NOT NULL,
          prepare_mldsa65 TEXT NOT NULL,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
      `);

      await client.query(`
        CREATE TABLE IF NOT EXISTS ${this.q('blind_shards')} (
          shard_id TEXT PRIMARY KEY,
          thread_digest TEXT NOT NULL,
          share_index SMALLINT NOT NULL CHECK (share_index BETWEEN 1 AND 3),
          nonce_hex TEXT NOT NULL,
          ciphertext_b64 TEXT NOT NULL,
          mac_tag_hex TEXT NOT NULL,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
      `);

      await client.query(`
        CREATE TABLE IF NOT EXISTS ${this.q('witness_peers')} (
          peer_id TEXT PRIMARY KEY,
          endpoint TEXT NOT NULL,
          ed25519_pk_hex TEXT NOT NULL,
          mldsa65_pk_b64 TEXT NOT NULL,
          x25519_pk_hex TEXT NOT NULL,
          hashcash_nonce TEXT NOT NULL,
          hashcash_bits INTEGER NOT NULL,
          self_sig_ed25519 TEXT NOT NULL,
          self_sig_mldsa65 TEXT NOT NULL,
          registered_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
      `);

      await client.query(`
        CREATE TABLE IF NOT EXISTS ${this.q('epoch_directories')} (
          epoch INTEGER PRIMARY KEY,
          directory_hash TEXT NOT NULL,
          directory_json TEXT NOT NULL,
          activated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
      `);

      await client.query(`
        CREATE TABLE IF NOT EXISTS ${this.q('witness_checkpoints')} (
          epoch INTEGER NOT NULL,
          seq INTEGER NOT NULL,
          prev_hash TEXT NOT NULL,
          state_root TEXT NOT NULL,
          tx_binding TEXT NOT NULL,
          tree_size INTEGER NOT NULL,
          checkpoint_hash TEXT NOT NULL,
          witness_peer_id TEXT NOT NULL,
          ed25519_pk_hex TEXT NOT NULL,
          mldsa65_pk_b64 TEXT NOT NULL,
          sig_ed25519 TEXT NOT NULL,
          sig_mldsa65 TEXT NOT NULL,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          PRIMARY KEY (epoch, seq)
        )
      `);

      await client.query(`
        CREATE TABLE IF NOT EXISTS ${this.q('equivocation_proofs')} (
          proof_hash TEXT PRIMARY KEY,
          witness_peer_id TEXT NOT NULL,
          kind TEXT NOT NULL,
          proof_json TEXT NOT NULL,
          reason TEXT NOT NULL,
          recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
      `);

      await client.query(`
        CREATE TABLE IF NOT EXISTS ${this.q('note_commitments')} (
          leaf_index INTEGER PRIMARY KEY,
          epoch INTEGER NOT NULL,
          note_commitment TEXT NOT NULL UNIQUE,
          leaf_hash TEXT NOT NULL,
          tx_kind TEXT NOT NULL CHECK (tx_kind IN ('genesis', 'mint', 'spend')),
          tx_ref TEXT NOT NULL,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
      `);

      await client.query(`
        CREATE TABLE IF NOT EXISTS ${this.q('merkle_roots')} (
          id SERIAL PRIMARY KEY,
          epoch INTEGER NOT NULL,
          tree_size INTEGER NOT NULL,
          merkle_root TEXT NOT NULL,
          witness_peer_id TEXT NOT NULL,
          sig_ed25519 TEXT NOT NULL,
          sig_mldsa65 TEXT NOT NULL,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          UNIQUE (epoch, tree_size, merkle_root)
        )
      `);

      await client.query(`
        CREATE TABLE IF NOT EXISTS ${this.q('epoch_issuance_totals')} (
          epoch INTEGER PRIMARY KEY,
          genesis_total NUMERIC(39, 0) NOT NULL DEFAULT 0,
          mint_total NUMERIC(39, 0) NOT NULL DEFAULT 0,
          issuance_count INTEGER NOT NULL DEFAULT 0,
          updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
      `);

      await client.query(`
        CREATE TABLE IF NOT EXISTS ${this.q('committed_tx_outputs')} (
          tx_binding TEXT PRIMARY KEY,
          epoch INTEGER NOT NULL,
          leaf_index_0 INTEGER NOT NULL,
          leaf_index_1 INTEGER NOT NULL,
          out_commit_0 TEXT NOT NULL,
          out_commit_1 TEXT NOT NULL,
          merkle_root TEXT NOT NULL,
          committed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
      `);
    } finally {
      client.release();
    }
  }

  async ping(): Promise<boolean> {
    try {
      const res = await this.pool.query('SELECT 1 AS ok');
      return res.rows[0]?.ok === 1;
    } catch {
      return false;
    }
  }

  /**
   * Two-phase Prepare step: atomically reserves nullifiers in PostgreSQL (SERIALIZABLE)
   * with a lease TTL and idempotency keyed by tx_binding so failed/crashed spends can recover.
   */
  async prepareNullifiersAtomic(params: {
    epoch: number;
    nullifiers: [string, string];
    txBinding: string;
    authPkHash: string;
    proofSha256: string;
    expiresAt: string;
    prepareEd25519: string;
    prepareMldsa65: string;
  }): Promise<PrepareNullifierResult> {
    const [n0, n1] = params.nullifiers;
    if (n0 === n1) {
      return { ok: false, reason: 'DOUBLE_SPEND' };
    }

    const client = await this.pool.connect();
    try {
      await client.query('BEGIN ISOLATION LEVEL SERIALIZABLE');

      // 1. Check permanent spent nullifiers
      const spentRes = await client.query<{
        nullifier: string;
        tx_binding: string;
        issued_at_iso: string;
        attestation_ed25519: string;
        attestation_mldsa65: string;
      }>(
        `SELECT nullifier, tx_binding, issued_at_iso, attestation_ed25519, attestation_mldsa65
         FROM ${this.q('spent_nullifiers')} WHERE nullifier IN ($1, $2)`,
        [n0, n1],
      );
      if (spentRes.rows.length > 0) {
        const allSameTx =
          spentRes.rows.length === 2 &&
          spentRes.rows.every((r) => r.tx_binding === params.txBinding);
        if (allSameTx) {
          await client.query('COMMIT');
          return {
            ok: true,
            state: 'ALREADY_COMMITTED',
            sigEd25519: spentRes.rows[0]!.attestation_ed25519,
            sigMldsa65: spentRes.rows[0]!.attestation_mldsa65,
            expiresAt: spentRes.rows[0]!.issued_at_iso || params.expiresAt,
          };
        }
        await client.query('ROLLBACK');
        return { ok: false, reason: 'DOUBLE_SPEND' };
      }

      // 2. Evict expired leases before checking active reservations
      await client.query(
        `DELETE FROM ${this.q('nullifier_reservations')} WHERE expires_at < NOW()`,
      );

      // 3. Check existing non-expired reservations
      const resvRes = await client.query<{
        nullifier: string;
        tx_binding: string;
        prepare_ed25519: string;
        prepare_mldsa65: string;
        expires_at_iso: string;
      }>(
        `SELECT nullifier, tx_binding, prepare_ed25519, prepare_mldsa65, expires_at_iso
         FROM ${this.q('nullifier_reservations')} WHERE nullifier IN ($1, $2)`,
        [n0, n1],
      );

      if (resvRes.rows.length > 0) {
        const allSameTx =
          resvRes.rows.length === 2 &&
          resvRes.rows.every((r) => r.tx_binding === params.txBinding);
        if (allSameTx) {
          await client.query('COMMIT');
          return {
            ok: true,
            state: 'PREPARED',
            sigEd25519: resvRes.rows[0]!.prepare_ed25519,
            sigMldsa65: resvRes.rows[0]!.prepare_mldsa65,
            expiresAt: resvRes.rows[0]!.expires_at_iso,
          };
        }
        await client.query('ROLLBACK');
        return { ok: false, reason: 'DOUBLE_SPEND_RESERVED' };
      }

      const insertRes = await client.query<{ nullifier: string }>(
        `INSERT INTO ${this.q('nullifier_reservations')} (
           nullifier, epoch, tx_binding, auth_pk_hash, proof_sha256, expires_at, expires_at_iso,
           prepare_ed25519, prepare_mldsa65
         )
         VALUES
           ($1, $3, $4, $5, $6, $7::timestamptz, $7, $8, $9),
           ($2, $3, $4, $5, $6, $7::timestamptz, $7, $8, $9)
         ON CONFLICT (nullifier) DO NOTHING
         RETURNING nullifier`,
        [
          n0,
          n1,
          params.epoch,
          params.txBinding,
          params.authPkHash,
          params.proofSha256,
          params.expiresAt,
          params.prepareEd25519,
          params.prepareMldsa65,
        ],
      );

      if (insertRes.rowCount !== 2) {
        await client.query('ROLLBACK');
        return { ok: false, reason: 'DOUBLE_SPEND_RESERVED' };
      }

      await client.query('COMMIT');
      return {
        ok: true,
        state: 'PREPARED',
        sigEd25519: params.prepareEd25519,
        sigMldsa65: params.prepareMldsa65,
        expiresAt: params.expiresAt,
      };
    } catch (err: unknown) {
      try {
        await client.query('ROLLBACK');
      } catch {
        // ignore rollback error
      }
      const pgCode =
        typeof err === 'object' && err !== null && 'code' in err
          ? String((err as { code?: unknown }).code)
          : '';
      if (pgCode === '40001' || pgCode === '23505') {
        return { ok: false, reason: 'DOUBLE_SPEND_RESERVED' };
      }
      throw err;
    } finally {
      client.release();
    }
  }

  /**
   * Two-phase Commit / Single-shot atomic nullifier claim (idempotent per tx_binding).
   */
  async claimNullifiersAtomic(params: {
    epoch?: number;
    nullifiers: [string, string];
    txBinding: string;
    proofSha256: string;
    issuedAtIso?: string;
    attestationEd25519: string;
    attestationMldsa65: string;
  }): Promise<ClaimNullifierResult> {
    const [n0, n1] = params.nullifiers;
    if (n0 === n1) {
      return { ok: false, reason: 'DOUBLE_SPEND' };
    }
    const issuedAtIso = params.issuedAtIso ?? new Date().toISOString();

    const client = await this.pool.connect();
    try {
      await client.query('BEGIN ISOLATION LEVEL SERIALIZABLE');

      // Check existing spent nullifiers for idempotency or conflict
      const existing = await client.query<{
        nullifier: string;
        tx_binding: string;
        issued_at_iso: string;
        attestation_ed25519: string;
        attestation_mldsa65: string;
      }>(
        `SELECT nullifier, tx_binding, issued_at_iso, attestation_ed25519, attestation_mldsa65
         FROM ${this.q('spent_nullifiers')} WHERE nullifier IN ($1, $2)`,
        [n0, n1],
      );
      if (existing.rows.length > 0) {
        if (existing.rows.length === 2 && existing.rows.every((r) => r.tx_binding === params.txBinding)) {
          await client.query('COMMIT');
          return {
            ok: true,
            idempotent: true,
            issuedAtIso: existing.rows[0]!.issued_at_iso,
            attestationEd25519: existing.rows[0]!.attestation_ed25519,
            attestationMldsa65: existing.rows[0]!.attestation_mldsa65,
          };
        }
        await client.query('ROLLBACK');
        return { ok: false, reason: 'DOUBLE_SPEND' };
      }

      // Evict expired reservations and ensure active reservation (if any) belongs to this txBinding
      await client.query(
        `DELETE FROM ${this.q('nullifier_reservations')} WHERE expires_at < NOW()`,
      );
      const resvRes = await client.query<{ tx_binding: string }>(
        `SELECT tx_binding FROM ${this.q('nullifier_reservations')} WHERE nullifier IN ($1, $2)`,
        [n0, n1],
      );
      if (resvRes.rows.some((r) => r.tx_binding !== params.txBinding)) {
        await client.query('ROLLBACK');
        return { ok: false, reason: 'DOUBLE_SPEND' };
      }

      const insertSql = `
        INSERT INTO ${this.q('spent_nullifiers')} (
          nullifier,
          epoch,
          tx_binding,
          proof_sha256,
          issued_at_iso,
          attestation_ed25519,
          attestation_mldsa65
        )
        VALUES
          ($1, $7, $3, $4, $8, $5, $6),
          ($2, $7, $3, $4, $8, $5, $6)
        ON CONFLICT (nullifier) DO NOTHING
        RETURNING nullifier
      `;
      const result = await client.query<{ nullifier: string }>(insertSql, [
        n0,
        n1,
        params.txBinding,
        params.proofSha256,
        params.attestationEd25519,
        params.attestationMldsa65,
        params.epoch ?? 0,
        issuedAtIso,
      ]);

      if (result.rowCount !== 2) {
        await client.query('ROLLBACK');
        return { ok: false, reason: 'DOUBLE_SPEND' };
      }

      await client.query(
        `DELETE FROM ${this.q('nullifier_reservations')} WHERE tx_binding = $1`,
        [params.txBinding],
      );

      await client.query('COMMIT');
      return {
        ok: true,
        idempotent: false,
        issuedAtIso,
        attestationEd25519: params.attestationEd25519,
        attestationMldsa65: params.attestationMldsa65,
      };
    } catch (err: unknown) {
      try {
        await client.query('ROLLBACK');
      } catch {
        // ignore rollback error after failed transaction
      }
      const pgCode =
        typeof err === 'object' && err !== null && 'code' in err
          ? String((err as { code?: unknown }).code)
          : '';
      if (pgCode === '40001' || pgCode === '23505') {
        return { ok: false, reason: 'DOUBLE_SPEND' };
      }
      throw err;
    } finally {
      client.release();
    }
  }

  async abortNullifierReservations(txBinding: string, authPkHash: string): Promise<number> {
    const res = await this.pool.query(
      `DELETE FROM ${this.q('nullifier_reservations')}
       WHERE tx_binding = $1 AND auth_pk_hash = $2`,
      [txBinding, authPkHash],
    );
    return res.rowCount ?? 0;
  }

  async saveEpochDirectory(directory: SignedEpochDirectory, directoryHash: string): Promise<void> {
    await this.pool.query(
      `INSERT INTO ${this.q('epoch_directories')} (epoch, directory_hash, directory_json)
       VALUES ($1, $2, $3)
       ON CONFLICT (epoch) DO UPDATE SET
         directory_hash = EXCLUDED.directory_hash,
         directory_json = EXCLUDED.directory_json,
         activated_at = NOW()`,
      [directory.epoch, directoryHash, JSON.stringify(directory)],
    );
  }

  async getLatestEpochDirectory(): Promise<{ directory: SignedEpochDirectory; directoryHash: string } | null> {
    const res = await this.pool.query<{ directory_hash: string; directory_json: string }>(
      `SELECT directory_hash, directory_json FROM ${this.q('epoch_directories')} ORDER BY epoch DESC LIMIT 1`,
    );
    const row = res.rows[0];
    if (!row) return null;
    return {
      directory: JSON.parse(row.directory_json) as SignedEpochDirectory,
      directoryHash: row.directory_hash,
    };
  }

  async getEpochDirectory(epoch: number): Promise<{ directory: SignedEpochDirectory; directoryHash: string } | null> {
    const res = await this.pool.query<{ directory_hash: string; directory_json: string }>(
      `SELECT directory_hash, directory_json FROM ${this.q('epoch_directories')} WHERE epoch = $1`,
      [epoch],
    );
    const row = res.rows[0];
    if (!row) return null;
    return {
      directory: JSON.parse(row.directory_json) as SignedEpochDirectory,
      directoryHash: row.directory_hash,
    };
  }

  async pruneExpiredNullifierEpochs(minRetainedEpoch: number): Promise<number> {
    const res = await this.pool.query(
      `DELETE FROM ${this.q('spent_nullifiers')} WHERE epoch < $1`,
      [minRetainedEpoch],
    );
    await this.pool.query(
      `DELETE FROM ${this.q('nullifier_reservations')} WHERE expires_at < NOW() OR epoch < $1`,
      [minRetainedEpoch],
    );
    return res.rowCount ?? 0;
  }

  async getLastCheckpoint(epoch: number): Promise<{ seq: number; checkpointHash: string } | null> {
    const res = await this.pool.query<{ seq: number; checkpoint_hash: string }>(
      `SELECT seq, checkpoint_hash FROM ${this.q('witness_checkpoints')}
       WHERE epoch = $1 ORDER BY seq DESC LIMIT 1`,
      [epoch],
    );
    const row = res.rows[0];
    return row ? { seq: row.seq, checkpointHash: row.checkpoint_hash } : null;
  }

  async appendWitnessCheckpoint(cp: ChainedWitnessCheckpoint): Promise<void> {
    await this.pool.query(
      `INSERT INTO ${this.q('witness_checkpoints')} (
         epoch, seq, prev_hash, state_root, tx_binding, tree_size, checkpoint_hash,
         witness_peer_id, ed25519_pk_hex, mldsa65_pk_b64, sig_ed25519, sig_mldsa65
       )
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
       ON CONFLICT (epoch, seq) DO NOTHING`,
      [
        cp.epoch,
        cp.seq,
        cp.prevHash,
        cp.stateRoot,
        cp.txBinding,
        cp.treeSize,
        cp.checkpointHash,
        cp.witnessPeerId,
        cp.ed25519PkHex,
        cp.mldsa65PkB64,
        cp.sig.ed25519Hex,
        cp.sig.mldsa65B64,
      ],
    );
  }

  async listWitnessCheckpoints(epoch?: number): Promise<ChainedWitnessCheckpoint[]> {
    const res = await this.pool.query<{
      epoch: number;
      seq: number;
      prev_hash: string;
      state_root: string;
      tx_binding: string;
      tree_size: number;
      checkpoint_hash: string;
      witness_peer_id: string;
      ed25519_pk_hex: string;
      mldsa65_pk_b64: string;
      sig_ed25519: string;
      sig_mldsa65: string;
      created_at: Date;
    }>(
      epoch !== undefined
        ? `SELECT * FROM ${this.q('witness_checkpoints')} WHERE epoch = $1 ORDER BY seq ASC`
        : `SELECT * FROM ${this.q('witness_checkpoints')} ORDER BY epoch ASC, seq ASC`,
      epoch !== undefined ? [epoch] : [],
    );
    return res.rows.map((r) => ({
      epoch: r.epoch,
      seq: r.seq,
      prevHash: r.prev_hash,
      stateRoot: r.state_root,
      txBinding: r.tx_binding,
      treeSize: r.tree_size,
      checkpointHash: r.checkpoint_hash,
      witnessPeerId: r.witness_peer_id,
      ed25519PkHex: r.ed25519_pk_hex,
      mldsa65PkB64: r.mldsa65_pk_b64,
      sig: {
        ed25519Hex: r.sig_ed25519,
        mldsa65B64: r.sig_mldsa65,
      },
      createdAt: r.created_at.toISOString(),
    }));
  }

  async recordEquivocationProof(params: {
    proofHash: string;
    proof: EquivocationProof;
    reason: string;
  }): Promise<void> {
    await this.pool.query(
      `INSERT INTO ${this.q('equivocation_proofs')} (
         proof_hash, witness_peer_id, kind, proof_json, reason
       )
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (proof_hash) DO NOTHING`,
      [
        params.proofHash,
        params.proof.witnessPeerId,
        params.proof.kind,
        JSON.stringify(params.proof),
        params.reason,
      ],
    );
  }

  async listSlashedPeers(): Promise<string[]> {
    const res = await this.pool.query<{ witness_peer_id: string }>(
      `SELECT DISTINCT witness_peer_id FROM ${this.q('equivocation_proofs')}`,
    );
    return res.rows.map((r) => r.witness_peer_id);
  }

  async listEquivocationProofs(): Promise<Array<{ proofHash: string; witnessPeerId: string; kind: string; reason: string; recordedAt: string }>> {
    const res = await this.pool.query<{
      proof_hash: string;
      witness_peer_id: string;
      kind: string;
      reason: string;
      recorded_at: Date;
    }>(`SELECT proof_hash, witness_peer_id, kind, reason, recorded_at FROM ${this.q('equivocation_proofs')} ORDER BY recorded_at DESC`);
    return res.rows.map((r) => ({
      proofHash: r.proof_hash,
      witnessPeerId: r.witness_peer_id,
      kind: r.kind,
      reason: r.reason,
      recordedAt: r.recorded_at.toISOString(),
    }));
  }

  async listNoteCommitments(): Promise<NoteCommitmentRow[]> {
    const res = await this.pool.query<{
      leaf_index: number;
      epoch: number;
      note_commitment: string;
      leaf_hash: string;
      tx_kind: string;
      tx_ref: string;
      created_at: Date;
    }>(
      `SELECT leaf_index, epoch, note_commitment, leaf_hash, tx_kind, tx_ref, created_at
       FROM ${this.q('note_commitments')} ORDER BY leaf_index ASC`,
    );
    return res.rows.map((r) => ({
      leafIndex: r.leaf_index,
      epoch: r.epoch,
      noteCommitment: r.note_commitment,
      leafHash: r.leaf_hash,
      txKind: r.tx_kind,
      txRef: r.tx_ref,
      createdAt: r.created_at.toISOString(),
    }));
  }

  async recordIssuanceAtomic(params: {
    issuanceId: string;
    epoch: number;
    txKind: 'genesis' | 'mint';
    amount: string;
    noteCommitment: string;
    leafHash: string;
    leafIndex: number;
    merkleRoot: string;
    witnessPeerId: string;
    sigEd25519: string;
    sigMldsa65: string;
  }): Promise<{ inserted: boolean }> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN ISOLATION LEVEL SERIALIZABLE');

      // Check idempotency if exact issuance already persisted
      const existing = await client.query<{ note_commitment: string }>(
        `SELECT note_commitment FROM ${this.q('note_commitments')} WHERE leaf_index = $1`,
        [params.leafIndex],
      );
      if (existing.rows[0]) {
        if (existing.rows[0].note_commitment === params.noteCommitment) {
          await client.query('COMMIT');
          return { inserted: false };
        }
        throw new Error(`Leaf index ${params.leafIndex} conflict during issuance`);
      }

      await client.query(
        `INSERT INTO ${this.q('note_commitments')}
           (leaf_index, epoch, note_commitment, leaf_hash, tx_kind, tx_ref)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [
          params.leafIndex,
          params.epoch,
          params.noteCommitment,
          params.leafHash,
          params.txKind,
          params.issuanceId,
        ],
      );

      const genesisDelta = params.txKind === 'genesis' ? params.amount : '0';
      const mintDelta = params.txKind === 'mint' ? params.amount : '0';
      await client.query(
        `INSERT INTO ${this.q('epoch_issuance_totals')} (epoch, genesis_total, mint_total, issuance_count)
         VALUES ($1, $2::numeric, $3::numeric, 1)
         ON CONFLICT (epoch) DO UPDATE SET
           genesis_total = ${this.q('epoch_issuance_totals')}.genesis_total + $2::numeric,
           mint_total = ${this.q('epoch_issuance_totals')}.mint_total + $3::numeric,
           issuance_count = ${this.q('epoch_issuance_totals')}.issuance_count + 1,
           updated_at = NOW()`,
        [params.epoch, genesisDelta, mintDelta],
      );

      await client.query(
        `INSERT INTO ${this.q('merkle_roots')}
           (epoch, tree_size, merkle_root, witness_peer_id, sig_ed25519, sig_mldsa65)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (epoch, tree_size, merkle_root) DO NOTHING`,
        [
          params.epoch,
          params.leafIndex + 1,
          params.merkleRoot,
          params.witnessPeerId,
          params.sigEd25519,
          params.sigMldsa65,
        ],
      );

      await client.query('COMMIT');
      return { inserted: true };
    } catch (err) {
      try {
        await client.query('ROLLBACK');
      } catch {
        // ignore
      }
      throw err;
    } finally {
      client.release();
    }
  }

  async recordSpendOutputsAtomic(params: {
    txBinding: string;
    epoch: number;
    leafIndex0: number;
    leafIndex1: number;
    outCommit0: string;
    outCommit1: string;
    leafHash0: string;
    leafHash1: string;
    merkleRoot: string;
    witnessPeerId: string;
    sigEd25519: string;
    sigMldsa65: string;
  }): Promise<{ inserted: boolean; leafIndex0: number; leafIndex1: number; merkleRoot: string }> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN ISOLATION LEVEL SERIALIZABLE');

      const existing = await client.query<{
        leaf_index_0: number;
        leaf_index_1: number;
        merkle_root: string;
      }>(
        `SELECT leaf_index_0, leaf_index_1, merkle_root FROM ${this.q('committed_tx_outputs')} WHERE tx_binding = $1`,
        [params.txBinding],
      );
      if (existing.rows[0]) {
        await client.query('COMMIT');
        return {
          inserted: false,
          leafIndex0: existing.rows[0].leaf_index_0,
          leafIndex1: existing.rows[0].leaf_index_1,
          merkleRoot: existing.rows[0].merkle_root,
        };
      }

      await client.query(
        `INSERT INTO ${this.q('note_commitments')}
           (leaf_index, epoch, note_commitment, leaf_hash, tx_kind, tx_ref)
         VALUES
           ($1, $2, $3, $4, 'spend', $7),
           ($5, $2, $6, $8, 'spend', $7)`,
        [
          params.leafIndex0,
          params.epoch,
          params.outCommit0,
          params.leafHash0,
          params.leafIndex1,
          params.outCommit1,
          params.txBinding,
          params.leafHash1,
        ],
      );

      await client.query(
        `INSERT INTO ${this.q('committed_tx_outputs')}
           (tx_binding, epoch, leaf_index_0, leaf_index_1, out_commit_0, out_commit_1, merkle_root)
         VALUES ($1, $2, $3, $4, $5, $6, $7)`,
        [
          params.txBinding,
          params.epoch,
          params.leafIndex0,
          params.leafIndex1,
          params.outCommit0,
          params.outCommit1,
          params.merkleRoot,
        ],
      );

      await client.query(
        `INSERT INTO ${this.q('merkle_roots')}
           (epoch, tree_size, merkle_root, witness_peer_id, sig_ed25519, sig_mldsa65)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (epoch, tree_size, merkle_root) DO NOTHING`,
        [
          params.epoch,
          params.leafIndex1 + 1,
          params.merkleRoot,
          params.witnessPeerId,
          params.sigEd25519,
          params.sigMldsa65,
        ],
      );

      await client.query('COMMIT');
      return {
        inserted: true,
        leafIndex0: params.leafIndex0,
        leafIndex1: params.leafIndex1,
        merkleRoot: params.merkleRoot,
      };
    } catch (err) {
      try {
        await client.query('ROLLBACK');
      } catch {
        // ignore
      }
      throw err;
    } finally {
      client.release();
    }
  }

  async isRecentSignedMerkleRoot(merkleRootHex: string, recentWindow = 64): Promise<boolean> {
    const res = await this.pool.query<{ merkle_root: string }>(
      `SELECT merkle_root FROM ${this.q('merkle_roots')}
       ORDER BY id DESC LIMIT $1`,
      [recentWindow],
    );
    return res.rows.some((r) => r.merkle_root === merkleRootHex);
  }

  async getLatestSignedRoot(): Promise<SignedMerkleRootRow | null> {
    const res = await this.pool.query<{
      id: number;
      epoch: number;
      tree_size: number;
      merkle_root: string;
      witness_peer_id: string;
      sig_ed25519: string;
      sig_mldsa65: string;
      created_at: Date;
    }>(
      `SELECT id, epoch, tree_size, merkle_root, witness_peer_id, sig_ed25519, sig_mldsa65, created_at
       FROM ${this.q('merkle_roots')} ORDER BY id DESC LIMIT 1`,
    );
    const r = res.rows[0];
    if (!r) return null;
    return {
      id: r.id,
      epoch: r.epoch,
      treeSize: r.tree_size,
      merkleRoot: r.merkle_root,
      witnessPeerId: r.witness_peer_id,
      sigEd25519: r.sig_ed25519,
      sigMldsa65: r.sig_mldsa65,
      createdAt: r.created_at.toISOString(),
    };
  }

  async listEpochIssuanceTotals(): Promise<EpochIssuanceTotalRow[]> {
    const res = await this.pool.query<{
      epoch: number;
      genesis_total: string;
      mint_total: string;
      issuance_count: number;
      updated_at: Date;
    }>(
      `SELECT epoch, genesis_total::text, mint_total::text, issuance_count, updated_at
       FROM ${this.q('epoch_issuance_totals')} ORDER BY epoch ASC`,
    );
    return res.rows.map((r) => ({
      epoch: r.epoch,
      genesisTotal: r.genesis_total,
      mintTotal: r.mint_total,
      totalIssued: (BigInt(r.genesis_total) + BigInt(r.mint_total)).toString(),
      issuanceCount: r.issuance_count,
      updatedAt: r.updated_at.toISOString(),
    }));
  }

  async storeBlindShard(shard: Omit<BlindShardRecord, 'createdAt'>): Promise<void> {
    await this.pool.query(
      `
        INSERT INTO ${this.q('blind_shards')} (
          shard_id, thread_digest, share_index, nonce_hex, ciphertext_b64, mac_tag_hex
        )
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (shard_id) DO UPDATE SET
          thread_digest = EXCLUDED.thread_digest,
          share_index = EXCLUDED.share_index,
          nonce_hex = EXCLUDED.nonce_hex,
          ciphertext_b64 = EXCLUDED.ciphertext_b64,
          mac_tag_hex = EXCLUDED.mac_tag_hex
      `,
      [
        shard.shardId,
        shard.threadDigest,
        shard.shareIndex,
        shard.nonceHex,
        shard.ciphertextB64,
        shard.macTagHex,
      ],
    );
  }

  async getBlindShard(shardId: string): Promise<BlindShardRecord | null> {
    const res = await this.pool.query<{
      shard_id: string;
      thread_digest: string;
      share_index: number;
      nonce_hex: string;
      ciphertext_b64: string;
      mac_tag_hex: string;
      created_at: Date;
    }>(
      `SELECT shard_id, thread_digest, share_index, nonce_hex, ciphertext_b64, mac_tag_hex, created_at
       FROM ${this.q('blind_shards')} WHERE shard_id = $1`,
      [shardId],
    );
    const row = res.rows[0];
    if (!row) return null;
    return {
      shardId: row.shard_id,
      threadDigest: row.thread_digest,
      shareIndex: row.share_index,
      nonceHex: row.nonce_hex,
      ciphertextB64: row.ciphertext_b64,
      macTagHex: row.mac_tag_hex,
      createdAt: row.created_at.toISOString(),
    };
  }

  async upsertWitnessPeer(record: SignedPeerRecord): Promise<void> {
    await this.pool.query(
      `
        INSERT INTO ${this.q('witness_peers')} (
          peer_id, endpoint, ed25519_pk_hex, mldsa65_pk_b64, x25519_pk_hex,
          hashcash_nonce, hashcash_bits, self_sig_ed25519, self_sig_mldsa65
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        ON CONFLICT (peer_id) DO UPDATE SET
          endpoint = EXCLUDED.endpoint,
          ed25519_pk_hex = EXCLUDED.ed25519_pk_hex,
          mldsa65_pk_b64 = EXCLUDED.mldsa65_pk_b64,
          x25519_pk_hex = EXCLUDED.x25519_pk_hex,
          hashcash_nonce = EXCLUDED.hashcash_nonce,
          hashcash_bits = EXCLUDED.hashcash_bits,
          self_sig_ed25519 = EXCLUDED.self_sig_ed25519,
          self_sig_mldsa65 = EXCLUDED.self_sig_mldsa65
      `,
      [
        record.peerId,
        record.endpoint,
        record.ed25519PkHex,
        record.mldsa65PkB64,
        record.x25519PkHex,
        record.hashcashNonce,
        record.hashcashBits,
        record.selfSigEd25519Hex,
        record.selfSigMldsa65B64,
      ],
    );
  }

  async listWitnessPeers(): Promise<SignedPeerRecord[]> {
    const res = await this.pool.query<{
      peer_id: string;
      endpoint: string;
      ed25519_pk_hex: string;
      mldsa65_pk_b64: string;
      x25519_pk_hex: string;
      hashcash_nonce: string;
      hashcash_bits: number;
      self_sig_ed25519: string;
      self_sig_mldsa65: string;
    }>(
      `SELECT peer_id, endpoint, ed25519_pk_hex, mldsa65_pk_b64, x25519_pk_hex,
              hashcash_nonce, hashcash_bits, self_sig_ed25519, self_sig_mldsa65
       FROM ${this.q('witness_peers')} ORDER BY peer_id ASC`,
    );
    return res.rows.map((r) => ({
      peerId: r.peer_id,
      endpoint: r.endpoint,
      ed25519PkHex: r.ed25519_pk_hex,
      mldsa65PkB64: r.mldsa65_pk_b64,
      x25519PkHex: r.x25519_pk_hex,
      hashcashNonce: r.hashcash_nonce,
      hashcashBits: r.hashcash_bits,
      selfSigEd25519Hex: r.self_sig_ed25519,
      selfSigMldsa65B64: r.self_sig_mldsa65,
    }));
  }

  async dumpAuditRows(): Promise<{
    schema: string;
    spentNullifiers: Record<string, unknown>[];
    blindShards: Record<string, unknown>[];
    witnessPeersCount: number;
  }> {
    const [nullifiersRes, shardsRes, peersRes] = await Promise.all([
      this.pool.query(`SELECT * FROM ${this.q('spent_nullifiers')} ORDER BY spent_at DESC`),
      this.pool.query(`SELECT * FROM ${this.q('blind_shards')} ORDER BY created_at DESC`),
      this.pool.query<{ cnt: string }>(`SELECT COUNT(*)::text AS cnt FROM ${this.q('witness_peers')}`),
    ]);
    return {
      schema: this.schema,
      spentNullifiers: nullifiersRes.rows,
      blindShards: shardsRes.rows,
      witnessPeersCount: Number(peersRes.rows[0]?.cnt ?? '0'),
    };
  }

  async close(): Promise<void> {
    await this.pool.end();
  }
}

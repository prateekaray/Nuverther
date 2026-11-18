import { Pool } from 'pg';
import type { SignedPeerRecord } from './crypto.ts';

export interface SpentNullifierRecord {
  nullifier: string;
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

export type ClaimNullifierResult =
  | { ok: true }
  | { ok: false; reason: 'DOUBLE_SPEND' };

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
          tx_binding TEXT NOT NULL,
          proof_sha256 TEXT NOT NULL,
          attestation_ed25519 TEXT NOT NULL,
          attestation_mldsa65 TEXT NOT NULL,
          spent_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
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
   * Atomically claims a pair of nullifiers using SERIALIZABLE isolation and
   * INSERT ... ON CONFLICT DO NOTHING so concurrent double-spend races are impossible.
   */
  async claimNullifiersAtomic(params: {
    nullifiers: [string, string];
    txBinding: string;
    proofSha256: string;
    attestationEd25519: string;
    attestationMldsa65: string;
  }): Promise<ClaimNullifierResult> {
    const [n0, n1] = params.nullifiers;
    if (n0 === n1) {
      return { ok: false, reason: 'DOUBLE_SPEND' };
    }

    const client = await this.pool.connect();
    try {
      await client.query('BEGIN ISOLATION LEVEL SERIALIZABLE');
      const insertSql = `
        INSERT INTO ${this.q('spent_nullifiers')} (
          nullifier,
          tx_binding,
          proof_sha256,
          attestation_ed25519,
          attestation_mldsa65
        )
        VALUES
          ($1, $3, $4, $5, $6),
          ($2, $3, $4, $5, $6)
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
      ]);

      if (result.rowCount !== 2) {
        await client.query('ROLLBACK');
        return { ok: false, reason: 'DOUBLE_SPEND' };
      }

      await client.query('COMMIT');
      return { ok: true };
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
      // Serialization failure (40001) or unique violation (23505) means concurrent race lost atomically
      if (pgCode === '40001' || pgCode === '23505') {
        return { ok: false, reason: 'DOUBLE_SPEND' };
      }
      throw err;
    } finally {
      client.release();
    }
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

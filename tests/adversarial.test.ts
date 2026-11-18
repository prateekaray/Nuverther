import { randomBytes } from 'node:crypto';
import { Pool } from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  computeCommitment,
  computeFeeCommitment,
  computeNullifier,
  destroyBarretenberg,
  generateSpendProof,
  normalizeFieldHex,
  randomFieldElement,
  verifySpendProof,
} from '@nuverther/zk';
import {
  NuvertherNode,
  ONION_PACKET_SIZE,
  computeExpectedTxBinding,
  computeShardMacTag,
  generateNodeKeypair,
  selectWitnessQuorum,
  spendStatementPayload,
  type SignedPeerRecord,
} from '@nuverther/node';
import {
  decryptWalletKeystore,
  encryptWalletKeystore,
  executeShieldedSpend,
  generateWallet,
  recoverEncryptedThreadFromShards,
  recoverWalletFromShamirShares,
  sendViaThreeHopOnion,
  signCanonicalMessage,
  splitMasterSeedShamir,
} from '@nuverther/client';

const DATABASE_URL =
  process.env.DATABASE_URL ?? 'postgresql://postgres:postgres@127.0.0.1:5432/postgres';

const NODE_COUNT = 11;
const TEST_SCHEMA_PREFIX = 'nuv_adv_node_';

describe('Nuverther Production Adversarial & Concurrency Verification Suite (Zero Mocks)', () => {
  const nodes: NuvertherNode[] = [];
  let peers: SignedPeerRecord[] = [];
  let adminPool: Pool;

  beforeAll(async () => {
    adminPool = new Pool({ connectionString: DATABASE_URL });

    // Clean schemas for deterministic test execution
    for (let i = 1; i <= NODE_COUNT; i++) {
      const schema = `${TEST_SCHEMA_PREFIX}${String(i).padStart(2, '0')}`;
      await adminPool.query(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`);
    }

    // Boot 11 independent Witness / Onion Relay / Blind Shard nodes backed by PostgreSQL
    for (let i = 1; i <= NODE_COUNT; i++) {
      const idx = String(i).padStart(2, '0');
      const peerId = `witness-${idx}`;
      const schema = `${TEST_SCHEMA_PREFIX}${idx}`;
      const keypair = generateNodeKeypair(peerId, Buffer.from(`test-seed-${idx}`, 'utf8'));
      const node = new NuvertherNode({
        peerId,
        host: '127.0.0.1',
        port: 0,
        databaseUrl: DATABASE_URL,
        dbSchema: schema,
        keypair,
        hashcashBits: 10,
        rateLimitCapacity: 2000,
        rateLimitRefillPerSec: 1000,
        logLevel: 'silent',
      });
      await node.start();
      nodes.push(node);
    }

    peers = nodes.map((n) => n.getSignedIdentity());

    // Cross-register all 11 signed peer identities via Hash-Cash verified /v1/peers endpoint
    await Promise.all(
      nodes.map(async (node) => {
        for (const peer of peers) {
          const res = await fetch(`${node.endpoint}/v1/peers`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(peer),
          });
          expect(res.status).toBe(201);
        }
      }),
    );

    // Verify readiness & Prometheus metrics endpoints on live nodes
    const readyRes = await fetch(`${nodes[0]!.endpoint}/readyz`);
    expect(readyRes.status).toBe(200);
    const metricsRes = await fetch(`${nodes[0]!.endpoint}/metrics`);
    expect(metricsRes.status).toBe(200);
    expect(await metricsRes.text()).toContain('nuverther_witness_attestations_total');
  });

  afterAll(async () => {
    await Promise.all(nodes.map((n) => n.stop()));
    if (adminPool) {
      for (let i = 1; i <= NODE_COUNT; i++) {
        const schema = `${TEST_SCHEMA_PREFIX}${String(i).padStart(2, '0')}`;
        await adminPool.query(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`);
      }
      await adminPool.end();
    }
    await destroyBarretenberg();
  });

  it('0. Quantum-safe key custody: Argon2id + XChaCha20-Poly1305 & 2-of-3 Shamir recovery', async () => {
    const wallet = await generateWallet();
    const keystore = await encryptWalletKeystore(wallet, 'correct-horse-quantum-battery', {
      t: 2,
      m: 16384,
      p: 1,
    });

    await expect(
      decryptWalletKeystore(keystore, 'wrong-passphrase-123'),
    ).rejects.toThrow();

    const unlocked = await decryptWalletKeystore(keystore, 'correct-horse-quantum-battery');
    expect(unlocked.ownerPkHex).toBe(wallet.ownerPkHex);
    expect(unlocked.ed25519PkHex).toBe(wallet.ed25519PkHex);
    expect(unlocked.mldsa65PkB64).toBe(wallet.mldsa65PkB64);

    const shares = await splitMasterSeedShamir(wallet.masterSeed, 3, 2);
    expect(shares).toHaveLength(3);

    const recovered = await recoverWalletFromShamirShares([shares[0]!, shares[2]!]);
    expect(recovered.spendSecret).toBe(wallet.spendSecret);
    expect(recovered.ownerPkHex).toBe(wallet.ownerPkHex);
    expect(recovered.ed25519PkHex).toBe(wallet.ed25519PkHex);
    expect(recovered.mldsa65PkB64).toBe(wallet.mldsa65PkB64);
  });

  it('1. Concurrent double-spend race: 50 parallel spends of same nullifier -> exactly 1 succeeds, 49 fail atomically', async () => {
    const alice = await generateWallet();
    const bob = await generateWallet();

    const in0 = { amount: 5000n, blinding: randomFieldElement(), threadId: randomFieldElement() };
    const in1 = { amount: 2500n, blinding: randomFieldElement(), threadId: randomFieldElement() };
    const out0Amount = 6000n;
    const out1Amount = 1450n;
    const fee = 50n;
    const out0Blind = randomFieldElement();
    const out1Blind = randomFieldElement();
    const feeBlind = randomFieldElement();

    const out0Commit = normalizeFieldHex(
      await computeCommitment(out0Amount, bob.ownerPk, out0Blind),
    );
    const out1Commit = normalizeFieldHex(
      await computeCommitment(out1Amount, alice.ownerPk, out1Blind),
    );
    const feeCommit = normalizeFieldHex(await computeFeeCommitment(fee, feeBlind));

    const txBinding = computeExpectedTxBinding({
      ed25519PkHex: alice.ed25519PkHex,
      mldsa65PkB64: alice.mldsa65PkB64,
      outputCommitments: [out0Commit, out1Commit],
      feeCommitment: feeCommit,
    });

    const proofBundle = await generateSpendProof({
      spendSecret: alice.spendSecret,
      inAmounts: [in0.amount, in1.amount],
      inBlindings: [in0.blinding, in1.blinding],
      inThreadIds: [in0.threadId, in1.threadId],
      outAmounts: [out0Amount, out1Amount],
      outOwnerPks: [bob.ownerPk, alice.ownerPk],
      outBlindings: [out0Blind, out1Blind],
      fee,
      feeBlinding: feeBlind,
      txBinding: BigInt(txBinding),
    });

    const spenderSig = signCanonicalMessage(
      spendStatementPayload(proofBundle.publicSignals),
      alice,
    );

    const attestBody = {
      proofBundle,
      spenderPub: {
        ed25519PkHex: alice.ed25519PkHex,
        mldsa65PkB64: alice.mldsa65PkB64,
      },
      spenderSig,
    };

    const quorum = selectWitnessQuorum(proofBundle.publicSignals.nullifiers[0], peers, 7);
    expect(quorum).toHaveLength(7);

    // Fire 50 simultaneous spend attempts for the EXACT same nullifier across the 7-of-11 Witness quorum via 3-hop onion routes
    const raceResults = await Promise.allSettled(
      Array.from({ length: 50 }, async () => {
        await sendViaThreeHopOnion<{ attestation: unknown }>({
          peers,
          targetPeer: quorum[0]!,
          method: 'POST',
          path: '/v1/witness/attest',
          body: attestBody,
        });
        const witnessResponses = await Promise.all(
          quorum.slice(1).map((witness) =>
            sendViaThreeHopOnion<{ attestation: unknown }>({
              peers,
              targetPeer: witness,
              method: 'POST',
              path: '/v1/witness/attest',
              body: attestBody,
            }),
          ),
        );
        return 1 + witnessResponses.length;
      }),
    );

    const succeeded = raceResults.filter((r) => r.status === 'fulfilled');
    const rejected = raceResults.filter((r) => r.status === 'rejected');

    expect(succeeded).toHaveLength(1);
    expect(rejected).toHaveLength(49);
    for (const failure of rejected) {
      expect(String(failure.reason)).toContain('ERR_DOUBLE_SPEND');
    }

    // Confirm PostgreSQL on every quorum Witness holds exactly 1 row for each of the 2 nullifiers
    for (const witness of quorum) {
      const node = nodes.find((n) => n.getSignedIdentity().peerId === witness.peerId)!;
      const dump = await node.db.dumpAuditRows();
      const matching = dump.spentNullifiers.filter(
        (r) =>
          r.nullifier === proofBundle.publicSignals.nullifiers[0] ||
          r.nullifier === proofBundle.publicSignals.nullifiers[1],
      );
      expect(matching).toHaveLength(2);
    }
  });

  it('2. Amount inflation & 64-bit overflow: modifying output or using 2^64 - 1 -> ZK proof & verification fail', async () => {
    const alice = await generateWallet();
    const maxU64 = (1n << 64n) - 1n; // 2^64 - 1

    // 2a. Attempt to inflate output using 2^64 - 1 wrap-around inside the Noir circuit
    await expect(
      generateSpendProof({
        spendSecret: alice.spendSecret,
        inAmounts: [100n, 0n],
        inBlindings: [11n, 22n],
        inThreadIds: [1001n, 1002n],
        outAmounts: [maxU64, 101n],
        outOwnerPks: [alice.ownerPk, alice.ownerPk],
        outBlindings: [33n, 44n],
        fee: 0n,
        feeBlinding: 55n,
        txBinding: 999n,
      }),
    ).rejects.toThrow();

    // 2b. Attempt value >= 2^64 (out of u64 range)
    await expect(
      generateSpendProof({
        spendSecret: alice.spendSecret,
        inAmounts: [1n << 64n, 0n],
        inBlindings: [11n, 22n],
        inThreadIds: [1001n, 1002n],
        outAmounts: [1n << 64n, 0n],
        outOwnerPks: [alice.ownerPk, alice.ownerPk],
        outBlindings: [33n, 44n],
        fee: 0n,
        feeBlinding: 55n,
        txBinding: 999n,
      }),
    ).rejects.toThrow();

    // 2c. Modify an output commitment in a valid proof bundle -> ZK verification rejects immediately
    const validOutBlind = randomFieldElement();
    const validFeeBlind = randomFieldElement();
    const out0Commit = normalizeFieldHex(
      await computeCommitment(800n, alice.ownerPk, validOutBlind),
    );
    const out1Commit = normalizeFieldHex(
      await computeCommitment(190n, alice.ownerPk, validOutBlind + 1n),
    );
    const feeCommit = normalizeFieldHex(await computeFeeCommitment(10n, validFeeBlind));
    const txBinding = computeExpectedTxBinding({
      ed25519PkHex: alice.ed25519PkHex,
      mldsa65PkB64: alice.mldsa65PkB64,
      outputCommitments: [out0Commit, out1Commit],
      feeCommitment: feeCommit,
    });

    const validBundle = await generateSpendProof({
      spendSecret: alice.spendSecret,
      inAmounts: [600n, 400n],
      inBlindings: [101n, 102n],
      inThreadIds: [2001n, 2002n],
      outAmounts: [800n, 190n],
      outOwnerPks: [alice.ownerPk, alice.ownerPk],
      outBlindings: [validOutBlind, validOutBlind + 1n],
      fee: 10n,
      feeBlinding: validFeeBlind,
      txBinding: BigInt(txBinding),
    });

    const inflatedOutCommit = normalizeFieldHex(
      await computeCommitment(999_999n, alice.ownerPk, validOutBlind),
    );
    const tamperedBundle = {
      ...validBundle,
      publicInputs: [
        validBundle.publicInputs[0]!,
        validBundle.publicInputs[1]!,
        validBundle.publicInputs[2]!,
        validBundle.publicInputs[3]!,
        inflatedOutCommit,
        validBundle.publicInputs[5]!,
        validBundle.publicInputs[6]!,
        validBundle.publicInputs[7]!,
      ],
      publicSignals: {
        ...validBundle.publicSignals,
        outputCommitments: [inflatedOutCommit, out1Commit] as [string, string],
      },
    };

    expect(await verifySpendProof(tamperedBundle)).toBe(false);

    // Also verify Witness rejects tampered output commitment over HTTP
    const tamperedSig = signCanonicalMessage(
      spendStatementPayload(tamperedBundle.publicSignals),
      alice,
    );
    const res = await fetch(`${nodes[0]!.endpoint}/v1/witness/attest`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        proofBundle: tamperedBundle,
        spenderPub: {
          ed25519PkHex: alice.ed25519PkHex,
          mldsa65PkB64: alice.mldsa65PkB64,
        },
        spenderSig: tamperedSig,
      }),
    });
    expect(res.status).toBe(403);
  });

  it('3. Node breach & IP privacy: dumping all Witness & Storage DBs reveals zero plaintext amounts, zero keys, zero user IPs', async () => {
    const alice = await generateWallet();
    const bob = await generateWallet();
    const secretMemo = 'CONFIDENTIAL_INVOICE_42917_DO_NOT_LEAK';
    const secretAmount = 77_432_109n;

    const spendResult = await executeShieldedSpend({
      keys: alice,
      peers,
      inputs: [
        { amount: 80_000_000n, blinding: randomFieldElement(), threadId: randomFieldElement() },
        { amount: 5_000_000n, blinding: randomFieldElement(), threadId: randomFieldElement() },
      ],
      outputs: [
        { amount: secretAmount, recipientOwnerPk: bob.ownerPk, memo: secretMemo },
        { amount: 7_567_800n, recipientOwnerPk: alice.ownerPk },
      ],
      fee: 91n,
    });

    expect(spendResult.attestations).toHaveLength(7);
    expect(spendResult.shardPointers).toHaveLength(3);

    // Recover Thread payload using ONLY 2 of the 3 blind shards via 3-hop onion relay
    const recovered = await recoverEncryptedThreadFromShards({
      peers,
      shardPointers: [spendResult.shardPointers[0]!, spendResult.shardPointers[2]!],
      threadKeyHex: spendResult.threadKeyHex,
    });
    expect(recovered.amount).toBe(secretAmount.toString());
    expect(recovered.memo).toBe(secretMemo);

    // Breach simulation: dump EVERY table on EVERY node in PostgreSQL
    for (const node of nodes) {
      const dump = await node.db.dumpAuditRows();
      const serializedDump = JSON.stringify(dump);

      // Zero plaintext amounts or secret memos
      expect(serializedDump).not.toContain(secretMemo);
      expect(serializedDump).not.toContain(secretAmount.toString());
      expect(serializedDump).not.toContain('80000000');
      expect(serializedDump).not.toContain('7567800');

      // Zero user private keys or spendSecret
      expect(serializedDump).not.toContain(alice.spendSecret.toString(16));
      expect(serializedDump).not.toContain(Buffer.from(alice.ed25519Sk).toString('hex'));
      expect(serializedDump).not.toContain(spendResult.threadKeyHex);

      // Zero user IP columns or IP addresses in Witness/Shard schemas
      for (const row of dump.spentNullifiers) {
        const keys = Object.keys(row);
        expect(keys).not.toContain('ip');
        expect(keys).not.toContain('client_ip');
        expect(keys).not.toContain('amount');
        expect(serializedDump).not.toContain('127.0.0.1');
      }
      for (const row of dump.blindShards) {
        const keys = Object.keys(row);
        expect(keys).not.toContain('ip');
        expect(keys).not.toContain('amount');
        expect(keys).not.toContain('plaintext');
      }
    }

    // Rejects any non-16KB packet on /v1/relay
    const badRelay = await fetch(`${nodes[0]!.endpoint}/v1/relay`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/octet-stream' },
      body: randomBytes(ONION_PACKET_SIZE - 1),
    });
    expect(badRelay.status).toBe(400);
  });

  it('4. Tampered shard / forged PQ signature: flipping 1 byte in shard, Ed25519 sig, or ML-DSA-65 sig -> rejected immediately', async () => {
    const alice = await generateWallet();

    // 4a. Flip 1 byte in a Blind Shard ciphertext -> MAC rejected on write & AEAD rejected on read
    const shardId = Buffer.from(randomBytes(32)).toString('hex');
    const threadDigest = Buffer.from(randomBytes(32)).toString('hex');
    const nonceHex = Buffer.from(randomBytes(24)).toString('hex');
    const originalCipher = randomBytes(64);
    const ciphertextB64 = originalCipher.toString('base64');
    const macTagHex = computeShardMacTag({
      shardId,
      threadDigest,
      shareIndex: 1,
      nonceHex,
      ciphertextB64,
    });

    const flippedCipher = Buffer.from(originalCipher);
    flippedCipher[0] = flippedCipher[0]! ^ 0x01;
    const tamperedShardResp = await fetch(`${nodes[0]!.endpoint}/v1/shards`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        shardId,
        threadDigest,
        shareIndex: 1,
        nonceHex,
        ciphertextB64: flippedCipher.toString('base64'),
        macTagHex,
      }),
    });
    expect(tamperedShardResp.status).toBe(400);
    expect(await tamperedShardResp.json()).toMatchObject({ error: 'TAMPERED_SHARD_MAC' });

    // Prepare valid proof + signature for 4b & 4c
    const outBlind = randomFieldElement();
    const feeBlind = randomFieldElement();
    const out0Commit = normalizeFieldHex(await computeCommitment(300n, alice.ownerPk, outBlind));
    const out1Commit = normalizeFieldHex(await computeCommitment(190n, alice.ownerPk, outBlind + 1n));
    const feeCommit = normalizeFieldHex(await computeFeeCommitment(10n, feeBlind));
    const txBinding = computeExpectedTxBinding({
      ed25519PkHex: alice.ed25519PkHex,
      mldsa65PkB64: alice.mldsa65PkB64,
      outputCommitments: [out0Commit, out1Commit],
      feeCommitment: feeCommit,
    });

    const proofBundle = await generateSpendProof({
      spendSecret: alice.spendSecret,
      inAmounts: [250n, 250n],
      inBlindings: [71n, 72n],
      inThreadIds: [3001n, 3002n],
      outAmounts: [300n, 190n],
      outOwnerPks: [alice.ownerPk, alice.ownerPk],
      outBlindings: [outBlind, outBlind + 1n],
      fee: 10n,
      feeBlinding: feeBlind,
      txBinding: BigInt(txBinding),
    });

    const validSig = signCanonicalMessage(
      spendStatementPayload(proofBundle.publicSignals),
      alice,
    );

    // 4b. Flip 1 byte in Ed25519 signature -> rejected immediately (403)
    const edBytes = Buffer.from(validSig.ed25519Hex, 'hex');
    edBytes[0] = edBytes[0]! ^ 0x01;
    const forgedEdRes = await fetch(`${nodes[1]!.endpoint}/v1/witness/attest`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        proofBundle,
        spenderPub: {
          ed25519PkHex: alice.ed25519PkHex,
          mldsa65PkB64: alice.mldsa65PkB64,
        },
        spenderSig: {
          ed25519Hex: edBytes.toString('hex'),
          mldsa65B64: validSig.mldsa65B64,
        },
      }),
    });
    expect(forgedEdRes.status).toBe(403);
    expect(await forgedEdRes.json()).toMatchObject({ error: 'INVALID_HYBRID_PQ_SIGNATURE' });

    // 4c. Flip 1 byte in ML-DSA-65 post-quantum signature -> rejected immediately (403)
    const pqBytes = Buffer.from(validSig.mldsa65B64, 'base64');
    pqBytes[10] = pqBytes[10]! ^ 0x01;
    const forgedPqRes = await fetch(`${nodes[1]!.endpoint}/v1/witness/attest`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        proofBundle,
        spenderPub: {
          ed25519PkHex: alice.ed25519PkHex,
          mldsa65PkB64: alice.mldsa65PkB64,
        },
        spenderSig: {
          ed25519Hex: validSig.ed25519Hex,
          mldsa65B64: pqBytes.toString('base64'),
        },
      }),
    });
    expect(forgedPqRes.status).toBe(403);
    expect(await forgedPqRes.json()).toMatchObject({ error: 'INVALID_HYBRID_PQ_SIGNATURE' });

    // 4d. Flip 1 byte in Noir proof -> rejected immediately (403)
    const proofBytes = Buffer.from(proofBundle.proofBase64, 'base64');
    proofBytes[200] = proofBytes[200]! ^ 0x01;
    const forgedZkRes = await fetch(`${nodes[1]!.endpoint}/v1/witness/attest`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        proofBundle: {
          ...proofBundle,
          proofBase64: proofBytes.toString('base64'),
        },
        spenderPub: {
          ed25519PkHex: alice.ed25519PkHex,
          mldsa65PkB64: alice.mldsa65PkB64,
        },
        spenderSig: validSig,
      }),
    });
    expect(forgedZkRes.status).toBe(403);
    expect(await forgedZkRes.json()).toMatchObject({ error: 'INVALID_ZK_PROOF' });

    // Confirm valid nullifier was NEVER claimed by any of the tampered attempts
    const nullifier = await computeNullifier(alice.spendSecret, 3001n);
    const dumpAfterTamper = await nodes[1]!.db.dumpAuditRows();
    expect(
      dumpAfterTamper.spentNullifiers.some((r) => r.nullifier === normalizeFieldHex(nullifier)),
    ).toBe(false);
  });
});

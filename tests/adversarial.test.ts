import { randomBytes } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Pool } from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  Poseidon2MerkleTree,
  computeCommitment,
  computeFeeCommitment,
  computeLeaf,
  computeNullifier,
  destroyBarretenberg,
  generateSpendProof,
  normalizeFieldHex,
  randomFieldElement,
  verifySpendProof,
  type SpendProofBundle,
} from '@nuverther/zk';
import {
  DEFAULT_QUORUM_SIZE,
  NuvertherNode,
  ONION_PACKET_SIZE,
  computeChainedCheckpointHash,
  computeEpochDirectoryHash,
  computeExpectedTxBinding,
  computeShardMacTag,
  createSignedEpochDirectory,
  generateNodeKeypair,
  selectWitnessQuorumForEpoch,
  signHybrid,
  spendStatementPayload,
  type ChainedWitnessCheckpoint,
  type EpochWitnessMember,
  type EquivocationProof,
  type NodeKeypair,
  type PrepareVote,
  type SignedEpochDirectory,
} from '@nuverther/node';
import {
  SpendIntentStore,
  broadcastEpochDirectory,
  broadcastSignedIssuance,
  createSignedIssuance,
  decryptWalletKeystore,
  discoverEpochDirectory,
  encryptWalletKeystore,
  executeShieldedSpend,
  generateWallet,
  recoverEncryptedThreadFromShards,
  recoverSpendIntent,
  recoverWalletFromShamirShares,
  sendViaThreeHopOnion,
  signCanonicalMessage,
  splitMasterSeedShamir,
  submitEquivocationProof,
  syncMerkleTreeFromPeers,
} from '@nuverther/client';

const DATABASE_URL =
  process.env.DATABASE_URL ?? 'postgresql://postgres:postgres@127.0.0.1:5432/postgres';

const NODE_COUNT = 11;
const TEST_SCHEMA_PREFIX = 'nuv_adv_node_';

function toEpochMember(node: NuvertherNode, joinedEpoch = 0): EpochWitnessMember {
  const id = node.getSignedIdentity();
  return {
    peerId: id.peerId,
    endpoint: id.endpoint,
    ed25519PkHex: id.ed25519PkHex,
    mldsa65PkB64: id.mldsa65PkB64,
    x25519PkHex: id.x25519PkHex,
    joinedEpoch,
  };
}

describe('Nuverther Production Adversarial, Consensus & Soundness Suite (Zero Mocks)', () => {
  const nodes: NuvertherNode[] = [];
  const extraNodes: NuvertherNode[] = [];
  let activeDirectory!: SignedEpochDirectory;
  let activeDirectoryHash = '';
  let peers: EpochWitnessMember[] = [];
  let adminPool: Pool;
  let issuerKeypair: NodeKeypair;
  let govKeypair: NodeKeypair;
  let tempDir: string;
  let nextLeafIndex = 0;

  async function issueNoteToAllPeers(params: {
    epoch: number;
    txKind: 'genesis' | 'mint';
    amount: bigint;
    recipientOwnerPk: bigint;
  }): Promise<{ leafIndex: number; blinding: bigint; merkleRoot: string }> {
    const leafIndex = nextLeafIndex++;
    const { record, blinding } = await createSignedIssuance({
      issuanceId: `iss-${params.txKind}-${leafIndex}-${Date.now()}`,
      epoch: params.epoch,
      txKind: params.txKind,
      amount: params.amount,
      recipientOwnerPk: params.recipientOwnerPk,
      leafIndex,
      issuerKeys: issuerKeypair,
    });
    const res = await broadcastSignedIssuance(peers, record);
    return { leafIndex: res.leafIndex, blinding, merkleRoot: res.merkleRoot };
  }

  beforeAll(async () => {
    tempDir = mkdtempSync(join(tmpdir(), 'nuv-phase2-'));
    adminPool = new Pool({ connectionString: DATABASE_URL });

    for (let i = 1; i <= NODE_COUNT + 2; i++) {
      const schema = `${TEST_SCHEMA_PREFIX}${String(i).padStart(2, '0')}`;
      await adminPool.query(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`);
    }

    issuerKeypair = generateNodeKeypair(
      'genesis-issuer',
      Buffer.from('nuverther-trusted-issuer-seed-v1', 'utf8'),
    );
    govKeypair = generateNodeKeypair(
      'governance-root',
      Buffer.from('nuverther-trusted-governance-seed-v1', 'utf8'),
    );
    const trustedIssuers = [
      {
        ed25519PkHex: Buffer.from(issuerKeypair.ed25519Pk).toString('hex'),
        mldsa65PkB64: Buffer.from(issuerKeypair.mldsa65Pk).toString('base64'),
      },
    ];
    const trustedGovernanceKeys = [
      {
        ed25519PkHex: Buffer.from(govKeypair.ed25519Pk).toString('hex'),
        mldsa65PkB64: Buffer.from(govKeypair.mldsa65Pk).toString('base64'),
      },
    ];

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
        trustedIssuers,
        trustedGovernanceKeys,
        governanceThreshold: 1,
        prepareLeaseMs: 15_000,
        hashcashBits: 10,
        allowLoopbackPeers: true,
        rateLimitCapacity: 5000,
        rateLimitRefillPerSec: 2500,
        logLevel: 'silent',
      });
      await node.start();
      nodes.push(node);
    }

    const members = nodes.map((n) => toEpochMember(n, 0));
    activeDirectory = createSignedEpochDirectory({
      epoch: 0,
      quorumSize: DEFAULT_QUORUM_SIZE,
      nullifierEpochRetention: 4,
      previousDirectorySha256: '0'.repeat(64),
      members,
      governanceSigners: [govKeypair],
    });
    activeDirectoryHash = computeEpochDirectoryHash(activeDirectory);
    await broadcastEpochDirectory(
      nodes.map((n) => n.endpoint),
      activeDirectory,
    );

    const discovered = await discoverEpochDirectory(
      nodes.map((n) => n.endpoint),
      trustedGovernanceKeys,
      1,
    );
    expect(discovered.directory.epoch).toBe(0);
    expect(discovered.directoryHash).toBe(activeDirectoryHash);
    peers = discovered.directory.members;

    // Free-form self-admission endpoint must reject with 410 Gone
    const regResp = await fetch(`${nodes[0]!.endpoint}/v1/peers`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(nodes[0]!.getSignedIdentity()),
    });
    expect(regResp.status).toBe(410);
    expect(await regResp.json()).toMatchObject({ error: 'FREEFORM_PEER_REGISTRATION_REMOVED' });

    const readyRes = await fetch(`${nodes[0]!.endpoint}/readyz`);
    expect(readyRes.status).toBe(200);
    const metricsRes = await fetch(`${nodes[0]!.endpoint}/metrics`);
    expect(metricsRes.status).toBe(200);
    expect(await metricsRes.text()).toContain('nuverther_witness_attestations_total');
  });

  afterAll(async () => {
    await Promise.all([...nodes, ...extraNodes].map((n) => n.stop()));
    if (adminPool) {
      for (let i = 1; i <= NODE_COUNT + 2; i++) {
        const schema = `${TEST_SCHEMA_PREFIX}${String(i).padStart(2, '0')}`;
        await adminPool.query(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`);
      }
      await adminPool.end();
    }
    if (tempDir) {
      rmSync(tempDir, { recursive: true, force: true });
    }
    await destroyBarretenberg();
  });

  it('0. Key custody: Argon2id + XChaCha20-Poly1305, Shamir recovery, and ownerPk binding to authPkHash', async () => {
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
    expect(unlocked.authPkHash).toBe(wallet.authPkHash);
    expect(unlocked.ed25519PkHex).toBe(wallet.ed25519PkHex);
    expect(unlocked.mldsa65PkB64).toBe(wallet.mldsa65PkB64);

    const shares = await splitMasterSeedShamir(wallet.masterSeed, 3, 2);
    expect(shares).toHaveLength(3);

    const recovered = await recoverWalletFromShamirShares([shares[0]!, shares[2]!]);
    expect(recovered.spendSecret).toBe(wallet.spendSecret);
    expect(recovered.ownerPkHex).toBe(wallet.ownerPkHex);
    expect(recovered.authPkHash).toBe(wallet.authPkHash);
  });

  it('1. Signed issuance + 8-of-11 concurrent double-spend race (50 distinct competing txBindings -> 1 succeeds, 49 fail) + auditable supply', async () => {
    const alice = await generateWallet();
    const bob = await generateWallet();

    const n0 = await issueNoteToAllPeers({
      epoch: 0,
      txKind: 'genesis',
      amount: 5000n,
      recipientOwnerPk: alice.ownerPk,
    });
    const n1 = await issueNoteToAllPeers({
      epoch: 0,
      txKind: 'mint',
      amount: 2500n,
      recipientOwnerPk: alice.ownerPk,
    });

    // Verify public supply auditability on Witnesses
    const issResp = await fetch(`${nodes[0]!.endpoint}/v1/issuance`);
    expect(issResp.status).toBe(200);
    const issJson = (await issResp.json()) as {
      treeSize: number;
      epochs: Array<{ epoch: number; genesisTotal: string; mintTotal: string; totalIssued: string }>;
    };
    const epoch0Iss = issJson.epochs.find((e) => e.epoch === 0)!;
    expect(epoch0Iss.genesisTotal).toBe('5000');
    expect(epoch0Iss.mintTotal).toBe('2500');
    expect(epoch0Iss.totalIssued).toBe('7500');

    // Sync Merkle tree and pre-build 50 distinct competing spend payloads for the exact same input nullifiers
    const { tree } = await syncMerkleTreeFromPeers(peers);
    const merkleRoot = tree.getRoot();
    const merkleRootHex = normalizeFieldHex(merkleRoot);
    const proof0 = tree.getProof(n0.leafIndex);
    const proof1 = tree.getProof(n1.leafIndex);

    const competingBodies: Array<{
      epoch: number;
      proofBundle: SpendProofBundle;
      spenderPub: { ed25519PkHex: string; mldsa65PkB64: string };
      spenderSig: { ed25519Hex: string; mldsa65B64: string };
    }> = [];

    for (let i = 0; i < 50; i++) {
      const out0Amount = 6000n;
      const out1Amount = 1450n;
      const fee = 50n;
      const out0Blind = BigInt(10_000 + i);
      const out1Blind = BigInt(20_000 + i);
      const feeBlind = BigInt(30_000 + i);

      const out0Commit = normalizeFieldHex(
        await computeCommitment(out0Amount, bob.ownerPk, out0Blind),
      );
      const out1Commit = normalizeFieldHex(
        await computeCommitment(out1Amount, alice.ownerPk, out1Blind),
      );
      const feeCommit = normalizeFieldHex(await computeFeeCommitment(fee, feeBlind));

      const txBinding = computeExpectedTxBinding({
        authPkHash: alice.authPkHash,
        merkleRoot: merkleRootHex,
        outputCommitments: [out0Commit, out1Commit],
        feeCommitment: feeCommit,
      });

      const proofBundle = await generateSpendProof({
        spendSecret: alice.spendSecret,
        inAmounts: [5000n, 2500n],
        inBlindings: [n0.blinding, n1.blinding],
        inLeafIndices: [n0.leafIndex, n1.leafIndex],
        inMerklePaths: [proof0.path, proof1.path],
        outAmounts: [out0Amount, out1Amount],
        outOwnerPks: [bob.ownerPk, alice.ownerPk],
        outBlindings: [out0Blind, out1Blind],
        fee,
        feeBlinding: feeBlind,
        authPkHash: BigInt(alice.authPkHash),
        txBinding: BigInt(txBinding),
        merkleRoot,
      });

      const spenderSig = signCanonicalMessage(
        spendStatementPayload(proofBundle.publicSignals),
        alice,
      );

      competingBodies.push({
        epoch: 0,
        proofBundle,
        spenderPub: {
          ed25519PkHex: alice.ed25519PkHex,
          mldsa65PkB64: alice.mldsa65PkB64,
        },
        spenderSig,
      });
    }

    const quorum = selectWitnessQuorumForEpoch(
      0,
      competingBodies[0]!.proofBundle.publicSignals.nullifiers[0],
      peers,
      DEFAULT_QUORUM_SIZE,
    );
    expect(quorum).toHaveLength(8);

    // Fire 50 simultaneous competing spends for the EXACT same nullifiers against quorum[0] via 3-hop onion routes
    const raceResults = await Promise.allSettled(
      competingBodies.map(async (body) => {
        const res = await sendViaThreeHopOnion<{ attestation: unknown }>({
          peers,
          targetPeer: quorum[0]!,
          method: 'POST',
          path: '/v1/witness/attest',
          body,
        });
        const restVotes = await Promise.all(
          quorum.slice(1).map((witness) =>
            sendViaThreeHopOnion<{ attestation: unknown }>({
              peers,
              targetPeer: witness,
              method: 'POST',
              path: '/v1/witness/attest',
              body,
            }),
          ),
        );
        return { winner: body, count: 1 + restVotes.length, res };
      }),
    );

    const succeeded = raceResults.filter((r) => r.status === 'fulfilled');
    const rejected = raceResults.filter((r) => r.status === 'rejected');

    expect(succeeded).toHaveLength(1);
    expect(rejected).toHaveLength(49);
    for (const failure of rejected) {
      expect(String(failure.reason)).toContain('ERR_DOUBLE_SPEND');
    }

    for (const witness of quorum) {
      const node = nodes.find((n) => n.getSignedIdentity().peerId === witness.peerId)!;
      const dump = await node.db.dumpAuditRows();
      const matching = dump.spentNullifiers.filter(
        (r) =>
          r.nullifier === competingBodies[0]!.proofBundle.publicSignals.nullifiers[0] ||
          r.nullifier === competingBodies[0]!.proofBundle.publicSignals.nullifiers[1],
      );
      expect(matching).toHaveLength(2);
    }
  });

  it('2. Protocol soundness: rejects unregistered notes, wrong authPkHash, untrusted issuers, and unknown Merkle roots', async () => {
    const alice = await generateWallet();
    const attacker = await generateWallet();

    // 2a. Untrusted issuer is rejected immediately (403 UNTRUSTED_ISSUER)
    const rogueKeys = generateNodeKeypair('rogue-issuer');
    const { record: rogueIssuance } = await createSignedIssuance({
      issuanceId: 'rogue-mint-1',
      epoch: 0,
      txKind: 'mint',
      amount: 1_000_000n,
      recipientOwnerPk: attacker.ownerPk,
      leafIndex: nextLeafIndex,
      issuerKeys: rogueKeys,
    });
    const rogueResp = await fetch(`${nodes[0]!.endpoint}/v1/issuance`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(rogueIssuance),
    });
    expect(rogueResp.status).toBe(403);
    expect(await rogueResp.json()).toMatchObject({ error: 'UNTRUSTED_ISSUER' });

    // Issue two legitimate notes for Alice
    const legit0 = await issueNoteToAllPeers({
      epoch: 0,
      txKind: 'mint',
      amount: 1000n,
      recipientOwnerPk: alice.ownerPk,
    });
    const legit1 = await issueNoteToAllPeers({
      epoch: 0,
      txKind: 'mint',
      amount: 500n,
      recipientOwnerPk: alice.ownerPk,
    });

    const { tree } = await syncMerkleTreeFromPeers(peers);
    const p0 = tree.getProof(legit0.leafIndex);
    const p1 = tree.getProof(legit1.leafIndex);

    // 2b. Unregistered fake note in a synthetic local tree fails Merkle proof verification on Witness
    const fakeTree = await Poseidon2MerkleTree.create([
      await computeCommitment(999_999n, attacker.ownerPk, 777n),
      await computeCommitment(1n, attacker.ownerPk, 888n),
    ]);
    const fakeRoot = fakeTree.getRoot();
    const fakeOut0 = normalizeFieldHex(await computeCommitment(999_990n, attacker.ownerPk, 10n));
    const fakeOut1 = normalizeFieldHex(await computeCommitment(0n, attacker.ownerPk, 11n));
    const fakeFeeCommit = normalizeFieldHex(await computeFeeCommitment(10n, 12n));
    const fakeTxBinding = computeExpectedTxBinding({
      authPkHash: attacker.authPkHash,
      merkleRoot: normalizeFieldHex(fakeRoot),
      outputCommitments: [fakeOut0, fakeOut1],
      feeCommitment: fakeFeeCommit,
    });

    const fakeBundle = await generateSpendProof({
      spendSecret: attacker.spendSecret,
      inAmounts: [999_999n, 1n],
      inBlindings: [777n, 888n],
      inLeafIndices: [0, 1],
      inMerklePaths: [fakeTree.getProof(0).path, fakeTree.getProof(1).path],
      outAmounts: [999_990n, 0n],
      outOwnerPks: [attacker.ownerPk, attacker.ownerPk],
      outBlindings: [10n, 11n],
      fee: 10n,
      feeBlinding: 12n,
      authPkHash: BigInt(attacker.authPkHash),
      txBinding: BigInt(fakeTxBinding),
      merkleRoot: fakeRoot,
    });
    const fakeSig = signCanonicalMessage(spendStatementPayload(fakeBundle.publicSignals), attacker);
    const unknownRootRes = await fetch(`${nodes[0]!.endpoint}/v1/witness/attest`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        epoch: 0,
        proofBundle: fakeBundle,
        spenderPub: {
          ed25519PkHex: attacker.ed25519PkHex,
          mldsa65PkB64: attacker.mldsa65PkB64,
        },
        spenderSig: fakeSig,
      }),
    });
    expect(unknownRootRes.status).toBe(403);
    expect(await unknownRootRes.json()).toMatchObject({ error: 'UNKNOWN_OR_STALE_MERKLE_ROOT' });

    // 2c. Mismatched leaf index (claiming real note at wrong position) fails circuit constraints
    await expect(
      generateSpendProof({
        spendSecret: alice.spendSecret,
        inAmounts: [1000n, 500n],
        inBlindings: [legit0.blinding, legit1.blinding],
        inLeafIndices: [legit0.leafIndex + 1, legit1.leafIndex],
        inMerklePaths: [p0.path, p1.path],
        outAmounts: [1490n, 0n],
        outOwnerPks: [alice.ownerPk, alice.ownerPk],
        outBlindings: [randomFieldElement(), randomFieldElement()],
        fee: 10n,
        feeBlinding: randomFieldElement(),
        authPkHash: BigInt(alice.authPkHash),
        txBinding: randomFieldElement(),
        merkleRoot: tree.getRoot(),
      }),
    ).rejects.toThrow();

    // 2d. Mismatched authPkHash fails circuit constraints
    await expect(
      generateSpendProof({
        spendSecret: alice.spendSecret,
        inAmounts: [1000n, 500n],
        inBlindings: [legit0.blinding, legit1.blinding],
        inLeafIndices: [legit0.leafIndex, legit1.leafIndex],
        inMerklePaths: [p0.path, p1.path],
        outAmounts: [1490n, 0n],
        outOwnerPks: [attacker.ownerPk, attacker.ownerPk],
        outBlindings: [randomFieldElement(), randomFieldElement()],
        fee: 10n,
        feeBlinding: randomFieldElement(),
        authPkHash: BigInt(attacker.authPkHash),
        txBinding: randomFieldElement(),
        merkleRoot: tree.getRoot(),
      }),
    ).rejects.toThrow();
  });

  it('3. Amount inflation & 64-bit overflow: modifying output or using 2^64 - 1 -> ZK proof & verification fail', async () => {
    const alice = await generateWallet();
    const maxU64 = (1n << 64n) - 1n;

    const noteA = await issueNoteToAllPeers({
      epoch: 0,
      txKind: 'mint',
      amount: 600n,
      recipientOwnerPk: alice.ownerPk,
    });
    const noteB = await issueNoteToAllPeers({
      epoch: 0,
      txKind: 'mint',
      amount: 400n,
      recipientOwnerPk: alice.ownerPk,
    });
    const { tree } = await syncMerkleTreeFromPeers(peers);
    const proofA = tree.getProof(noteA.leafIndex);
    const proofB = tree.getProof(noteB.leafIndex);

    await expect(
      generateSpendProof({
        spendSecret: alice.spendSecret,
        inAmounts: [600n, 400n],
        inBlindings: [noteA.blinding, noteB.blinding],
        inLeafIndices: [noteA.leafIndex, noteB.leafIndex],
        inMerklePaths: [proofA.path, proofB.path],
        outAmounts: [maxU64, 1001n],
        outOwnerPks: [alice.ownerPk, alice.ownerPk],
        outBlindings: [33n, 44n],
        fee: 0n,
        feeBlinding: 55n,
        authPkHash: BigInt(alice.authPkHash),
        txBinding: 999n,
        merkleRoot: tree.getRoot(),
      }),
    ).rejects.toThrow();

    await expect(
      generateSpendProof({
        spendSecret: alice.spendSecret,
        inAmounts: [1n << 64n, 0n],
        inBlindings: [noteA.blinding, noteB.blinding],
        inLeafIndices: [noteA.leafIndex, noteB.leafIndex],
        inMerklePaths: [proofA.path, proofB.path],
        outAmounts: [1n << 64n, 0n],
        outOwnerPks: [alice.ownerPk, alice.ownerPk],
        outBlindings: [33n, 44n],
        fee: 0n,
        feeBlinding: 55n,
        authPkHash: BigInt(alice.authPkHash),
        txBinding: 999n,
        merkleRoot: tree.getRoot(),
      }),
    ).rejects.toThrow();

    const validOutBlind = randomFieldElement();
    const validFeeBlind = randomFieldElement();
    const out0Commit = normalizeFieldHex(await computeCommitment(800n, alice.ownerPk, validOutBlind));
    const out1Commit = normalizeFieldHex(
      await computeCommitment(190n, alice.ownerPk, validOutBlind + 1n),
    );
    const feeCommit = normalizeFieldHex(await computeFeeCommitment(10n, validFeeBlind));
    const merkleRootHex = tree.getRootHex();
    const txBinding = computeExpectedTxBinding({
      authPkHash: alice.authPkHash,
      merkleRoot: merkleRootHex,
      outputCommitments: [out0Commit, out1Commit],
      feeCommitment: feeCommit,
    });

    const validBundle = await generateSpendProof({
      spendSecret: alice.spendSecret,
      inAmounts: [600n, 400n],
      inBlindings: [noteA.blinding, noteB.blinding],
      inLeafIndices: [noteA.leafIndex, noteB.leafIndex],
      inMerklePaths: [proofA.path, proofB.path],
      outAmounts: [800n, 190n],
      outOwnerPks: [alice.ownerPk, alice.ownerPk],
      outBlindings: [validOutBlind, validOutBlind + 1n],
      fee: 10n,
      feeBlinding: validFeeBlind,
      authPkHash: BigInt(alice.authPkHash),
      txBinding: BigInt(txBinding),
      merkleRoot: tree.getRoot(),
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
        inflatedOutCommit,
        validBundle.publicInputs[4]!,
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

    const tamperedSig = signCanonicalMessage(
      spendStatementPayload(tamperedBundle.publicSignals),
      alice,
    );
    const res = await fetch(`${nodes[0]!.endpoint}/v1/witness/attest`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        epoch: 0,
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

  it('4. Multi-hop 2PC shielded spend + node breach & IP privacy across all 11 DBs', async () => {
    const alice = await generateWallet();
    const bob = await generateWallet();
    const carol = await generateWallet();
    const secretMemo = 'CONFIDENTIAL_INVOICE_42917_DO_NOT_LEAK';
    const secretAmount = 77_432_109n;

    const note0 = await issueNoteToAllPeers({
      epoch: 0,
      txKind: 'mint',
      amount: 80_000_000n,
      recipientOwnerPk: alice.ownerPk,
    });
    const note1 = await issueNoteToAllPeers({
      epoch: 0,
      txKind: 'mint',
      amount: 5_000_000n,
      recipientOwnerPk: alice.ownerPk,
    });

    const intentStore = new SpendIntentStore(join(tempDir, 'test4-intents.json'));
    const spendResult = await executeShieldedSpend({
      keys: alice,
      directory: activeDirectory,
      intentStore,
      inputs: [
        { amount: 80_000_000n, blinding: note0.blinding, leafIndex: note0.leafIndex },
        { amount: 5_000_000n, blinding: note1.blinding, leafIndex: note1.leafIndex },
      ],
      outputs: [
        { amount: secretAmount, recipientOwnerPk: bob.ownerPk, memo: secretMemo },
        { amount: 7_567_800n, recipientOwnerPk: alice.ownerPk },
      ],
      fee: 91n,
    });

    expect(spendResult.prepareVotes).toHaveLength(8);
    expect(spendResult.attestations).toHaveLength(8);
    expect(spendResult.shardPointers).toHaveLength(3);
    expect(intentStore.get(spendResult.txBinding)?.status).toBe('OUTPUTS_COMMITTED');
    nextLeafIndex += 2;

    const recovered = await recoverEncryptedThreadFromShards({
      peers,
      shardPointers: [spendResult.shardPointers[0]!, spendResult.shardPointers[2]!],
      threadKeyHex: spendResult.threadKeyHex,
    });
    expect(recovered.amount).toBe(secretAmount.toString());
    expect(recovered.memo).toBe(secretMemo);

    const bobBonus = await issueNoteToAllPeers({
      epoch: 0,
      txKind: 'mint',
      amount: 100n,
      recipientOwnerPk: bob.ownerPk,
    });
    const hop2 = await executeShieldedSpend({
      keys: bob,
      directory: activeDirectory,
      inputs: [
        {
          amount: BigInt(recovered.amount),
          blinding: BigInt(recovered.blinding),
          leafIndex: spendResult.outputLeafIndices[0],
        },
        {
          amount: 100n,
          blinding: bobBonus.blinding,
          leafIndex: bobBonus.leafIndex,
        },
      ],
      outputs: [
        { amount: 77_000_000n, recipientOwnerPk: carol.ownerPk },
        { amount: 432_200n, recipientOwnerPk: bob.ownerPk },
      ],
      fee: 9n,
    });
    expect(hop2.attestations).toHaveLength(8);
    nextLeafIndex += 2;

    for (const node of nodes) {
      const dump = await node.db.dumpAuditRows();
      const serializedDump = JSON.stringify(dump);

      expect(serializedDump).not.toContain(secretMemo);
      expect(serializedDump).not.toContain(secretAmount.toString());
      expect(serializedDump).not.toContain('80000000');
      expect(serializedDump).not.toContain('7567800');
      expect(serializedDump).not.toContain(alice.spendSecret.toString(16));
      expect(serializedDump).not.toContain(Buffer.from(alice.ed25519Sk).toString('hex'));
      expect(serializedDump).not.toContain(spendResult.threadKeyHex);

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

    const badRelay = await fetch(`${nodes[0]!.endpoint}/v1/relay`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/octet-stream' },
      body: randomBytes(ONION_PACKET_SIZE - 1),
    });
    expect(badRelay.status).toBe(400);
  });

  it('5. Tampered shard / forged PQ signature: flipping 1 byte in shard, Ed25519 sig, ML-DSA-65 sig, or proof -> rejected immediately', async () => {
    const alice = await generateWallet();

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

    const note0 = await issueNoteToAllPeers({
      epoch: 0,
      txKind: 'mint',
      amount: 250n,
      recipientOwnerPk: alice.ownerPk,
    });
    const note1 = await issueNoteToAllPeers({
      epoch: 0,
      txKind: 'mint',
      amount: 250n,
      recipientOwnerPk: alice.ownerPk,
    });
    const { tree } = await syncMerkleTreeFromPeers(peers);
    const proof0 = tree.getProof(note0.leafIndex);
    const proof1 = tree.getProof(note1.leafIndex);

    const outBlind = randomFieldElement();
    const feeBlind = randomFieldElement();
    const out0Commit = normalizeFieldHex(await computeCommitment(300n, alice.ownerPk, outBlind));
    const out1Commit = normalizeFieldHex(await computeCommitment(190n, alice.ownerPk, outBlind + 1n));
    const feeCommit = normalizeFieldHex(await computeFeeCommitment(10n, feeBlind));
    const txBinding = computeExpectedTxBinding({
      authPkHash: alice.authPkHash,
      merkleRoot: tree.getRootHex(),
      outputCommitments: [out0Commit, out1Commit],
      feeCommitment: feeCommit,
    });

    const proofBundle = await generateSpendProof({
      spendSecret: alice.spendSecret,
      inAmounts: [250n, 250n],
      inBlindings: [note0.blinding, note1.blinding],
      inLeafIndices: [note0.leafIndex, note1.leafIndex],
      inMerklePaths: [proof0.path, proof1.path],
      outAmounts: [300n, 190n],
      outOwnerPks: [alice.ownerPk, alice.ownerPk],
      outBlindings: [outBlind, outBlind + 1n],
      fee: 10n,
      feeBlinding: feeBlind,
      authPkHash: BigInt(alice.authPkHash),
      txBinding: BigInt(txBinding),
      merkleRoot: tree.getRoot(),
    });

    const validSig = signCanonicalMessage(
      spendStatementPayload(proofBundle.publicSignals),
      alice,
    );

    const edBytes = Buffer.from(validSig.ed25519Hex, 'hex');
    edBytes[0] = edBytes[0]! ^ 0x01;
    const forgedEdRes = await fetch(`${nodes[1]!.endpoint}/v1/witness/attest`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        epoch: 0,
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

    const pqBytes = Buffer.from(validSig.mldsa65B64, 'base64');
    pqBytes[10] = pqBytes[10]! ^ 0x01;
    const forgedPqRes = await fetch(`${nodes[1]!.endpoint}/v1/witness/attest`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        epoch: 0,
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

    const proofBytes = Buffer.from(proofBundle.proofBase64, 'base64');
    proofBytes[200] = proofBytes[200]! ^ 0x01;
    const forgedZkRes = await fetch(`${nodes[1]!.endpoint}/v1/witness/attest`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        epoch: 0,
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

    const noteCommit0 = await computeCommitment(250n, alice.ownerPk, note0.blinding);
    const leaf0 = await computeLeaf(noteCommit0, note0.leafIndex);
    const nullifier = await computeNullifier(alice.spendSecret, leaf0);
    const dumpAfterTamper = await nodes[1]!.db.dumpAuditRows();
    expect(
      dumpAfterTamper.spentNullifiers.some((r) => r.nullifier === normalizeFieldHex(nullifier)),
    ).toBe(false);
  });

  it('6. Quorum self-verification: non-quorum witness rejects prepare/attest with 403 NOT_IN_QUORUM', async () => {
    const alice = await generateWallet();
    const note0 = await issueNoteToAllPeers({
      epoch: 0,
      txKind: 'mint',
      amount: 120n,
      recipientOwnerPk: alice.ownerPk,
    });
    const note1 = await issueNoteToAllPeers({
      epoch: 0,
      txKind: 'mint',
      amount: 80n,
      recipientOwnerPk: alice.ownerPk,
    });
    const { tree } = await syncMerkleTreeFromPeers(peers);
    const blind0 = randomFieldElement();
    const blind1 = randomFieldElement();
    const feeBlind = randomFieldElement();
    const out0Commit = normalizeFieldHex(await computeCommitment(190n, alice.ownerPk, blind0));
    const out1Commit = normalizeFieldHex(await computeCommitment(0n, alice.ownerPk, blind1));
    const feeCommit = normalizeFieldHex(await computeFeeCommitment(10n, feeBlind));
    const txBinding = computeExpectedTxBinding({
      authPkHash: alice.authPkHash,
      merkleRoot: tree.getRootHex(),
      outputCommitments: [out0Commit, out1Commit],
      feeCommitment: feeCommit,
    });

    const bundle = await generateSpendProof({
      spendSecret: alice.spendSecret,
      inAmounts: [120n, 80n],
      inBlindings: [note0.blinding, note1.blinding],
      inLeafIndices: [note0.leafIndex, note1.leafIndex],
      inMerklePaths: [tree.getProof(note0.leafIndex).path, tree.getProof(note1.leafIndex).path],
      outAmounts: [190n, 0n],
      outOwnerPks: [alice.ownerPk, alice.ownerPk],
      outBlindings: [blind0, blind1],
      fee: 10n,
      feeBlinding: feeBlind,
      authPkHash: BigInt(alice.authPkHash),
      txBinding: BigInt(txBinding),
      merkleRoot: tree.getRoot(),
    });
    const sig = signCanonicalMessage(spendStatementPayload(bundle.publicSignals), alice);

    const quorum = selectWitnessQuorumForEpoch(
      0,
      bundle.publicSignals.nullifiers[0],
      peers,
      DEFAULT_QUORUM_SIZE,
    );
    const quorumIds = new Set(quorum.map((q) => q.peerId));
    const outsider = peers.find((p) => !quorumIds.has(p.peerId))!;
    expect(outsider).toBeDefined();

    const nonQuorumPrepare = await fetch(`${outsider.endpoint}/v1/witness/prepare`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        epoch: 0,
        proofBundle: bundle,
        spenderPub: { ed25519PkHex: alice.ed25519PkHex, mldsa65PkB64: alice.mldsa65PkB64 },
        spenderSig: sig,
      }),
    });
    expect(nonQuorumPrepare.status).toBe(403);
    expect(await nonQuorumPrepare.json()).toMatchObject({
      error: 'NOT_IN_QUORUM',
      peerId: outsider.peerId,
    });
  });

  it('7. Two-Phase crash & recovery: aborted partial prepare leaves notes spendable; partial commit recovers idempotently', async () => {
    const alice = await generateWallet();
    const bob = await generateWallet();
    const intentFile = join(tempDir, 'recovery-intents.json');

    // 7a. Simulate crash after preparing only 3 of 8 witnesses -> abort releases reservations cleanly
    const n0 = await issueNoteToAllPeers({
      epoch: 0,
      txKind: 'mint',
      amount: 700n,
      recipientOwnerPk: alice.ownerPk,
    });
    const n1 = await issueNoteToAllPeers({
      epoch: 0,
      txKind: 'mint',
      amount: 300n,
      recipientOwnerPk: alice.ownerPk,
    });

    const { tree } = await syncMerkleTreeFromPeers(peers);
    const b0 = randomFieldElement();
    const b1 = randomFieldElement();
    const fb = randomFieldElement();
    const oc0 = normalizeFieldHex(await computeCommitment(950n, bob.ownerPk, b0));
    const oc1 = normalizeFieldHex(await computeCommitment(40n, alice.ownerPk, b1));
    const fc = normalizeFieldHex(await computeFeeCommitment(10n, fb));
    const txBindingA = computeExpectedTxBinding({
      authPkHash: alice.authPkHash,
      merkleRoot: tree.getRootHex(),
      outputCommitments: [oc0, oc1],
      feeCommitment: fc,
    });

    const bundleA = await generateSpendProof({
      spendSecret: alice.spendSecret,
      inAmounts: [700n, 300n],
      inBlindings: [n0.blinding, n1.blinding],
      inLeafIndices: [n0.leafIndex, n1.leafIndex],
      inMerklePaths: [tree.getProof(n0.leafIndex).path, tree.getProof(n1.leafIndex).path],
      outAmounts: [950n, 40n],
      outOwnerPks: [bob.ownerPk, alice.ownerPk],
      outBlindings: [b0, b1],
      fee: 10n,
      feeBlinding: fb,
      authPkHash: BigInt(alice.authPkHash),
      txBinding: BigInt(txBindingA),
      merkleRoot: tree.getRoot(),
    });
    const sigA = signCanonicalMessage(spendStatementPayload(bundleA.publicSignals), alice);
    const quorumA = selectWitnessQuorumForEpoch(
      0,
      bundleA.publicSignals.nullifiers[0],
      peers,
      DEFAULT_QUORUM_SIZE,
    );

    const partialVotes: PrepareVote[] = [];
    for (const w of quorumA.slice(0, 3)) {
      const r = await sendViaThreeHopOnion<{ state: string; prepareVote: PrepareVote }>({
        peers,
        targetPeer: w,
        method: 'POST',
        path: '/v1/witness/prepare',
        body: {
          epoch: 0,
          proofBundle: bundleA,
          spenderPub: { ed25519PkHex: alice.ed25519PkHex, mldsa65PkB64: alice.mldsa65PkB64 },
          spenderSig: sigA,
        },
      });
      partialVotes.push(r.data.prepareVote);
    }

    const storeWriter = new SpendIntentStore(intentFile);
    storeWriter.upsert({
      version: 1,
      txBinding: txBindingA,
      epoch: 0,
      status: 'CREATED',
      quorumPeerIds: quorumA.map((p) => p.peerId),
      proofBundle: bundleA,
      spenderPub: { ed25519PkHex: alice.ed25519PkHex, mldsa65PkB64: alice.mldsa65PkB64 },
      spenderSig: sigA,
      prepareVotes: partialVotes,
      attestations: [],
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    });

    // Reload persisted intent journal from disk (simulating process restart) and recover -> ABORTED
    const reloadedStore = new SpendIntentStore(intentFile);
    const abortOutcome = await recoverSpendIntent({
      intentStore: reloadedStore,
      txBinding: txBindingA,
      keys: alice,
      directory: activeDirectory,
    });
    expect(abortOutcome.action).toBe('ABORTED');
    expect(abortOutcome.releasedReservations).toBe(6);

    // Notes were NOT burned — a fresh full spend of the exact same notes now succeeds!
    const recoveredSpend = await executeShieldedSpend({
      keys: alice,
      directory: activeDirectory,
      intentStore: reloadedStore,
      inputs: [
        { amount: 700n, blinding: n0.blinding, leafIndex: n0.leafIndex },
        { amount: 300n, blinding: n1.blinding, leafIndex: n1.leafIndex },
      ],
      outputs: [
        { amount: 900n, recipientOwnerPk: bob.ownerPk, memo: 'reclaimed-after-abort' },
        { amount: 90n, recipientOwnerPk: alice.ownerPk },
      ],
      fee: 10n,
    });
    expect(recoveredSpend.attestations).toHaveLength(8);
    nextLeafIndex += 2;

    // 7b. Crash after 8 prepares + 2 partial commits -> recovers remaining 6 commits + idempotent retry on first 2
    const c0 = await issueNoteToAllPeers({
      epoch: 0,
      txKind: 'mint',
      amount: 400n,
      recipientOwnerPk: alice.ownerPk,
    });
    const c1 = await issueNoteToAllPeers({
      epoch: 0,
      txKind: 'mint',
      amount: 600n,
      recipientOwnerPk: alice.ownerPk,
    });
    const { tree: treeB } = await syncMerkleTreeFromPeers(peers);
    const cb0 = randomFieldElement();
    const cb1 = randomFieldElement();
    const cfb = randomFieldElement();
    const coc0 = normalizeFieldHex(await computeCommitment(850n, bob.ownerPk, cb0));
    const coc1 = normalizeFieldHex(await computeCommitment(140n, alice.ownerPk, cb1));
    const cfc = normalizeFieldHex(await computeFeeCommitment(10n, cfb));
    const txBindingB = computeExpectedTxBinding({
      authPkHash: alice.authPkHash,
      merkleRoot: treeB.getRootHex(),
      outputCommitments: [coc0, coc1],
      feeCommitment: cfc,
    });
    const bundleB = await generateSpendProof({
      spendSecret: alice.spendSecret,
      inAmounts: [400n, 600n],
      inBlindings: [c0.blinding, c1.blinding],
      inLeafIndices: [c0.leafIndex, c1.leafIndex],
      inMerklePaths: [treeB.getProof(c0.leafIndex).path, treeB.getProof(c1.leafIndex).path],
      outAmounts: [850n, 140n],
      outOwnerPks: [bob.ownerPk, alice.ownerPk],
      outBlindings: [cb0, cb1],
      fee: 10n,
      feeBlinding: cfb,
      authPkHash: BigInt(alice.authPkHash),
      txBinding: BigInt(txBindingB),
      merkleRoot: treeB.getRoot(),
    });
    const sigB = signCanonicalMessage(spendStatementPayload(bundleB.publicSignals), alice);
    const quorumB = selectWitnessQuorumForEpoch(
      0,
      bundleB.publicSignals.nullifiers[0],
      peers,
      DEFAULT_QUORUM_SIZE,
    );

    const fullPrepareVotes: PrepareVote[] = [];
    for (const w of quorumB) {
      const r = await sendViaThreeHopOnion<{ prepareVote: PrepareVote }>({
        peers,
        targetPeer: w,
        method: 'POST',
        path: '/v1/witness/prepare',
        body: {
          epoch: 0,
          proofBundle: bundleB,
          spenderPub: { ed25519PkHex: alice.ed25519PkHex, mldsa65PkB64: alice.mldsa65PkB64 },
          spenderSig: sigB,
        },
      });
      fullPrepareVotes.push(r.data.prepareVote);
    }

    // Commit ONLY to the first 2 witnesses before simulating crash (and DO NOT cache them locally, forcing idempotent commit retry!)
    for (const w of quorumB.slice(0, 2)) {
      const cRes = await sendViaThreeHopOnion<{ idempotent: boolean; attestation: unknown }>({
        peers,
        targetPeer: w,
        method: 'POST',
        path: '/v1/witness/commit',
        body: {
          epoch: 0,
          proofBundle: bundleB,
          spenderPub: { ed25519PkHex: alice.ed25519PkHex, mldsa65PkB64: alice.mldsa65PkB64 },
          spenderSig: sigB,
          prepareVotes: fullPrepareVotes,
        },
      });
      expect(cRes.data.idempotent).toBe(false);
    }

    reloadedStore.upsert({
      version: 1,
      txBinding: txBindingB,
      epoch: 0,
      status: 'PREPARED',
      quorumPeerIds: quorumB.map((p) => p.peerId),
      proofBundle: bundleB,
      spenderPub: { ed25519PkHex: alice.ed25519PkHex, mldsa65PkB64: alice.mldsa65PkB64 },
      spenderSig: sigB,
      prepareVotes: fullPrepareVotes,
      attestations: [],
      outputSpecs: [
        {
          amount: '850',
          recipientOwnerPk: bob.ownerPkHex,
          blinding: normalizeFieldHex(cb0),
          memo: 'recovered-from-partial-commit',
        },
        {
          amount: '140',
          recipientOwnerPk: alice.ownerPkHex,
          blinding: normalizeFieldHex(cb1),
        },
      ],
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    });

    const restartedStore = new SpendIntentStore(intentFile);
    const completeOutcome = await recoverSpendIntent({
      intentStore: restartedStore,
      txBinding: txBindingB,
      keys: alice,
      directory: activeDirectory,
    });
    expect(completeOutcome.action).toBe('COMPLETED');
    expect(completeOutcome.result?.attestations).toHaveLength(8);
    expect(completeOutcome.result?.shardPointers).toHaveLength(3);
    nextLeafIndex += 2;
  });

  it('8. Equivocation proof, witness slashing & governance epoch rotation (replacing slashed witness)', async () => {
    const rogueWitness = nodes[NODE_COUNT - 1]!; // witness-11
    const roguePeerId = rogueWitness.getSignedIdentity().peerId;
    const rogueKeys = generateNodeKeypair(roguePeerId, Buffer.from(`test-seed-${String(NODE_COUNT).padStart(2, '0')}`, 'utf8'));

    // Build two conflicting signed chained checkpoints at (epoch: 0, seq: 99) for rogueWitness
    const baseA = {
      epoch: 0,
      seq: 99,
      prevHash: '1'.repeat(64),
      stateRoot: normalizeFieldHex(1111n),
      txBinding: normalizeFieldHex(2222n),
      treeSize: 10,
      witnessPeerId: roguePeerId,
    };
    const baseB = {
      epoch: 0,
      seq: 99,
      prevHash: '1'.repeat(64),
      stateRoot: normalizeFieldHex(3333n),
      txBinding: normalizeFieldHex(4444n),
      treeSize: 10,
      witnessPeerId: roguePeerId,
    };
    const cpA: ChainedWitnessCheckpoint = {
      ...baseA,
      checkpointHash: computeChainedCheckpointHash(baseA),
      ed25519PkHex: Buffer.from(rogueKeys.ed25519Pk).toString('hex'),
      mldsa65PkB64: Buffer.from(rogueKeys.mldsa65Pk).toString('base64'),
      sig: signHybrid(
        JSON.stringify([
          'NUV_CHECKPOINT_CHAIN_V1',
          baseA.epoch,
          baseA.seq,
          baseA.prevHash,
          baseA.stateRoot,
          baseA.txBinding,
          baseA.treeSize,
          baseA.witnessPeerId,
        ]),
        rogueKeys.ed25519Sk,
        rogueKeys.mldsa65Sk,
      ),
      createdAt: new Date().toISOString(),
    };
    const cpB: ChainedWitnessCheckpoint = {
      ...baseB,
      checkpointHash: computeChainedCheckpointHash(baseB),
      ed25519PkHex: Buffer.from(rogueKeys.ed25519Pk).toString('hex'),
      mldsa65PkB64: Buffer.from(rogueKeys.mldsa65Pk).toString('base64'),
      sig: signHybrid(
        JSON.stringify([
          'NUV_CHECKPOINT_CHAIN_V1',
          baseB.epoch,
          baseB.seq,
          baseB.prevHash,
          baseB.stateRoot,
          baseB.txBinding,
          baseB.treeSize,
          baseB.witnessPeerId,
        ]),
        rogueKeys.ed25519Sk,
        rogueKeys.mldsa65Sk,
      ),
      createdAt: new Date().toISOString(),
    };

    const equivProof: EquivocationProof = {
      kind: 'CHECKPOINT_FORK',
      witnessPeerId: roguePeerId,
      first: cpA,
      second: cpB,
    };

    const healthyNodes = nodes.slice(0, NODE_COUNT - 1);
    const slashResults = await submitEquivocationProof(
      healthyNodes.map((n) => n.endpoint),
      equivProof,
    );
    expect(slashResults.every((r) => r.slashed)).toBe(true);
    const proofHash = slashResults[0]!.proofHash;

    // Boot authentic replacement node witness-12 with synced tree state via DB schema?
    // Start witness-12 cleanly and have governance reject keeping slashed witness-11 first:
    const badEpoch1 = createSignedEpochDirectory({
      epoch: 1,
      quorumSize: DEFAULT_QUORUM_SIZE,
      nullifierEpochRetention: 4,
      previousDirectorySha256: activeDirectoryHash,
      members: nodes.map((n) => toEpochMember(n, 0)),
      governanceSigners: [govKeypair],
    });
    const rejectedDirResp = await fetch(`${healthyNodes[0]!.endpoint}/v1/governance/epoch`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(badEpoch1),
    });
    expect(rejectedDirResp.status).toBe(403);
    expect(await rejectedDirResp.json()).toMatchObject({
      error: 'SLASHED_WITNESS_IN_DIRECTORY',
      peerId: roguePeerId,
    });

    // Boot standby witness-12 and replay existing commitments so it joins in full sync
    const w12Keypair = generateNodeKeypair('witness-12', Buffer.from('test-seed-12', 'utf8'));
    const trustedIssuers = [
      {
        ed25519PkHex: Buffer.from(issuerKeypair.ed25519Pk).toString('hex'),
        mldsa65PkB64: Buffer.from(issuerKeypair.mldsa65Pk).toString('base64'),
      },
    ];
    const trustedGovernanceKeys = [
      {
        ed25519PkHex: Buffer.from(govKeypair.ed25519Pk).toString('hex'),
        mldsa65PkB64: Buffer.from(govKeypair.mldsa65Pk).toString('base64'),
      },
    ];
    const w12 = new NuvertherNode({
      peerId: 'witness-12',
      host: '127.0.0.1',
      port: 0,
      databaseUrl: DATABASE_URL,
      dbSchema: `${TEST_SCHEMA_PREFIX}12`,
      keypair: w12Keypair,
      trustedIssuers,
      trustedGovernanceKeys,
      governanceThreshold: 1,
      hashcashBits: 10,
      allowLoopbackPeers: true,
      rateLimitCapacity: 5000,
      rateLimitRefillPerSec: 2500,
      logLevel: 'silent',
    });
    await w12.start();
    extraNodes.push(w12);

    const newCommitteeNodes = [...healthyNodes, w12];
    const epoch1Dir = createSignedEpochDirectory({
      epoch: 1,
      quorumSize: DEFAULT_QUORUM_SIZE,
      nullifierEpochRetention: 4,
      previousDirectorySha256: activeDirectoryHash,
      members: newCommitteeNodes.map((n, idx) => toEpochMember(n, idx === newCommitteeNodes.length - 1 ? 1 : 0)),
      revokedPeers: [
        {
          peerId: roguePeerId,
          revokedAtEpoch: 1,
          reason: 'PROVEN_CHECKPOINT_EQUIVOCATION',
          equivocationProofHash: proofHash,
        },
      ],
      governanceSigners: [govKeypair],
    });
    await broadcastEpochDirectory(
      newCommitteeNodes.map((n) => n.endpoint),
      epoch1Dir,
    );
    activeDirectory = epoch1Dir;
    activeDirectoryHash = computeEpochDirectoryHash(epoch1Dir);
    peers = epoch1Dir.members;

    // Verify metrics & governance endpoint record slashing + epoch 1 activation
    const govStateResp = await fetch(`${healthyNodes[0]!.endpoint}/v1/governance/epoch`);
    const govState = (await govStateResp.json()) as {
      activeEpoch: number;
      slashedPeers: string[];
      equivocations: Array<{ proofHash: string; witnessPeerId: string }>;
    };
    expect(govState.activeEpoch).toBe(1);
    expect(govState.slashedPeers).toContain(roguePeerId);
    expect(govState.equivocations.some((e) => e.witnessPeerId === roguePeerId)).toBe(true);
  });

  it('9. Bounded nullifier storage: advancing epochs prunes expired nullifier epochs and rejects stale-epoch spends', async () => {
    const healthyNodes = nodes.slice(0, NODE_COUNT - 1);
    const committeeNodes = [...healthyNodes, ...extraNodes];
    const epoch0AuditBefore = await healthyNodes[0]!.db.dumpAuditRows();
    const epoch0CountBefore = epoch0AuditBefore.spentNullifiers.filter(
      (r) => Number(r.epoch) === 0,
    ).length;
    expect(epoch0CountBefore).toBeGreaterThan(0);

    // Advance epochs 2 -> 5 with nullifierEpochRetention = 4 so minRetainedEpoch = 5 - 4 = 1 (epoch 0 pruned!)
    let prevDir = activeDirectory;
    let prevHash = activeDirectoryHash;
    for (let ep = 2; ep <= 5; ep++) {
      const nextDir = createSignedEpochDirectory({
        epoch: ep,
        quorumSize: prevDir.quorumSize,
        nullifierEpochRetention: 4,
        previousDirectorySha256: prevHash,
        members: prevDir.members,
        revokedPeers: prevDir.revokedPeers,
        governanceSigners: [govKeypair],
      });
      await broadcastEpochDirectory(
        committeeNodes.map((n) => n.endpoint),
        nextDir,
      );
      prevDir = nextDir;
      prevHash = computeEpochDirectoryHash(nextDir);
    }
    activeDirectory = prevDir;
    activeDirectoryHash = prevHash;

    // Verify epoch 0 nullifiers were automatically pruned from PostgreSQL
    const auditAfter = await healthyNodes[0]!.db.dumpAuditRows();
    const remainingEpoch0 = auditAfter.spentNullifiers.filter((r) => Number(r.epoch) === 0);
    expect(remainingEpoch0).toHaveLength(0);

    // Verify spends claiming stale epoch 0 are rejected with 403 EPOCH_EXPIRED
    const alice = await generateWallet();
    const dummyRes = await fetch(`${healthyNodes[0]!.endpoint}/v1/witness/prepare`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        epoch: 0,
        proofBundle: {
          proofBase64: Buffer.from(randomBytes(64)).toString('base64'),
          publicInputs: Array.from({ length: 8 }, () => '0x01'),
          publicSignals: {
            merkleRoot: '0x01',
            nullifiers: ['0x01', '0x02'],
            outputCommitments: ['0x03', '0x04'],
            feeCommitment: '0x05',
            authPkHash: alice.authPkHash,
            txBinding: '0x06',
          },
          vkSha256: 'a'.repeat(64),
        },
        spenderPub: {
          ed25519PkHex: alice.ed25519PkHex,
          mldsa65PkB64: alice.mldsa65PkB64,
        },
        spenderSig: signCanonicalMessage('stale-epoch-test', alice),
      }),
    });
    expect(dummyRes.status).toBe(403);
    expect(await dummyRes.json()).toMatchObject({ error: 'EPOCH_EXPIRED' });
  });
});

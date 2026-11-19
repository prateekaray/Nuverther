import { randomBytes, randomInt } from 'node:crypto';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { combine, split } from 'shamir-secret-sharing';
import {
  Poseidon2MerkleTree,
  computeCommitment,
  computeFeeCommitment,
  generateSpendProof,
  normalizeFieldHex,
  randomFieldElement,
  type SpendProofBundle,
} from '@nuverther/zk';
import {
  CHUNK_FRAME_HEADER_SIZE,
  DEFAULT_QUORUM_SIZE,
  DEFAULT_RELAY_POW_BITS,
  ONION_MAX_CHUNK_DATA_SIZE,
  ONION_PACKET_SIZE,
  abortRequestSigningPayload,
  attestationSigningPayload,
  computeEpochDirectoryHash,
  computeExpectedTxBinding,
  computeShardMacTag,
  deriveChunkMsgId,
  prepareVoteSigningPayload,
  selectWitnessQuorumForEpoch,
  sha3Digest,
  sha3Hex,
  spendStatementPayload,
  verifyHybrid,
  verifySignedEpochDirectory,
  wrapOnionPacket,
  type BlindShardRecord,
  type EpochWitnessMember,
  type EquivocationProof,
  type HybridPublicKeys,
  type OnionHopTarget,
  type PrepareVote,
  type SignedEpochDirectory,
  type SignedIssuanceRecord,
  type WitnessAttestation,
} from '@nuverther/node';
import { signCanonicalMessage, type NuvertherWalletKeys } from './custody.ts';
import type { SpendIntentRecord, SpendIntentStore } from './intentStore.ts';

export type PeerTransportInfo = Pick<
  EpochWitnessMember,
  'peerId' | 'endpoint' | 'ed25519PkHex' | 'mldsa65PkB64' | 'x25519PkHex'
>;

export interface ShieldedNoteInput {
  amount: bigint;
  blinding: bigint;
  leafIndex: number;
}

export interface ShieldedOutputSpec {
  amount: bigint;
  recipientOwnerPk: bigint;
  blinding?: bigint;
  memo?: string;
}

export interface ThreadPayload {
  version: 2;
  noteNonce: string;
  recipientOwnerPk: string;
  amount: string;
  blinding: string;
  leafIndex?: number;
  noteCommitment?: string;
  memo?: string;
  createdAt: string;
}

export interface StoredShardPointer {
  peerId: string;
  endpoint: string;
  shardId: string;
  shareIndex: number;
  shareKeyHex: string;
}

export interface ShieldedSpendResult {
  epoch: number;
  txBinding: string;
  proofBundle: SpendProofBundle;
  quorumWitnesses: string[];
  prepareVotes: PrepareVote[];
  attestations: WitnessAttestation[];
  threadKeyHex: string;
  threadDigest: string;
  shardPointers: StoredShardPointer[];
  outputCommitments: [string, string];
  outputBlindings: [bigint, bigint];
  outputLeafIndices: [number, number];
  newMerkleRoot: string;
}

export class NuvertherProtocolError extends Error {
  public readonly code: string;
  public readonly status: number;

  constructor(code: string, status: number, message: string) {
    super(message);
    this.name = 'NuvertherProtocolError';
    this.code = code;
    this.status = status;
  }
}

export async function retryWithBackoffAndJitter<T>(
  fn: () => Promise<T>,
  options: { maxAttempts?: number; baseMs?: number; capMs?: number } = {},
): Promise<T> {
  const maxAttempts = options.maxAttempts ?? 4;
  const baseMs = options.baseMs ?? 60;
  const capMs = options.capMs ?? 1500;

  let lastError: unknown;
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    try {
      return await fn();
    } catch (err) {
      lastError = err;
      if (
        err instanceof NuvertherProtocolError &&
        err.status >= 400 &&
        err.status < 500 &&
        err.status !== 429
      ) {
        throw err;
      }
      if (attempt === maxAttempts - 1) {
        break;
      }
      const ceiling = Math.min(capMs, baseMs * 2 ** attempt);
      const delayMs = Math.floor(Math.random() * ceiling) + 10;
      await new Promise((resolve) => setTimeout(resolve, delayMs));
    }
  }
  throw lastError instanceof Error ? lastError : new Error(String(lastError));
}

export async function discoverEpochDirectory(
  seedUrls: readonly string[],
  trustedGovernanceKeys?: readonly HybridPublicKeys[],
  governanceThreshold = 1,
): Promise<{
  directory: SignedEpochDirectory;
  directoryHash: string;
  slashedPeers: string[];
}> {
  const validCandidates: Array<{
    directory: SignedEpochDirectory;
    directoryHash: string;
    slashedPeers: string[];
  }> = [];

  await Promise.all(
    seedUrls.map(async (url) => {
      try {
        const resp = await fetch(`${url}/v1/governance/epoch`);
        if (!resp.ok) return;
        const data = (await resp.json()) as {
          activeEpoch: number | null;
          directoryHash: string | null;
          directory: SignedEpochDirectory | null;
          slashedPeers?: string[];
        };
        if (!data.directory) return;
        if (
          trustedGovernanceKeys &&
          trustedGovernanceKeys.length > 0 &&
          !verifySignedEpochDirectory(data.directory, trustedGovernanceKeys, governanceThreshold)
        ) {
          return;
        }
        const computedHash = computeEpochDirectoryHash(data.directory);
        if (data.directoryHash && data.directoryHash !== computedHash) {
          return;
        }
        validCandidates.push({
          directory: data.directory,
          directoryHash: computedHash,
          slashedPeers: data.slashedPeers ?? [],
        });
      } catch {
        // Ignore unreachable seed during directory discovery
      }
    }),
  );

  if (validCandidates.length === 0) {
    throw new NuvertherProtocolError(
      'NO_VALID_EPOCH_DIRECTORY',
      503,
      'No signed epoch directory discovered from seed peers',
    );
  }

  validCandidates.sort((a, b) => b.directory.epoch - a.directory.epoch);
  const latest = validCandidates[0]!;
  const allSlashed = new Set<string>();
  for (const cand of validCandidates) {
    if (cand.directory.epoch === latest.directory.epoch && cand.directoryHash !== latest.directoryHash) {
      throw new NuvertherProtocolError(
        'EPOCH_DIRECTORY_DIVERGENCE',
        502,
        `Seeds disagreed on signed directory hash for epoch ${latest.directory.epoch}`,
      );
    }
    for (const s of cand.slashedPeers) {
      allSlashed.add(s);
    }
  }

  return {
    directory: latest.directory,
    directoryHash: latest.directoryHash,
    slashedPeers: [...allSlashed],
  };
}

export async function discoverVerifiedPeers(
  seedUrls: readonly string[],
  trustedGovernanceKeys?: readonly HybridPublicKeys[],
  governanceThreshold = 1,
): Promise<EpochWitnessMember[]> {
  const { directory, slashedPeers } = await discoverEpochDirectory(
    seedUrls,
    trustedGovernanceKeys,
    governanceThreshold,
  );
  const slashedSet = new Set(slashedPeers);
  return directory.members
    .filter((m) => !slashedSet.has(m.peerId))
    .sort((a, b) => a.peerId.localeCompare(b.peerId));
}

export async function broadcastEpochDirectory(
  peerUrls: readonly string[],
  directory: SignedEpochDirectory,
): Promise<void> {
  await Promise.all(
    peerUrls.map((url) =>
      retryWithBackoffAndJitter(async () => {
        const res = await fetch(`${url}/v1/governance/epoch`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(directory),
        });
        if (!res.ok) {
          const text = await res.text();
          throw new NuvertherProtocolError('EPOCH_ACTIVATION_REJECTED', res.status, text);
        }
      }),
    ),
  );
}

export async function submitEquivocationProof(
  peerUrls: readonly string[],
  proof: EquivocationProof,
): Promise<Array<{ peerUrl: string; slashed: boolean; proofHash: string }>> {
  const results = await Promise.all(
    peerUrls.map(async (peerUrl) => {
      const res = await fetch(`${peerUrl}/v1/governance/equivocation`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(proof),
      });
      const text = await res.text();
      if (!res.ok) {
        throw new NuvertherProtocolError('EQUIVOCATION_REJECTED', res.status, text);
      }
      const json = JSON.parse(text) as { slashed: boolean; proofHash: string };
      return { peerUrl, ...json };
    }),
  );
  return results;
}

export function selectRandomThreeHops<T extends PeerTransportInfo>(
  peers: readonly T[],
  excludePeerId?: string,
): [T, T, T] {
  const candidates = peers.filter((p) => p.peerId !== excludePeerId);
  const pool = candidates.length >= 3 ? [...candidates] : [...peers];
  if (pool.length < 3) {
    throw new Error(`Need at least 3 peers for 3-hop onion circuit, found ${pool.length}`);
  }
  for (let i = pool.length - 1; i > 0; i--) {
    const j = randomInt(0, i + 1);
    const tmp = pool[i]!;
    pool[i] = pool[j]!;
    pool[j] = tmp;
  }
  return [pool[0]!, pool[1]!, pool[2]!];
}

export async function sendViaThreeHopOnion<TResponse = unknown>(params: {
  peers: readonly PeerTransportInfo[];
  targetPeer: PeerTransportInfo;
  method: 'GET' | 'POST';
  path: string;
  body?: unknown;
  relayPowBits?: number;
}): Promise<{ status: number; data: TResponse }> {
  const hops = selectRandomThreeHops(params.peers, params.targetPeer.peerId);
  const hopTargets: [OnionHopTarget, OnionHopTarget, OnionHopTarget] = [
    { x25519PkHex: hops[0].x25519PkHex, hopUrl: hops[0].endpoint },
    { x25519PkHex: hops[1].x25519PkHex, hopUrl: hops[1].endpoint },
    { x25519PkHex: hops[2].x25519PkHex, hopUrl: hops[2].endpoint },
  ];

  const envelopeBytes = Buffer.from(
    JSON.stringify({ method: params.method, path: params.path, body: params.body }),
    'utf8',
  );

  const singleCellLimit = ONION_MAX_CHUNK_DATA_SIZE - 1;
  const frames: Buffer[] = [];

  if (envelopeBytes.length <= singleCellLimit) {
    frames.push(Buffer.concat([Buffer.from([0x01]), envelopeBytes]));
  } else {
    const chunkPayloadLimit = ONION_MAX_CHUNK_DATA_SIZE - CHUNK_FRAME_HEADER_SIZE;
    const msgSecret = randomBytes(32);
    const msgId = Buffer.from(deriveChunkMsgId(msgSecret));
    const msgSha3 = Buffer.from(sha3Digest(envelopeBytes));
    const totalChunks = Math.ceil(envelopeBytes.length / chunkPayloadLimit);
    if (totalChunks > 16) {
      throw new Error(`Payload exceeds maximum 16-cell onion limit (${envelopeBytes.length} bytes)`);
    }
    for (let i = 0; i < totalChunks; i++) {
      const slice = envelopeBytes.subarray(i * chunkPayloadLimit, (i + 1) * chunkPayloadLimit);
      const header = Buffer.alloc(CHUNK_FRAME_HEADER_SIZE);
      header[0] = 0x02;
      msgId.copy(header, 1);
      header[17] = i;
      header[18] = totalChunks;
      msgSecret.copy(header, 19);
      msgSha3.copy(header, 51);
      frames.push(Buffer.concat([header, slice]));
    }
  }

  let finalStatus = 500;
  let finalRaw = '';
  const relayPowBits = params.relayPowBits ?? DEFAULT_RELAY_POW_BITS;

  for (const frame of frames) {
    const packet = wrapOnionPacket(hopTargets, params.targetPeer.endpoint, frame, {
      relayPowBits,
    });
    if (packet.length !== ONION_PACKET_SIZE) {
      throw new Error(`Invariant failure: onion packet length ${packet.length} !== ${ONION_PACKET_SIZE}`);
    }

    const resp = await fetch(`${hops[0].endpoint}/v1/relay`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/octet-stream',
        'Content-Length': String(ONION_PACKET_SIZE),
      },
      body: Buffer.from(packet),
    });

    finalStatus = resp.status;
    finalRaw = await resp.text();
    if (resp.status >= 400 && resp.status !== 202) {
      let code = 'ONION_TARGET_ERROR';
      try {
        const parsedErr = JSON.parse(finalRaw) as { error?: string };
        if (parsedErr.error) code = parsedErr.error;
      } catch {
        // non-JSON response
      }
      throw new NuvertherProtocolError(code, resp.status, `${code} (${resp.status}): ${finalRaw}`);
    }
  }

  const data = (finalRaw ? JSON.parse(finalRaw) : {}) as TResponse;
  return { status: finalStatus, data };
}

export async function sendCoverTrafficCell(params: {
  peers: readonly PeerTransportInfo[];
  relayPowBits?: number;
}): Promise<number> {
  const hops = selectRandomThreeHops(params.peers);
  const hopTargets: [OnionHopTarget, OnionHopTarget, OnionHopTarget] = [
    { x25519PkHex: hops[0].x25519PkHex, hopUrl: hops[0].endpoint },
    { x25519PkHex: hops[1].x25519PkHex, hopUrl: hops[1].endpoint },
    { x25519PkHex: hops[2].x25519PkHex, hopUrl: hops[2].endpoint },
  ];
  const padPayload = Buffer.concat([Buffer.from([0x03]), randomBytes(256)]);
  const packet = wrapOnionPacket(hopTargets, hops[2].endpoint, padPayload, {
    relayPowBits: params.relayPowBits ?? DEFAULT_RELAY_POW_BITS,
  });
  const resp = await fetch(`${hops[0].endpoint}/v1/relay`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/octet-stream',
      'Content-Length': String(ONION_PACKET_SIZE),
    },
    body: Buffer.from(packet),
  });
  return resp.status;
}

export async function storeEncryptedThreadShards(params: {
  peers: readonly PeerTransportInfo[];
  payload: ThreadPayload;
}): Promise<{
  threadKeyHex: string;
  threadDigest: string;
  shardPointers: StoredShardPointer[];
}> {
  if (params.peers.length < 3) {
    throw new Error('At least 3 storage peers required for 2-of-3 Shamir shards');
  }

  const threadKey = new Uint8Array(randomBytes(32));
  const threadNonce = new Uint8Array(randomBytes(24));
  const plaintext = new TextEncoder().encode(JSON.stringify(params.payload));
  const cipher = xchacha20poly1305(threadKey, threadNonce).encrypt(plaintext);
  const sealedEnvelope = new Uint8Array(24 + cipher.length);
  sealedEnvelope.set(threadNonce, 0);
  sealedEnvelope.set(cipher, 24);

  const threadDigest = sha3Hex(sealedEnvelope);
  const shamirShares = await split(sealedEnvelope, 3, 2);

  const storagePeers = selectRandomThreeHops(params.peers);
  const shardPointers: StoredShardPointer[] = [];

  await Promise.all(
    shamirShares.map(async (shareBytes, idx) => {
      const shareIndex = idx + 1;
      const peer = storagePeers[idx]!;
      const shareKey = new Uint8Array(randomBytes(32));
      const shareNonce = new Uint8Array(randomBytes(24));
      const encryptedShare = xchacha20poly1305(shareKey, shareNonce).encrypt(shareBytes);

      const shardId = sha3Hex(`${threadDigest}:${shareIndex}:${peer.peerId}`);
      const nonceHex = Buffer.from(shareNonce).toString('hex');
      const ciphertextB64 = Buffer.from(encryptedShare).toString('base64');
      const macTagHex = computeShardMacTag({
        shardId,
        threadDigest,
        shareIndex,
        nonceHex,
        ciphertextB64,
      });

      await retryWithBackoffAndJitter(async () => {
        await sendViaThreeHopOnion({
          peers: params.peers,
          targetPeer: peer,
          method: 'POST',
          path: '/v1/shards',
          body: {
            shardId,
            threadDigest,
            shareIndex,
            nonceHex,
            ciphertextB64,
            macTagHex,
          },
        });
      });

      shardPointers.push({
        peerId: peer.peerId,
        endpoint: peer.endpoint,
        shardId,
        shareIndex,
        shareKeyHex: Buffer.from(shareKey).toString('hex'),
      });
    }),
  );

  return {
    threadKeyHex: Buffer.from(threadKey).toString('hex'),
    threadDigest,
    shardPointers,
  };
}

export async function recoverEncryptedThreadFromShards(params: {
  peers: readonly PeerTransportInfo[];
  shardPointers: StoredShardPointer[];
  threadKeyHex: string;
}): Promise<ThreadPayload> {
  const recoveredShares: Uint8Array[] = [];

  for (const pointer of params.shardPointers) {
    if (recoveredShares.length >= 2) break;
    const targetPeer = params.peers.find((p) => p.peerId === pointer.peerId);
    if (!targetPeer) continue;

    try {
      const { data } = await sendViaThreeHopOnion<{ shard: BlindShardRecord }>({
        peers: params.peers,
        targetPeer,
        method: 'GET',
        path: `/v1/shards/${pointer.shardId}`,
      });

      const shard = data.shard;
      const expectedMac = computeShardMacTag(shard);
      if (shard.macTagHex !== expectedMac) {
        throw new Error(`Shard ${pointer.shardId} MAC verification failed`);
      }

      const shareKey = new Uint8Array(Buffer.from(pointer.shareKeyHex, 'hex'));
      const shareNonce = new Uint8Array(Buffer.from(shard.nonceHex, 'hex'));
      const encryptedShare = new Uint8Array(Buffer.from(shard.ciphertextB64, 'base64'));
      const decryptedShare = xchacha20poly1305(shareKey, shareNonce).decrypt(encryptedShare);
      recoveredShares.push(decryptedShare);
    } catch {
      // Try next available share (2-of-3 tolerance)
    }
  }

  if (recoveredShares.length < 2) {
    throw new Error(`Unable to recover 2-of-3 valid Shamir shards (got ${recoveredShares.length})`);
  }

  const sealedEnvelope = await combine(recoveredShares.slice(0, 2));
  const threadNonce = sealedEnvelope.subarray(0, 24);
  const cipher = sealedEnvelope.subarray(24);
  const threadKey = new Uint8Array(Buffer.from(params.threadKeyHex, 'hex'));
  const plaintext = xchacha20poly1305(threadKey, threadNonce).decrypt(cipher);
  return JSON.parse(new TextDecoder().decode(plaintext)) as ThreadPayload;
}

export async function syncMerkleTreeFromPeers(
  peers: readonly PeerTransportInfo[],
): Promise<{ tree: Poseidon2MerkleTree; merkleRoot: string }> {
  if (peers.length === 0) {
    throw new Error('Cannot sync Merkle tree without peers');
  }
  const resp = await retryWithBackoffAndJitter(async () => {
    const r = await fetch(`${peers[0]!.endpoint}/v1/tree/commitments`);
    if (!r.ok) {
      throw new NuvertherProtocolError('SYNC_COMMITMENTS_FAILED', r.status, `HTTP ${r.status}`);
    }
    return (await r.json()) as {
      treeSize: number;
      merkleRoot: string | null;
      commitments: Array<{ leafIndex: number; noteCommitment: string }>;
    };
  });

  const sorted = [...resp.commitments].sort((a, b) => a.leafIndex - b.leafIndex);
  const tree = await Poseidon2MerkleTree.create(sorted.map((c) => BigInt(c.noteCommitment)));
  const merkleRoot = tree.getRootHex();
  if (resp.merkleRoot && normalizeFieldHex(resp.merkleRoot) !== merkleRoot) {
    throw new NuvertherProtocolError(
      'MERKLE_ROOT_SYNC_MISMATCH',
      502,
      `Synced tree root ${merkleRoot} !== node reported root ${resp.merkleRoot}`,
    );
  }
  return { tree, merkleRoot };
}

export async function broadcastSignedIssuance(
  peers: readonly PeerTransportInfo[],
  record: SignedIssuanceRecord,
): Promise<{ leafIndex: number; merkleRoot: string; treeSize: number }> {
  if (peers.length === 0) {
    throw new Error('At least 1 peer is required to broadcast issuance');
  }
  const results = await Promise.all(
    peers.map(async (peer) => {
      const resp = await retryWithBackoffAndJitter(async () => {
        const r = await fetch(`${peer.endpoint}/v1/issuance`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(record),
        });
        const text = await r.text();
        if (!r.ok) {
          throw new NuvertherProtocolError('ISSUANCE_REJECTED', r.status, text);
        }
        return JSON.parse(text) as { leafIndex: number; merkleRoot: string; treeSize: number };
      });
      return resp;
    }),
  );

  const first = results[0]!;
  for (const res of results.slice(1)) {
    if (res.merkleRoot !== first.merkleRoot || res.leafIndex !== first.leafIndex) {
      throw new NuvertherProtocolError(
        'ISSUANCE_ROOT_DIVERGENCE',
        502,
        `Witnesses diverged on issuance root: ${first.merkleRoot} vs ${res.merkleRoot}`,
      );
    }
  }
  return first;
}

function verifyPrepareVote(
  vote: PrepareVote,
  witness: PeerTransportInfo,
  epoch: number,
  nullifiers: [string, string],
  proofSha256: string,
  txBinding: string,
): void {
  if (
    vote.peerId !== witness.peerId ||
    vote.epoch !== epoch ||
    vote.ed25519PkHex !== witness.ed25519PkHex ||
    vote.mldsa65PkB64 !== witness.mldsa65PkB64 ||
    vote.proofSha256 !== proofSha256 ||
    normalizeFieldHex(vote.txBinding) !== txBinding ||
    normalizeFieldHex(vote.nullifiers[0]) !== normalizeFieldHex(nullifiers[0]) ||
    normalizeFieldHex(vote.nullifiers[1]) !== normalizeFieldHex(nullifiers[1])
  ) {
    throw new NuvertherProtocolError(
      'INVALID_PREPARE_VOTE_METADATA',
      502,
      `PrepareVote metadata mismatch from witness ${witness.peerId}`,
    );
  }
  const validSig = verifyHybrid(
    prepareVoteSigningPayload(vote),
    vote.sig,
    { ed25519PkHex: witness.ed25519PkHex, mldsa65PkB64: witness.mldsa65PkB64 },
  );
  if (!validSig) {
    throw new NuvertherProtocolError(
      'INVALID_PREPARE_VOTE_SIGNATURE',
      502,
      `Witness ${witness.peerId} returned invalid PrepareVote signature`,
    );
  }
}

function verifyWitnessReceipt(
  receipt: WitnessAttestation,
  witness: PeerTransportInfo,
  proofSha256: string,
  txBinding: string,
): void {
  if (
    receipt.peerId !== witness.peerId ||
    receipt.ed25519PkHex !== witness.ed25519PkHex ||
    receipt.mldsa65PkB64 !== witness.mldsa65PkB64 ||
    receipt.proofSha256 !== proofSha256 ||
    normalizeFieldHex(receipt.txBinding) !== txBinding
  ) {
    throw new NuvertherProtocolError(
      'INVALID_WITNESS_RECEIPT_IDENTITY',
      502,
      `Receipt metadata mismatch from witness ${witness.peerId}`,
    );
  }

  const validSig = verifyHybrid(
    attestationSigningPayload({
      peerId: receipt.peerId,
      nullifiers: receipt.nullifiers,
      proofSha256: receipt.proofSha256,
      txBinding: receipt.txBinding,
      issuedAt: receipt.issuedAt,
    }),
    receipt.sig,
    {
      ed25519PkHex: witness.ed25519PkHex,
      mldsa65PkB64: witness.mldsa65PkB64,
    },
  );
  if (!validSig) {
    throw new NuvertherProtocolError(
      'INVALID_WITNESS_SIGNATURE',
      502,
      `Witness ${witness.peerId} returned invalid Ed25519/ML-DSA-65 signature`,
    );
  }
}

export async function abortSpendReservations(params: {
  peers: readonly PeerTransportInfo[];
  quorumPeers: readonly PeerTransportInfo[];
  epoch: number;
  txBinding: string;
  keys: NuvertherWalletKeys;
}): Promise<number> {
  const abortSig = signCanonicalMessage(
    abortRequestSigningPayload({ epoch: params.epoch, txBinding: params.txBinding }),
    params.keys,
  );
  const body = {
    epoch: params.epoch,
    txBinding: params.txBinding,
    spenderPub: {
      ed25519PkHex: params.keys.ed25519PkHex,
      mldsa65PkB64: params.keys.mldsa65PkB64,
    },
    spenderSig: abortSig,
  };
  let releasedTotal = 0;
  await Promise.allSettled(
    params.quorumPeers.map(async (witness) => {
      const res = await sendViaThreeHopOnion<{ aborted: boolean; releasedRows: number }>({
        peers: params.peers,
        targetPeer: witness,
        method: 'POST',
        path: '/v1/witness/abort',
        body,
      });
      releasedTotal += res.data.releasedRows ?? 0;
    }),
  );
  return releasedTotal;
}

async function finalizeCommittedSpendOutputs(params: {
  peers: readonly PeerTransportInfo[];
  epoch: number;
  quorumSize: number;
  proofBundle: SpendProofBundle;
  attestations: WitnessAttestation[];
}): Promise<{ outputLeafIndices: [number, number]; newMerkleRoot: string }> {
  const settlements = await Promise.allSettled(
    params.peers.map((peer) =>
      retryWithBackoffAndJitter(async () => {
        const res = await sendViaThreeHopOnion<{
          leafIndices: [number, number];
          merkleRoot: string;
          treeSize: number;
        }>({
          peers: params.peers,
          targetPeer: peer,
          method: 'POST',
          path: '/v1/tree/commit-outputs',
          body: {
            epoch: params.epoch,
            publicSignals: params.proofBundle.publicSignals,
            attestations: params.attestations,
          },
        });
        return res.data;
      }),
    ),
  );

  const succeeded = settlements
    .filter((s): s is PromiseFulfilledResult<{ leafIndices: [number, number]; merkleRoot: string; treeSize: number }> => s.status === 'fulfilled')
    .map((s) => s.value);

  if (succeeded.length < params.quorumSize) {
    throw new NuvertherProtocolError(
      'COMMIT_OUTPUTS_QUORUM_FAILED',
      502,
      `Only ${succeeded.length}/${params.quorumSize} peers committed output notes`,
    );
  }

  return {
    outputLeafIndices: succeeded[0]!.leafIndices,
    newMerkleRoot: succeeded[0]!.merkleRoot,
  };
}

export async function executeShieldedSpend(params: {
  keys: NuvertherWalletKeys;
  peers?: readonly PeerTransportInfo[];
  directory?: SignedEpochDirectory;
  inputs: [ShieldedNoteInput, ShieldedNoteInput];
  outputs: [ShieldedOutputSpec, ShieldedOutputSpec];
  fee: bigint;
  epoch?: number;
  quorumSize?: number;
  merkleTree?: Poseidon2MerkleTree;
  intentStore?: SpendIntentStore;
  prepareLeaseMs?: number;
}): Promise<ShieldedSpendResult> {
  const activeDirectory = params.directory;
  const revokedSet = new Set((activeDirectory?.revokedPeers ?? []).map((r) => r.peerId));
  const activePeers: PeerTransportInfo[] = activeDirectory
    ? activeDirectory.members.filter((m) => !revokedSet.has(m.peerId))
    : [...(params.peers ?? [])];

  const quorumSize = params.quorumSize ?? activeDirectory?.quorumSize ?? DEFAULT_QUORUM_SIZE;
  const epoch = params.epoch ?? activeDirectory?.epoch ?? 0;

  if (activePeers.length < quorumSize) {
    throw new Error(`Need at least ${quorumSize} active peers, have ${activePeers.length}`);
  }

  const tree = params.merkleTree ?? (await syncMerkleTreeFromPeers(activePeers)).tree;
  const proof0 = tree.getProof(params.inputs[0].leafIndex);
  const proof1 = tree.getProof(params.inputs[1].leafIndex);
  const merkleRoot = tree.getRoot();
  const merkleRootHex = normalizeFieldHex(merkleRoot);

  const outBlindings: [bigint, bigint] = [
    params.outputs[0].blinding ?? randomFieldElement(),
    params.outputs[1].blinding ?? randomFieldElement(),
  ];
  const feeBlinding = randomFieldElement();

  const outCommitments: [string, string] = [
    normalizeFieldHex(
      await computeCommitment(
        params.outputs[0].amount,
        params.outputs[0].recipientOwnerPk,
        outBlindings[0],
      ),
    ),
    normalizeFieldHex(
      await computeCommitment(
        params.outputs[1].amount,
        params.outputs[1].recipientOwnerPk,
        outBlindings[1],
      ),
    ),
  ];
  const feeCommitment = normalizeFieldHex(
    await computeFeeCommitment(params.fee, feeBlinding),
  );

  const txBindingHex = computeExpectedTxBinding({
    authPkHash: params.keys.authPkHash,
    merkleRoot: merkleRootHex,
    outputCommitments: outCommitments,
    feeCommitment,
  });

  // 1. Generate Noir UltraHonk proof locally
  const proofBundle = await generateSpendProof({
    spendSecret: params.keys.spendSecret,
    inAmounts: [params.inputs[0].amount, params.inputs[1].amount],
    inBlindings: [params.inputs[0].blinding, params.inputs[1].blinding],
    inLeafIndices: [params.inputs[0].leafIndex, params.inputs[1].leafIndex],
    inMerklePaths: [proof0.path, proof1.path],
    outAmounts: [params.outputs[0].amount, params.outputs[1].amount],
    outOwnerPks: [params.outputs[0].recipientOwnerPk, params.outputs[1].recipientOwnerPk],
    outBlindings,
    fee: params.fee,
    feeBlinding,
    authPkHash: BigInt(params.keys.authPkHash),
    txBinding: BigInt(txBindingHex),
    merkleRoot,
  });

  const proofSha256 = sha3Hex(Buffer.from(proofBundle.proofBase64, 'base64'));
  const spenderPub = {
    ed25519PkHex: params.keys.ed25519PkHex,
    mldsa65PkB64: params.keys.mldsa65PkB64,
  };
  const spenderSig = signCanonicalMessage(
    spendStatementPayload(proofBundle.publicSignals),
    params.keys,
  );

  // 2. Deterministic Epoch-Bound Witness Quorum selection
  const quorumPeers = selectWitnessQuorumForEpoch(
    epoch,
    proofBundle.publicSignals.nullifiers[0],
    activePeers,
    quorumSize,
  );

  let intent: SpendIntentRecord | undefined;
  const nowIso = new Date().toISOString();
  if (params.intentStore) {
    intent = params.intentStore.upsert({
      version: 1,
      txBinding: txBindingHex,
      epoch,
      status: 'CREATED',
      quorumPeerIds: quorumPeers.map((p) => p.peerId),
      proofBundle,
      spenderPub,
      spenderSig,
      prepareVotes: [],
      attestations: [],
      outputSpecs: [
        {
          amount: params.outputs[0].amount.toString(),
          recipientOwnerPk: normalizeFieldHex(params.outputs[0].recipientOwnerPk),
          blinding: normalizeFieldHex(outBlindings[0]),
          memo: params.outputs[0].memo,
        },
        {
          amount: params.outputs[1].amount.toString(),
          recipientOwnerPk: normalizeFieldHex(params.outputs[1].recipientOwnerPk),
          blinding: normalizeFieldHex(outBlindings[1]),
          memo: params.outputs[1].memo,
        },
      ],
      createdAt: nowIso,
      updatedAt: nowIso,
    });
  }

  // 3. Two-Phase Spend — Phase A: Prepare leases on Q witnesses; auto-abort if quorum prepare fails
  const prepareSettlements = await Promise.allSettled(
    quorumPeers.map((witness) =>
      retryWithBackoffAndJitter(async () => {
        const res = await sendViaThreeHopOnion<{ state: string; prepareVote: PrepareVote }>({
          peers: activePeers,
          targetPeer: witness,
          method: 'POST',
          path: '/v1/witness/prepare',
          body: {
            epoch,
            leaseMs: params.prepareLeaseMs,
            proofBundle,
            spenderPub,
            spenderSig,
          },
        });
        verifyPrepareVote(
          res.data.prepareVote,
          witness,
          epoch,
          proofBundle.publicSignals.nullifiers,
          proofSha256,
          txBindingHex,
        );
        return res.data.prepareVote;
      }),
    ),
  );

  const prepareVotes: PrepareVote[] = [];
  let firstPrepareError: unknown = null;
  for (const s of prepareSettlements) {
    if (s.status === 'fulfilled') {
      prepareVotes.push(s.value);
    } else if (!firstPrepareError) {
      firstPrepareError = s.reason;
    }
  }

  if (prepareVotes.length < quorumSize) {
    await abortSpendReservations({
      peers: activePeers,
      quorumPeers,
      epoch,
      txBinding: txBindingHex,
      keys: params.keys,
    });
    if (params.intentStore && intent) {
      params.intentStore.upsert({
        ...intent,
        status: 'ABORTED',
        prepareVotes,
        lastError: firstPrepareError instanceof Error ? firstPrepareError.message : String(firstPrepareError),
      });
    }
    throw firstPrepareError instanceof Error
      ? firstPrepareError
      : new NuvertherProtocolError(
          'PREPARE_QUORUM_FAILED',
          409,
          `Only ${prepareVotes.length}/${quorumSize} witnesses prepared`,
        );
  }

  if (params.intentStore && intent) {
    intent = params.intentStore.upsert({
      ...intent,
      status: 'PREPARED',
      prepareVotes,
    });
  }

  // 4. Two-Phase Spend — Phase B: Commit across quorum using verified PrepareVotes (idempotent per txBinding)
  const attestations = await Promise.all(
    quorumPeers.map((witness) =>
      retryWithBackoffAndJitter(async () => {
        const res = await sendViaThreeHopOnion<{ idempotent: boolean; attestation: WitnessAttestation }>({
          peers: activePeers,
          targetPeer: witness,
          method: 'POST',
          path: '/v1/witness/commit',
          body: {
            epoch,
            proofBundle,
            spenderPub,
            spenderSig,
            prepareVotes,
          },
        });
        verifyWitnessReceipt(res.data.attestation, witness, proofSha256, txBindingHex);
        return res.data.attestation;
      }),
    ),
  );

  if (params.intentStore && intent) {
    intent = params.intentStore.upsert({
      ...intent,
      status: 'COMMITTED',
      attestations,
    });
  }

  // 5. Commit output notes to Merkle registry
  const { outputLeafIndices, newMerkleRoot } = await finalizeCommittedSpendOutputs({
    peers: activePeers,
    epoch,
    quorumSize,
    proofBundle,
    attestations,
  });

  // 6. Encrypt & store 2-of-3 Shamir Thread payload shards via 3-hop onion circuits
  const threadPayload: ThreadPayload = {
    version: 2,
    noteNonce: normalizeFieldHex(randomFieldElement()),
    recipientOwnerPk: normalizeFieldHex(params.outputs[0].recipientOwnerPk),
    amount: params.outputs[0].amount.toString(),
    blinding: normalizeFieldHex(outBlindings[0]),
    leafIndex: outputLeafIndices[0],
    noteCommitment: outCommitments[0],
    memo: params.outputs[0].memo,
    createdAt: new Date().toISOString(),
  };
  const shardResult = await storeEncryptedThreadShards({
    peers: activePeers,
    payload: threadPayload,
  });

  if (params.intentStore && intent) {
    params.intentStore.upsert({
      ...intent,
      status: 'OUTPUTS_COMMITTED',
      outputLeafIndices,
      newMerkleRoot,
      threadKeyHex: shardResult.threadKeyHex,
      threadDigest: shardResult.threadDigest,
      shardPointers: shardResult.shardPointers,
    });
  }

  return {
    epoch,
    txBinding: txBindingHex,
    proofBundle,
    quorumWitnesses: quorumPeers.map((p) => p.peerId),
    prepareVotes,
    attestations,
    threadKeyHex: shardResult.threadKeyHex,
    threadDigest: shardResult.threadDigest,
    shardPointers: shardResult.shardPointers,
    outputCommitments: outCommitments,
    outputBlindings: outBlindings,
    outputLeafIndices,
    newMerkleRoot,
  };
}

export async function recoverSpendIntent(params: {
  intentStore: SpendIntentStore;
  txBinding: string;
  keys: NuvertherWalletKeys;
  peers?: readonly PeerTransportInfo[];
  directory?: SignedEpochDirectory;
}): Promise<{
  action: 'ABORTED' | 'COMPLETED';
  releasedReservations?: number;
  result?: ShieldedSpendResult;
}> {
  const intent = params.intentStore.get(normalizeFieldHex(params.txBinding));
  if (!intent) {
    throw new Error(`No persisted SpendIntent found for txBinding ${params.txBinding}`);
  }

  const activeDirectory = params.directory;
  const revokedSet = new Set((activeDirectory?.revokedPeers ?? []).map((r) => r.peerId));
  const activePeers: PeerTransportInfo[] = activeDirectory
    ? activeDirectory.members.filter((m) => !revokedSet.has(m.peerId))
    : [...(params.peers ?? [])];
  const quorumSize = activeDirectory?.quorumSize ?? intent.quorumPeerIds.length;
  const quorumPeers = selectWitnessQuorumForEpoch(
    intent.epoch,
    intent.proofBundle.publicSignals.nullifiers[0],
    activePeers,
    quorumSize,
  );

  // If crash happened before collecting Q PrepareVotes -> abort & release leases cleanly!
  if (intent.status === 'CREATED' || intent.prepareVotes.length < quorumSize) {
    const released = await abortSpendReservations({
      peers: activePeers,
      quorumPeers,
      epoch: intent.epoch,
      txBinding: intent.txBinding,
      keys: params.keys,
    });
    params.intentStore.upsert({
      ...intent,
      status: 'ABORTED',
    });
    return { action: 'ABORTED', releasedReservations: released };
  }

  const proofSha256 = sha3Hex(Buffer.from(intent.proofBundle.proofBase64, 'base64'));
  const existingAttestMap = new Map(intent.attestations.map((a) => [a.peerId, a]));

  const attestations = await Promise.all(
    quorumPeers.map(async (witness) => {
      const cached = existingAttestMap.get(witness.peerId);
      if (cached) return cached;
      return retryWithBackoffAndJitter(async () => {
        const res = await sendViaThreeHopOnion<{ idempotent: boolean; attestation: WitnessAttestation }>({
          peers: activePeers,
          targetPeer: witness,
          method: 'POST',
          path: '/v1/witness/commit',
          body: {
            epoch: intent.epoch,
            proofBundle: intent.proofBundle,
            spenderPub: intent.spenderPub,
            spenderSig: intent.spenderSig,
            prepareVotes: intent.prepareVotes,
          },
        });
        verifyWitnessReceipt(res.data.attestation, witness, proofSha256, intent.txBinding);
        return res.data.attestation;
      });
    }),
  );

  const committedIntent = params.intentStore.upsert({
    ...intent,
    status: 'COMMITTED',
    attestations,
  });

  const { outputLeafIndices, newMerkleRoot } =
    committedIntent.outputLeafIndices && committedIntent.newMerkleRoot
      ? {
          outputLeafIndices: committedIntent.outputLeafIndices,
          newMerkleRoot: committedIntent.newMerkleRoot,
        }
      : await finalizeCommittedSpendOutputs({
          peers: activePeers,
          epoch: committedIntent.epoch,
          quorumSize,
          proofBundle: committedIntent.proofBundle,
          attestations,
        });

  let threadKeyHex = committedIntent.threadKeyHex ?? '';
  let threadDigest = committedIntent.threadDigest ?? '';
  let shardPointers: StoredShardPointer[] = committedIntent.shardPointers ?? [];

  if (shardPointers.length < 3 && committedIntent.outputSpecs) {
    const out0 = committedIntent.outputSpecs[0];
    const shardResult = await storeEncryptedThreadShards({
      peers: activePeers,
      payload: {
        version: 2,
        noteNonce: normalizeFieldHex(randomFieldElement()),
        recipientOwnerPk: out0.recipientOwnerPk,
        amount: out0.amount,
        blinding: out0.blinding,
        leafIndex: outputLeafIndices[0],
        noteCommitment: committedIntent.proofBundle.publicSignals.outputCommitments[0],
        memo: out0.memo,
        createdAt: new Date().toISOString(),
      },
    });
    threadKeyHex = shardResult.threadKeyHex;
    threadDigest = shardResult.threadDigest;
    shardPointers = shardResult.shardPointers;
  }

  params.intentStore.upsert({
    ...committedIntent,
    status: 'OUTPUTS_COMMITTED',
    outputLeafIndices,
    newMerkleRoot,
    threadKeyHex,
    threadDigest,
    shardPointers,
  });

  const outputBlindings: [bigint, bigint] = committedIntent.outputSpecs
    ? [BigInt(committedIntent.outputSpecs[0].blinding), BigInt(committedIntent.outputSpecs[1].blinding)]
    : [0n, 0n];

  return {
    action: 'COMPLETED',
    result: {
      epoch: committedIntent.epoch,
      txBinding: committedIntent.txBinding,
      proofBundle: committedIntent.proofBundle,
      quorumWitnesses: quorumPeers.map((p) => p.peerId),
      prepareVotes: committedIntent.prepareVotes,
      attestations,
      threadKeyHex,
      threadDigest,
      shardPointers,
      outputCommitments: committedIntent.proofBundle.publicSignals.outputCommitments,
      outputBlindings,
      outputLeafIndices,
      newMerkleRoot,
    },
  };
}

import { randomBytes } from 'node:crypto';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha3_256 } from '@noble/hashes/sha3.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { bytesToFieldScalar, normalizeFieldHex } from '@nuverther/zk';

/**
 * Byzantine Fault Tolerance parameters:
 *   f = 3 tolerated Byzantine witnesses
 *   N = 11 >= 3f + 1 (= 10)
 *   Q = 8  >= 2f + 1 (= 7), and quorum intersection 2Q - N = 5 >= f + 1 (= 4)
 *   Liveness margin N - Q = 3 >= f
 */
export const MAX_BYZANTINE_FAULTS = 3;
export const DEFAULT_WITNESS_COUNT = 11;
export const DEFAULT_QUORUM_SIZE = 8;

export const ONION_PACKET_SIZE = 16_384;
export const ONION_HEADER_SLOTS = 3;
export const ONION_SLOT_SIZE = 320;
export const ONION_HEADER_SIZE = ONION_HEADER_SLOTS * ONION_SLOT_SIZE; // 960 bytes
export const ONION_BODY_SIZE = ONION_PACKET_SIZE - ONION_HEADER_SIZE; // 15,424 bytes
export const ONION_AEAD_TAG_SIZE = 16;
export const ONION_MAX_PLAINTEXT_SIZE = ONION_BODY_SIZE - 3 * ONION_AEAD_TAG_SIZE; // 15,376 bytes
export const ONION_MAX_CHUNK_DATA_SIZE = ONION_MAX_PLAINTEXT_SIZE - 2; // 15,374 bytes
export const CHUNK_FRAME_HEADER_SIZE = 83; // [0x02:1][msgId:16][idx:1][total:1][msgSecret:32][msgSha3:32]
export const DEFAULT_RELAY_POW_BITS = 10;

const HYBRID_SIG_DOMAIN = Buffer.from('NUV_HYBRID_SIG_V1', 'utf8');
const HASHCASH_DOMAIN = Buffer.from('NUV_HASHCASH_V1', 'utf8');
const RELAY_POW_DOMAIN = Buffer.from('NUV_RELAY_POW_V1', 'utf8');
const CHUNK_ID_DOMAIN = Buffer.from('NUV_CHUNK_ID_V1', 'utf8');
const ONION_KDF_INFO = Buffer.from('NUV_ONION_XCHACHA_V1', 'utf8');

export interface HybridSignature {
  ed25519Hex: string;
  mldsa65B64: string;
}

export interface HybridPublicKeys {
  ed25519PkHex: string;
  mldsa65PkB64: string;
}

export interface NodeKeypair {
  peerId: string;
  ed25519Sk: Uint8Array;
  ed25519Pk: Uint8Array;
  mldsa65Sk: Uint8Array;
  mldsa65Pk: Uint8Array;
  x25519Sk: Uint8Array;
  x25519Pk: Uint8Array;
}

export interface SignedPeerRecord {
  peerId: string;
  endpoint: string;
  ed25519PkHex: string;
  mldsa65PkB64: string;
  x25519PkHex: string;
  hashcashNonce: string;
  hashcashBits: number;
  selfSigEd25519Hex: string;
  selfSigMldsa65B64: string;
}

export interface SignedIssuanceRecord {
  issuanceId: string;
  epoch: number;
  txKind: 'genesis' | 'mint';
  amount: string;
  ownerPkHex: string;
  blindingHex: string;
  noteCommitmentHex: string;
  leafIndex: number;
  issuerPub: HybridPublicKeys;
  issuerSig: HybridSignature;
}

export interface SignedRootCheckpoint {
  epoch: number;
  treeSize: number;
  merkleRootHex: string;
  witnessPeerId: string;
  ed25519PkHex: string;
  mldsa65PkB64: string;
  sig: HybridSignature;
  createdAt: string;
}

export function sha3Digest(data: Uint8Array | string): Uint8Array {
  const bytes = typeof data === 'string' ? Buffer.from(data, 'utf8') : data;
  return sha3_256(bytes);
}

export function sha3Hex(data: Uint8Array | string): string {
  return Buffer.from(sha3Digest(data)).toString('hex');
}

export function canonicalSignDigest(payload: Uint8Array | string): Uint8Array {
  const bytes = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
  return sha3_256(Buffer.concat([HYBRID_SIG_DOMAIN, bytes]));
}

export function computeAuthPkHash(pub: HybridPublicKeys): string {
  const canonical = `NUV_AUTH_PK_V1|${pub.ed25519PkHex.toLowerCase()}|${pub.mldsa65PkB64}`;
  return normalizeFieldHex(bytesToFieldScalar(sha3Digest(canonical)));
}

export function signHybrid(
  payload: Uint8Array | string,
  ed25519Sk: Uint8Array,
  mldsa65Sk: Uint8Array,
): HybridSignature {
  const digest = canonicalSignDigest(payload);
  const sigEd = ed25519.sign(digest, ed25519Sk);
  const sigPq = ml_dsa65.sign(digest, mldsa65Sk);
  return {
    ed25519Hex: Buffer.from(sigEd).toString('hex'),
    mldsa65B64: Buffer.from(sigPq).toString('base64'),
  };
}

export function verifyHybrid(
  payload: Uint8Array | string,
  sig: HybridSignature,
  pub: HybridPublicKeys,
): boolean {
  try {
    const edPk = new Uint8Array(Buffer.from(pub.ed25519PkHex, 'hex'));
    const pqPk = new Uint8Array(Buffer.from(pub.mldsa65PkB64, 'base64'));
    const edSig = new Uint8Array(Buffer.from(sig.ed25519Hex, 'hex'));
    const pqSig = new Uint8Array(Buffer.from(sig.mldsa65B64, 'base64'));

    if (edPk.length !== 32 || edSig.length !== 64) {
      return false;
    }
    if (pqPk.length !== ml_dsa65.lengths.publicKey || pqSig.length !== ml_dsa65.lengths.signature) {
      return false;
    }

    const digest = canonicalSignDigest(payload);
    const okEd = ed25519.verify(edSig, digest, edPk);
    if (!okEd) return false;
    return ml_dsa65.verify(pqSig, digest, pqPk);
  } catch {
    return false;
  }
}

export function generateNodeKeypair(peerId: string, seed?: Uint8Array): NodeKeypair {
  const masterSeed = seed ? sha3_256(seed) : randomBytes(32);
  const edSeed = sha3_256(Buffer.concat([masterSeed, Buffer.from('ed25519', 'utf8')]));
  const pqSeed = sha3_256(Buffer.concat([masterSeed, Buffer.from('mldsa65', 'utf8')]));
  const xSeed = sha3_256(Buffer.concat([masterSeed, Buffer.from('x25519', 'utf8')]));

  const edKeys = ed25519.keygen(edSeed);
  const pqKeys = ml_dsa65.keygen(pqSeed);
  const xKeys = x25519.keygen(xSeed);

  return {
    peerId,
    ed25519Sk: edKeys.secretKey,
    ed25519Pk: edKeys.publicKey,
    mldsa65Sk: pqKeys.secretKey,
    mldsa65Pk: pqKeys.publicKey,
    x25519Sk: xKeys.secretKey,
    x25519Pk: xKeys.publicKey,
  };
}

export function countLeadingZeroBits(bytes: Uint8Array): number {
  let bits = 0;
  for (const byte of bytes) {
    if (byte === 0) {
      bits += 8;
    } else {
      bits += Math.clz32(byte) - 24;
      break;
    }
  }
  return bits;
}

export function buildHashCashPreimage(
  peerId: string,
  ed25519PkHex: string,
  mldsa65PkB64: string,
  x25519PkHex: string,
  nonce: string,
): Buffer {
  return Buffer.concat([
    HASHCASH_DOMAIN,
    Buffer.from(`|${peerId}|${ed25519PkHex}|${mldsa65PkB64}|${x25519PkHex}|${nonce}`, 'utf8'),
  ]);
}

export function solveHashCash(
  peerId: string,
  ed25519PkHex: string,
  mldsa65PkB64: string,
  x25519PkHex: string,
  difficultyBits: number,
): string {
  for (let counter = 0; ; counter++) {
    const nonce = counter.toString(16);
    const digest = sha3_256(
      buildHashCashPreimage(peerId, ed25519PkHex, mldsa65PkB64, x25519PkHex, nonce),
    );
    if (countLeadingZeroBits(digest) >= difficultyBits) {
      return nonce;
    }
  }
}

export function verifyHashCash(
  peerId: string,
  ed25519PkHex: string,
  mldsa65PkB64: string,
  x25519PkHex: string,
  nonce: string,
  requiredBits: number,
): boolean {
  const digest = sha3_256(
    buildHashCashPreimage(peerId, ed25519PkHex, mldsa65PkB64, x25519PkHex, nonce),
  );
  return countLeadingZeroBits(digest) >= requiredBits;
}

export function peerRecordSigningPayload(record: {
  peerId: string;
  endpoint: string;
  ed25519PkHex: string;
  mldsa65PkB64: string;
  x25519PkHex: string;
  hashcashNonce: string;
  hashcashBits: number;
}): string {
  return JSON.stringify([
    'NUV_PEER_V1',
    record.peerId,
    record.endpoint,
    record.ed25519PkHex,
    record.mldsa65PkB64,
    record.x25519PkHex,
    record.hashcashNonce,
    record.hashcashBits,
  ]);
}

export function createSignedPeerRecord(
  keys: NodeKeypair,
  endpoint: string,
  difficultyBits: number,
): SignedPeerRecord {
  const ed25519PkHex = Buffer.from(keys.ed25519Pk).toString('hex');
  const mldsa65PkB64 = Buffer.from(keys.mldsa65Pk).toString('base64');
  const x25519PkHex = Buffer.from(keys.x25519Pk).toString('hex');
  const hashcashNonce = solveHashCash(
    keys.peerId,
    ed25519PkHex,
    mldsa65PkB64,
    x25519PkHex,
    difficultyBits,
  );
  const base = {
    peerId: keys.peerId,
    endpoint,
    ed25519PkHex,
    mldsa65PkB64,
    x25519PkHex,
    hashcashNonce,
    hashcashBits: difficultyBits,
  };
  const sig = signHybrid(peerRecordSigningPayload(base), keys.ed25519Sk, keys.mldsa65Sk);
  return {
    ...base,
    selfSigEd25519Hex: sig.ed25519Hex,
    selfSigMldsa65B64: sig.mldsa65B64,
  };
}

export function verifySignedPeerRecord(
  record: SignedPeerRecord,
  minHashCashBits: number,
): boolean {
  if (record.hashcashBits < minHashCashBits) return false;
  if (
    !verifyHashCash(
      record.peerId,
      record.ed25519PkHex,
      record.mldsa65PkB64,
      record.x25519PkHex,
      record.hashcashNonce,
      minHashCashBits,
    )
  ) {
    return false;
  }
  return verifyHybrid(
    peerRecordSigningPayload(record),
    {
      ed25519Hex: record.selfSigEd25519Hex,
      mldsa65B64: record.selfSigMldsa65B64,
    },
    {
      ed25519PkHex: record.ed25519PkHex,
      mldsa65PkB64: record.mldsa65PkB64,
    },
  );
}

export function issuanceSigningPayload(rec: {
  issuanceId: string;
  epoch: number;
  txKind: 'genesis' | 'mint';
  amount: string;
  ownerPkHex: string;
  blindingHex: string;
  noteCommitmentHex: string;
  leafIndex: number;
}): string {
  return JSON.stringify([
    'NUV_ISSUANCE_V1',
    rec.issuanceId,
    rec.epoch,
    rec.txKind,
    rec.amount,
    normalizeFieldHex(rec.ownerPkHex),
    normalizeFieldHex(rec.blindingHex),
    normalizeFieldHex(rec.noteCommitmentHex),
    rec.leafIndex,
  ]);
}

export function rootCheckpointSigningPayload(rec: {
  epoch: number;
  treeSize: number;
  merkleRootHex: string;
  witnessPeerId: string;
}): string {
  return JSON.stringify([
    'NUV_ROOT_V1',
    rec.epoch,
    rec.treeSize,
    normalizeFieldHex(rec.merkleRootHex),
    rec.witnessPeerId,
  ]);
}

export interface EpochWitnessMember {
  peerId: string;
  endpoint: string;
  ed25519PkHex: string;
  mldsa65PkB64: string;
  x25519PkHex: string;
  joinedEpoch: number;
}

export interface RevokedPeerEntry {
  peerId: string;
  revokedAtEpoch: number;
  reason: string;
  equivocationProofHash?: string;
}

export interface GovernanceApproval {
  signerId: string;
  pub: HybridPublicKeys;
  sig: HybridSignature;
}

export interface SignedEpochDirectory {
  version: 1;
  epoch: number;
  quorumSize: number;
  nullifierEpochRetention: number;
  validFrom: string;
  expiresAt: string;
  previousDirectorySha256: string;
  members: EpochWitnessMember[];
  revokedPeers: RevokedPeerEntry[];
  governanceApprovals: GovernanceApproval[];
}

export function canonicalizeEpochDirectory(dir: Omit<SignedEpochDirectory, 'governanceApprovals'>): string {
  const sortedMembers = [...dir.members].sort((a, b) => a.peerId.localeCompare(b.peerId));
  const sortedRevoked = [...dir.revokedPeers].sort((a, b) => a.peerId.localeCompare(b.peerId));
  return JSON.stringify([
    'NUV_EPOCH_DIR_V1',
    dir.version,
    dir.epoch,
    dir.quorumSize,
    dir.nullifierEpochRetention,
    dir.validFrom,
    dir.expiresAt,
    dir.previousDirectorySha256,
    sortedMembers.map((m) => [
      m.peerId,
      m.endpoint,
      m.ed25519PkHex.toLowerCase(),
      m.mldsa65PkB64,
      m.x25519PkHex.toLowerCase(),
      m.joinedEpoch,
    ]),
    sortedRevoked.map((r) => [
      r.peerId,
      r.revokedAtEpoch,
      r.reason,
      r.equivocationProofHash ?? '',
    ]),
  ]);
}

export function computeEpochDirectoryHash(dir: Omit<SignedEpochDirectory, 'governanceApprovals'>): string {
  return sha3Hex(canonicalizeEpochDirectory(dir));
}

export function createSignedEpochDirectory(params: {
  epoch: number;
  quorumSize?: number;
  nullifierEpochRetention?: number;
  validFrom?: string;
  expiresAt?: string;
  previousDirectorySha256: string;
  members: EpochWitnessMember[];
  revokedPeers?: RevokedPeerEntry[];
  governanceSigners: NodeKeypair[];
}): SignedEpochDirectory {
  const base: Omit<SignedEpochDirectory, 'governanceApprovals'> = {
    version: 1,
    epoch: params.epoch,
    quorumSize: params.quorumSize ?? DEFAULT_QUORUM_SIZE,
    nullifierEpochRetention: params.nullifierEpochRetention ?? 4,
    validFrom: params.validFrom ?? new Date().toISOString(),
    expiresAt: params.expiresAt ?? new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
    previousDirectorySha256: params.previousDirectorySha256,
    members: [...params.members].sort((a, b) => a.peerId.localeCompare(b.peerId)),
    revokedPeers: [...(params.revokedPeers ?? [])].sort((a, b) => a.peerId.localeCompare(b.peerId)),
  };
  const payload = canonicalizeEpochDirectory(base);
  const governanceApprovals: GovernanceApproval[] = params.governanceSigners.map((signer) => ({
    signerId: signer.peerId,
    pub: {
      ed25519PkHex: Buffer.from(signer.ed25519Pk).toString('hex'),
      mldsa65PkB64: Buffer.from(signer.mldsa65Pk).toString('base64'),
    },
    sig: signHybrid(payload, signer.ed25519Sk, signer.mldsa65Sk),
  }));
  return { ...base, governanceApprovals };
}

export function verifySignedEpochDirectory(
  dir: SignedEpochDirectory,
  trustedGovernanceKeys: readonly HybridPublicKeys[],
  threshold = 1,
): boolean {
  if (dir.members.length < dir.quorumSize || dir.quorumSize < 1) {
    return false;
  }
  const seenPeerIds = new Set<string>();
  const revokedIds = new Set(dir.revokedPeers.map((r) => r.peerId));
  for (const m of dir.members) {
    if (seenPeerIds.has(m.peerId) || revokedIds.has(m.peerId)) {
      return false;
    }
    seenPeerIds.add(m.peerId);
  }

  const payload = canonicalizeEpochDirectory(dir);
  const validSigners = new Set<string>();
  for (const approval of dir.governanceApprovals) {
    const edLower = approval.pub.ed25519PkHex.toLowerCase();
    const isTrusted = trustedGovernanceKeys.some(
      (k) => k.ed25519PkHex.toLowerCase() === edLower && k.mldsa65PkB64 === approval.pub.mldsa65PkB64,
    );
    if (!isTrusted) continue;
    const signerKey = `${edLower}|${approval.pub.mldsa65PkB64}`;
    if (validSigners.has(signerKey)) continue;
    if (verifyHybrid(payload, approval.sig, approval.pub)) {
      validSigners.add(signerKey);
    }
  }
  return validSigners.size >= threshold;
}

export interface PrepareVote {
  peerId: string;
  epoch: number;
  nullifiers: [string, string];
  proofSha256: string;
  txBinding: string;
  expiresAt: string;
  ed25519PkHex: string;
  mldsa65PkB64: string;
  sig: HybridSignature;
}

export function prepareVoteSigningPayload(vote: {
  peerId: string;
  epoch: number;
  nullifiers: [string, string];
  proofSha256: string;
  txBinding: string;
  expiresAt: string;
}): string {
  return JSON.stringify([
    'NUV_PREPARE_V1',
    vote.peerId,
    vote.epoch,
    vote.nullifiers.map((x) => normalizeFieldHex(x)),
    vote.proofSha256,
    normalizeFieldHex(vote.txBinding),
    vote.expiresAt,
  ]);
}

export function abortRequestSigningPayload(req: {
  epoch: number;
  txBinding: string;
}): string {
  return JSON.stringify([
    'NUV_ABORT_V1',
    req.epoch,
    normalizeFieldHex(req.txBinding),
  ]);
}

export interface ChainedWitnessCheckpoint {
  epoch: number;
  seq: number;
  prevHash: string;
  stateRoot: string;
  txBinding: string;
  treeSize: number;
  witnessPeerId: string;
  checkpointHash: string;
  ed25519PkHex: string;
  mldsa65PkB64: string;
  sig: HybridSignature;
  createdAt: string;
}

export function checkpointSigningPayload(cp: {
  epoch: number;
  seq: number;
  prevHash: string;
  stateRoot: string;
  txBinding: string;
  treeSize: number;
  witnessPeerId: string;
}): string {
  return JSON.stringify([
    'NUV_CHECKPOINT_CHAIN_V1',
    cp.epoch,
    cp.seq,
    cp.prevHash,
    normalizeFieldHex(cp.stateRoot),
    normalizeFieldHex(cp.txBinding),
    cp.treeSize,
    cp.witnessPeerId,
  ]);
}

export function computeChainedCheckpointHash(cp: {
  epoch: number;
  seq: number;
  prevHash: string;
  stateRoot: string;
  txBinding: string;
  treeSize: number;
  witnessPeerId: string;
}): string {
  return sha3Hex(checkpointSigningPayload(cp));
}

export type EquivocationProof =
  | {
      kind: 'CHECKPOINT_FORK';
      witnessPeerId: string;
      first: ChainedWitnessCheckpoint;
      second: ChainedWitnessCheckpoint;
    }
  | {
      kind: 'PREPARE_CONFLICT';
      witnessPeerId: string;
      first: PrepareVote;
      second: PrepareVote;
    };

export function verifyEquivocationProof(
  proof: EquivocationProof,
  expectedPub: HybridPublicKeys,
): { valid: boolean; proofHash: string; reason: string } {
  if (proof.kind === 'CHECKPOINT_FORK') {
    const a = proof.first;
    const b = proof.second;
    if (
      a.witnessPeerId !== proof.witnessPeerId ||
      b.witnessPeerId !== proof.witnessPeerId ||
      a.ed25519PkHex.toLowerCase() !== expectedPub.ed25519PkHex.toLowerCase() ||
      a.mldsa65PkB64 !== expectedPub.mldsa65PkB64 ||
      b.ed25519PkHex.toLowerCase() !== expectedPub.ed25519PkHex.toLowerCase() ||
      b.mldsa65PkB64 !== expectedPub.mldsa65PkB64
    ) {
      return { valid: false, proofHash: '', reason: 'WITNESS_KEY_MISMATCH' };
    }
    if (a.epoch !== b.epoch || a.seq !== b.seq) {
      return { valid: false, proofHash: '', reason: 'NOT_SAME_EPOCH_AND_SEQ' };
    }
    const hashA = computeChainedCheckpointHash(a);
    const hashB = computeChainedCheckpointHash(b);
    if (hashA === hashB) {
      return { valid: false, proofHash: '', reason: 'CHECKPOINTS_IDENTICAL' };
    }
    const sigA = verifyHybrid(checkpointSigningPayload(a), a.sig, expectedPub);
    const sigB = verifyHybrid(checkpointSigningPayload(b), b.sig, expectedPub);
    if (!sigA || !sigB) {
      return { valid: false, proofHash: '', reason: 'INVALID_CHECKPOINT_SIGNATURE' };
    }
    const proofHash = sha3Hex(JSON.stringify([proof.kind, proof.witnessPeerId, hashA, hashB].sort()));
    return { valid: true, proofHash, reason: 'PROVEN_CHECKPOINT_EQUIVOCATION' };
  }

  const a = proof.first;
  const b = proof.second;
  if (
    a.peerId !== proof.witnessPeerId ||
    b.peerId !== proof.witnessPeerId ||
    a.ed25519PkHex.toLowerCase() !== expectedPub.ed25519PkHex.toLowerCase() ||
    a.mldsa65PkB64 !== expectedPub.mldsa65PkB64 ||
    b.ed25519PkHex.toLowerCase() !== expectedPub.ed25519PkHex.toLowerCase() ||
    b.mldsa65PkB64 !== expectedPub.mldsa65PkB64
  ) {
    return { valid: false, proofHash: '', reason: 'WITNESS_KEY_MISMATCH' };
  }
  if (a.epoch !== b.epoch) {
    return { valid: false, proofHash: '', reason: 'DIFFERENT_EPOCHS' };
  }
  const sharesNullifier =
    normalizeFieldHex(a.nullifiers[0]) === normalizeFieldHex(b.nullifiers[0]) ||
    normalizeFieldHex(a.nullifiers[0]) === normalizeFieldHex(b.nullifiers[1]) ||
    normalizeFieldHex(a.nullifiers[1]) === normalizeFieldHex(b.nullifiers[0]) ||
    normalizeFieldHex(a.nullifiers[1]) === normalizeFieldHex(b.nullifiers[1]);
  if (!sharesNullifier || normalizeFieldHex(a.txBinding) === normalizeFieldHex(b.txBinding)) {
    return { valid: false, proofHash: '', reason: 'NO_CONFLICTING_NULLIFIER_VOTE' };
  }
  const sigA = verifyHybrid(prepareVoteSigningPayload(a), a.sig, expectedPub);
  const sigB = verifyHybrid(prepareVoteSigningPayload(b), b.sig, expectedPub);
  if (!sigA || !sigB) {
    return { valid: false, proofHash: '', reason: 'INVALID_PREPARE_SIGNATURE' };
  }
  const pA = prepareVoteSigningPayload(a);
  const pB = prepareVoteSigningPayload(b);
  const proofHash = sha3Hex(JSON.stringify([proof.kind, proof.witnessPeerId, pA, pB].sort()));
  return { valid: true, proofHash, reason: 'PROVEN_PREPARE_EQUIVOCATION' };
}

/**
 * Deterministically selects an 8-of-11 (configurable Q-of-N) Witness quorum
 * bound to the signed epoch record via SHA3-256(epoch || "|" || nullifier || "|" || peer_id).
 */
export function selectWitnessQuorumForEpoch<T extends { peerId: string }>(
  epoch: number,
  nullifier: string,
  peers: readonly T[],
  quorumSize = DEFAULT_QUORUM_SIZE,
): T[] {
  if (peers.length < quorumSize) {
    throw new Error(`Insufficient peers for quorum: have ${peers.length}, need ${quorumSize}`);
  }
  const normNull = normalizeFieldHex(nullifier);
  const scored = peers.map((peer) => {
    const score = Buffer.from(
      sha3_256(Buffer.from(`${epoch}|${normNull}|${peer.peerId}`, 'utf8')),
    ).toString('hex');
    return { peer, score };
  });
  scored.sort((a, b) => (a.score < b.score ? -1 : a.score > b.score ? 1 : 0));
  return scored.slice(0, quorumSize).map((item) => item.peer);
}

/**
 * Convenience wrapper defaulting to epoch 0 when using an explicit peer list.
 */
export function selectWitnessQuorum<T extends { peerId: string }>(
  nullifier: string,
  peers: readonly T[],
  quorumSize = DEFAULT_QUORUM_SIZE,
  epoch = 0,
): T[] {
  return selectWitnessQuorumForEpoch(epoch, nullifier, peers, quorumSize);
}

export interface OnionHopTarget {
  x25519PkHex: string;
  hopUrl: string;
}

function deriveHeaderKey(
  sharedSecret: Uint8Array,
  ephemPk: Uint8Array,
  hopPk: Uint8Array,
): Uint8Array {
  const salt = Buffer.concat([ephemPk, hopPk]);
  return hkdf(sha3_256, sharedSecret, salt, ONION_KDF_INFO, 32);
}

export function deriveChunkMsgId(msgSecret: Uint8Array): Uint8Array {
  return sha3_256(Buffer.concat([CHUNK_ID_DOMAIN, msgSecret])).subarray(0, 16);
}

export function solveRelaySlotPoW(ephemPk: Uint8Array, requiredBits = DEFAULT_RELAY_POW_BITS): Uint8Array {
  const nonce = new Uint8Array(24);
  randomBytes(16).copy(nonce, 0);
  if (requiredBits <= 0) {
    randomBytes(8).copy(nonce, 16);
    return nonce;
  }
  const buf = Buffer.concat([RELAY_POW_DOMAIN, ephemPk, nonce]);
  const nonceOffset = RELAY_POW_DOMAIN.length + ephemPk.length;
  const view = new DataView(buf.buffer, buf.byteOffset + nonceOffset + 16, 8);
  for (let ctr = 0n; ; ctr++) {
    view.setBigUint64(0, ctr, false);
    const digest = sha3_256(buf);
    if (countLeadingZeroBits(digest) >= requiredBits) {
      return new Uint8Array(buf.subarray(nonceOffset, nonceOffset + 24));
    }
  }
}

export function verifyRelaySlotPoW(
  ephemPk: Uint8Array,
  headerNonce: Uint8Array,
  requiredBits: number,
): boolean {
  if (requiredBits <= 0) return true;
  if (ephemPk.length !== 32 || headerNonce.length !== 24) return false;
  const digest = sha3_256(Buffer.concat([RELAY_POW_DOMAIN, ephemPk, headerNonce]));
  return countLeadingZeroBits(digest) >= requiredBits;
}

export function extractOnionSlot0AuthPrefix(packet: Uint8Array): {
  ephemPkHex: string;
  ephemPk: Uint8Array;
  headerNonce: Uint8Array;
} | null {
  if (packet.length !== ONION_PACKET_SIZE || packet[0] !== 0x01) {
    return null;
  }
  const ephemPk = packet.subarray(1, 33);
  const headerNonce = packet.subarray(33, 57);
  return {
    ephemPkHex: Buffer.from(ephemPk).toString('hex'),
    ephemPk,
    headerNonce,
  };
}

function buildHeaderSlot(
  hopX25519Pk: Uint8Array,
  flag: number,
  url: string,
  bodyKey: Uint8Array,
  bodyNonce: Uint8Array,
  bodyCipherLen: number,
  relayPowBits = DEFAULT_RELAY_POW_BITS,
): Uint8Array {
  const ephem = x25519.keygen();
  const shared = x25519.getSharedSecret(ephem.secretKey, hopX25519Pk);
  const headerKey = deriveHeaderKey(shared, ephem.publicKey, hopX25519Pk);
  const headerNonce = solveRelaySlotPoW(ephem.publicKey, relayPowBits);

  const urlBytes = Buffer.from(url, 'utf8');
  if (urlBytes.length > 180) {
    throw new Error(`Onion hop URL too long (${urlBytes.length} > 180)`);
  }

  const plaintextLen = ONION_SLOT_SIZE - 1 - 32 - 24 - ONION_AEAD_TAG_SIZE;
  const plaintext = new Uint8Array(plaintextLen);
  randomBytes(plaintextLen).copy(plaintext);
  plaintext[0] = flag;
  plaintext[1] = (bodyCipherLen >> 8) & 0xff;
  plaintext[2] = bodyCipherLen & 0xff;
  plaintext.set(bodyKey, 3);
  plaintext.set(bodyNonce, 35);
  plaintext[59] = urlBytes.length;
  plaintext.set(urlBytes, 60);

  const sealed = xchacha20poly1305(headerKey, headerNonce).encrypt(plaintext);
  const slot = new Uint8Array(ONION_SLOT_SIZE);
  slot[0] = 0x01;
  slot.set(ephem.publicKey, 1);
  slot.set(headerNonce, 33);
  slot.set(sealed, 57);
  return slot;
}

export function wrapOnionPacket(
  hops: [OnionHopTarget, OnionHopTarget, OnionHopTarget],
  terminalUrl: string,
  payload: Uint8Array,
  options: { relayPowBits?: number } = {},
): Uint8Array {
  const relayPowBits = options.relayPowBits ?? DEFAULT_RELAY_POW_BITS;
  if (payload.length > ONION_MAX_CHUNK_DATA_SIZE) {
    throw new RangeError(
      `Onion chunk exceeds max capacity (${payload.length} > ${ONION_MAX_CHUNK_DATA_SIZE})`,
    );
  }

  const innerPlain = new Uint8Array(ONION_MAX_PLAINTEXT_SIZE);
  randomBytes(ONION_MAX_PLAINTEXT_SIZE).copy(innerPlain);
  innerPlain[0] = (payload.length >> 8) & 0xff;
  innerPlain[1] = payload.length & 0xff;
  innerPlain.set(payload, 2);

  const bodyKeys = [randomBytes(32), randomBytes(32), randomBytes(32)];
  const bodyNonces = [randomBytes(24), randomBytes(24), randomBytes(24)];

  const c3 = xchacha20poly1305(bodyKeys[2]!, bodyNonces[2]!).encrypt(innerPlain);
  const c2 = xchacha20poly1305(bodyKeys[1]!, bodyNonces[1]!).encrypt(c3);
  const c1 = xchacha20poly1305(bodyKeys[0]!, bodyNonces[0]!).encrypt(c2);

  const slot0 = buildHeaderSlot(
    new Uint8Array(Buffer.from(hops[0].x25519PkHex, 'hex')),
    0x01,
    hops[1].hopUrl,
    bodyKeys[0]!,
    bodyNonces[0]!,
    c1.length,
    relayPowBits,
  );
  const slot1 = buildHeaderSlot(
    new Uint8Array(Buffer.from(hops[1].x25519PkHex, 'hex')),
    0x01,
    hops[2].hopUrl,
    bodyKeys[1]!,
    bodyNonces[1]!,
    c2.length,
    relayPowBits,
  );
  const slot2 = buildHeaderSlot(
    new Uint8Array(Buffer.from(hops[2].x25519PkHex, 'hex')),
    0x02,
    terminalUrl,
    bodyKeys[2]!,
    bodyNonces[2]!,
    c3.length,
    relayPowBits,
  );

  const packet = new Uint8Array(ONION_PACKET_SIZE);
  packet.set(slot0, 0);
  packet.set(slot1, ONION_SLOT_SIZE);
  packet.set(slot2, ONION_SLOT_SIZE * 2);
  packet.set(c1, ONION_HEADER_SIZE);
  return packet;
}

export type UnwrappedOnionResult =
  | {
      mode: 'relay';
      nextHopUrl: string;
      nextPacket: Uint8Array;
    }
  | {
      mode: 'terminal';
      targetUrl: string;
      payload: Uint8Array;
    };

export function unwrapOnionLayer(
  packet: Uint8Array,
  nodeX25519Sk: Uint8Array,
  nodeX25519Pk: Uint8Array,
): UnwrappedOnionResult {
  if (packet.length !== ONION_PACKET_SIZE) {
    throw new Error(`Invalid onion packet size: expected ${ONION_PACKET_SIZE}, got ${packet.length}`);
  }
  const slot0 = packet.subarray(0, ONION_SLOT_SIZE);
  if (slot0[0] !== 0x01) {
    throw new Error('Unsupported onion slot version');
  }
  const ephemPk = slot0.subarray(1, 33);
  const headerNonce = slot0.subarray(33, 57);
  const sealedSlot = slot0.subarray(57, ONION_SLOT_SIZE);

  const shared = x25519.getSharedSecret(nodeX25519Sk, ephemPk);
  const headerKey = deriveHeaderKey(shared, ephemPk, nodeX25519Pk);
  const slotPlain = xchacha20poly1305(headerKey, headerNonce).decrypt(sealedSlot);

  const flag = slotPlain[0]!;
  const bodyCipherLen = (slotPlain[1]! << 8) | slotPlain[2]!;
  const bodyKey = slotPlain.subarray(3, 35);
  const bodyNonce = slotPlain.subarray(35, 59);
  const urlLen = slotPlain[59]!;
  const url = Buffer.from(slotPlain.subarray(60, 60 + urlLen)).toString('utf8');

  if (bodyCipherLen < ONION_AEAD_TAG_SIZE || bodyCipherLen > ONION_BODY_SIZE) {
    throw new Error('Invalid onion body cipher length');
  }

  const wireBody = packet.subarray(ONION_HEADER_SIZE, ONION_HEADER_SIZE + bodyCipherLen);
  const decryptedBody = xchacha20poly1305(bodyKey, bodyNonce).decrypt(wireBody);

  if (flag === 0x01) {
    const nextPacket = new Uint8Array(ONION_PACKET_SIZE);
    nextPacket.set(packet.subarray(ONION_SLOT_SIZE, ONION_HEADER_SIZE), 0);
    randomBytes(ONION_SLOT_SIZE).copy(
      Buffer.from(nextPacket.buffer, nextPacket.byteOffset + ONION_SLOT_SIZE * 2, ONION_SLOT_SIZE),
    );
    const paddedBody = new Uint8Array(ONION_BODY_SIZE);
    randomBytes(ONION_BODY_SIZE).copy(paddedBody);
    paddedBody.set(decryptedBody, 0);
    nextPacket.set(paddedBody, ONION_HEADER_SIZE);
    return { mode: 'relay', nextHopUrl: url, nextPacket };
  }

  if (flag === 0x02) {
    const payloadLen = (decryptedBody[0]! << 8) | decryptedBody[1]!;
    if (payloadLen > ONION_MAX_CHUNK_DATA_SIZE || 2 + payloadLen > decryptedBody.length) {
      throw new Error('Invalid terminal onion payload length');
    }
    return {
      mode: 'terminal',
      targetUrl: url,
      payload: decryptedBody.slice(2, 2 + payloadLen),
    };
  }

  throw new Error(`Unknown onion hop flag: ${flag}`);
}

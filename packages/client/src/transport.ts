import { randomBytes, randomInt } from 'node:crypto';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { combine, split } from 'shamir-secret-sharing';
import {
  computeFeeCommitment,
  generateSpendProof,
  normalizeFieldHex,
  randomFieldElement,
  type SpendProofBundle,
} from '@nuverther/zk';
import {
  ONION_MAX_CHUNK_DATA_SIZE,
  ONION_PACKET_SIZE,
  computeExpectedTxBinding,
  computeShardMacTag,
  selectWitnessQuorum,
  sha3Hex,
  spendStatementPayload,
  verifyHybrid,
  verifySignedPeerRecord,
  wrapOnionPacket,
  type BlindShardRecord,
  type OnionHopTarget,
  type SignedPeerRecord,
  type WitnessAttestation,
  attestationSigningPayload,
} from '@nuverther/node';
import { signCanonicalMessage, type NuvertherWalletKeys } from './custody.ts';

export interface ShieldedNoteInput {
  amount: bigint;
  blinding: bigint;
  threadId: bigint;
}

export interface ShieldedOutputSpec {
  amount: bigint;
  recipientOwnerPk: bigint;
  blinding?: bigint;
  memo?: string;
}

export interface ThreadPayload {
  version: 1;
  threadId: string;
  recipientOwnerPk: string;
  amount: string;
  blinding: string;
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
  proofBundle: SpendProofBundle;
  quorumWitnesses: string[];
  attestations: WitnessAttestation[];
  threadKeyHex: string;
  threadDigest: string;
  shardPointers: StoredShardPointer[];
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

export async function discoverVerifiedPeers(
  seedUrls: string[],
  minHashCashBits = 12,
): Promise<SignedPeerRecord[]> {
  const byPeerId = new Map<string, SignedPeerRecord>();

  await Promise.all(
    seedUrls.map(async (url) => {
      try {
        const idResp = await fetch(`${url}/v1/identity`);
        if (idResp.ok) {
          const rec = (await idResp.json()) as SignedPeerRecord;
          if (verifySignedPeerRecord(rec, minHashCashBits)) {
            byPeerId.set(rec.peerId, rec);
          }
        }
        const peersResp = await fetch(`${url}/v1/peers`);
        if (peersResp.ok) {
          const data = (await peersResp.json()) as { peers?: SignedPeerRecord[] };
          for (const rec of data.peers ?? []) {
            if (verifySignedPeerRecord(rec, minHashCashBits)) {
              byPeerId.set(rec.peerId, rec);
            }
          }
        }
      } catch {
        // Ignore unreachable seed during discovery
      }
    }),
  );

  return [...byPeerId.values()].sort((a, b) => a.peerId.localeCompare(b.peerId));
}

export function selectRandomThreeHops(
  peers: readonly SignedPeerRecord[],
  excludePeerId?: string,
): [SignedPeerRecord, SignedPeerRecord, SignedPeerRecord] {
  const candidates = peers.filter((p) => p.peerId !== excludePeerId);
  const pool = candidates.length >= 3 ? [...candidates] : [...peers];
  if (pool.length < 3) {
    throw new Error(`Need at least 3 peers for 3-hop onion circuit, found ${pool.length}`);
  }
  // Fisher-Yates shuffle using CSPRNG
  for (let i = pool.length - 1; i > 0; i--) {
    const j = randomInt(0, i + 1);
    const tmp = pool[i]!;
    pool[i] = pool[j]!;
    pool[j] = tmp;
  }
  return [pool[0]!, pool[1]!, pool[2]!];
}

export async function sendViaThreeHopOnion<TResponse = unknown>(params: {
  peers: readonly SignedPeerRecord[];
  targetPeer: SignedPeerRecord;
  method: 'GET' | 'POST';
  path: string;
  body?: unknown;
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
    const chunkPayloadLimit = ONION_MAX_CHUNK_DATA_SIZE - 19;
    const msgId = randomBytes(16);
    const totalChunks = Math.ceil(envelopeBytes.length / chunkPayloadLimit);
    if (totalChunks > 16) {
      throw new Error(`Payload exceeds maximum 16-cell onion limit (${envelopeBytes.length} bytes)`);
    }
    for (let i = 0; i < totalChunks; i++) {
      const slice = envelopeBytes.subarray(i * chunkPayloadLimit, (i + 1) * chunkPayloadLimit);
      const header = Buffer.alloc(19);
      header[0] = 0x02;
      msgId.copy(header, 1);
      header[17] = i;
      header[18] = totalChunks;
      frames.push(Buffer.concat([header, slice]));
    }
  }

  let finalStatus = 500;
  let finalRaw = '';

  for (const frame of frames) {
    const packet = wrapOnionPacket(hopTargets, params.targetPeer.endpoint, frame);
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

export async function storeEncryptedThreadShards(params: {
  peers: readonly SignedPeerRecord[];
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

  // Pick 3 distinct storage peers deterministically-randomly
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
  peers: readonly SignedPeerRecord[];
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

export async function executeShieldedSpend(params: {
  keys: NuvertherWalletKeys;
  peers: readonly SignedPeerRecord[];
  inputs: [ShieldedNoteInput, ShieldedNoteInput];
  outputs: [ShieldedOutputSpec, ShieldedOutputSpec];
  fee: bigint;
  quorumSize?: number;
}): Promise<ShieldedSpendResult> {
  const quorumSize = params.quorumSize ?? 7;
  if (params.peers.length < quorumSize) {
    throw new Error(`Need at least ${quorumSize} peers, have ${params.peers.length}`);
  }

  const outBlindings: [bigint, bigint] = [
    params.outputs[0].blinding ?? randomFieldElement(),
    params.outputs[1].blinding ?? randomFieldElement(),
  ];
  const feeBlinding = randomFieldElement();

  // Pre-compute output commitments & fee commitment to derive txBinding
  const { computeCommitment } = await import('@nuverther/zk');
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
    ed25519PkHex: params.keys.ed25519PkHex,
    mldsa65PkB64: params.keys.mldsa65PkB64,
    outputCommitments: outCommitments,
    feeCommitment,
  });

  // 1. Generate Noir UltraHonk proof locally
  const proofBundle = await generateSpendProof({
    spendSecret: params.keys.spendSecret,
    inAmounts: [params.inputs[0].amount, params.inputs[1].amount],
    inBlindings: [params.inputs[0].blinding, params.inputs[1].blinding],
    inThreadIds: [params.inputs[0].threadId, params.inputs[1].threadId],
    outAmounts: [params.outputs[0].amount, params.outputs[1].amount],
    outOwnerPks: [params.outputs[0].recipientOwnerPk, params.outputs[1].recipientOwnerPk],
    outBlindings,
    fee: params.fee,
    feeBlinding,
    txBinding: BigInt(txBindingHex),
  });

  // 2. Hybrid Ed25519 + ML-DSA-65 spend signature
  const spenderSig = signCanonicalMessage(
    spendStatementPayload(proofBundle.publicSignals),
    params.keys,
  );

  // 3. Encrypt & store 2-of-3 Shamir Thread payload shards via 3-hop onion circuits
  const threadPayload: ThreadPayload = {
    version: 1,
    threadId: normalizeFieldHex(randomFieldElement()),
    recipientOwnerPk: normalizeFieldHex(params.outputs[0].recipientOwnerPk),
    amount: params.outputs[0].amount.toString(),
    blinding: normalizeFieldHex(outBlindings[0]),
    memo: params.outputs[0].memo,
    createdAt: new Date().toISOString(),
  };
  const shardResult = await storeEncryptedThreadShards({
    peers: params.peers,
    payload: threadPayload,
  });

  // 4. Deterministic 7-of-11 Witness Quorum selection via SHA3-256(nullifier || peer_id)
  const quorumPeers = selectWitnessQuorum(
    proofBundle.publicSignals.nullifiers[0],
    params.peers,
    quorumSize,
  );

  const attestBody = {
    proofBundle,
    spenderPub: {
      ed25519PkHex: params.keys.ed25519PkHex,
      mldsa65PkB64: params.keys.mldsa65PkB64,
    },
    spenderSig,
  };

  // 5. Route spend through 3 random onion hops: attest deterministic VRF leader quorum[0] first
  // to prevent split-quorum races, then fan out to quorum[1..k-1] in parallel.
  const verifyWitnessAttestation = async (witness: SignedPeerRecord): Promise<WitnessAttestation> => {
    const receipt = await retryWithBackoffAndJitter(async () => {
      const res = await sendViaThreeHopOnion<{ attestation: WitnessAttestation }>({
        peers: params.peers,
        targetPeer: witness,
        method: 'POST',
        path: '/v1/witness/attest',
        body: attestBody,
      });
      return res.data.attestation;
    });

    // Strict hybrid PQ signature verification on every Witness receipt
    const expectedProofSha = sha3Hex(Buffer.from(proofBundle.proofBase64, 'base64'));
    if (
      receipt.peerId !== witness.peerId ||
      receipt.ed25519PkHex !== witness.ed25519PkHex ||
      receipt.mldsa65PkB64 !== witness.mldsa65PkB64 ||
      receipt.proofSha256 !== expectedProofSha
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

    return receipt;
  };

  const primaryAttestation = await verifyWitnessAttestation(quorumPeers[0]!);
  const secondaryAttestations = await Promise.all(
    quorumPeers.slice(1).map((witness) => verifyWitnessAttestation(witness)),
  );
  const attestations = [primaryAttestation, ...secondaryAttestations];

  return {
    proofBundle,
    quorumWitnesses: quorumPeers.map((p) => p.peerId),
    attestations,
    threadKeyHex: shardResult.threadKeyHex,
    threadDigest: shardResult.threadDigest,
    shardPointers: shardResult.shardPointers,
  };
}

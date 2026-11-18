import { randomBytes } from 'node:crypto';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha3_256 } from '@noble/hashes/sha3.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';

export const ONION_PACKET_SIZE = 16_384;
export const ONION_HEADER_SLOTS = 3;
export const ONION_SLOT_SIZE = 320;
export const ONION_HEADER_SIZE = ONION_HEADER_SLOTS * ONION_SLOT_SIZE; // 960 bytes
export const ONION_BODY_SIZE = ONION_PACKET_SIZE - ONION_HEADER_SIZE; // 15,424 bytes
export const ONION_AEAD_TAG_SIZE = 16;
export const ONION_MAX_PLAINTEXT_SIZE = ONION_BODY_SIZE - 3 * ONION_AEAD_TAG_SIZE; // 15,376 bytes
export const ONION_MAX_CHUNK_DATA_SIZE = ONION_MAX_PLAINTEXT_SIZE - 2; // 15,374 bytes

const HYBRID_SIG_DOMAIN = Buffer.from('NUV_HYBRID_SIG_V1', 'utf8');
const HASHCASH_DOMAIN = Buffer.from('NUV_HASHCASH_V1', 'utf8');
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
    const okPq = ml_dsa65.verify(pqSig, digest, pqPk);
    return okPq;
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

/**
 * Deterministically selects a 7-of-11 (configurable k-of-N) Witness quorum
 * via SHA3-256(nullifier || peer_id) sorted lexicographically.
 */
export function selectWitnessQuorum<T extends { peerId: string }>(
  nullifier: string,
  peers: readonly T[],
  quorumSize = 7,
): T[] {
  if (peers.length < quorumSize) {
    throw new Error(`Insufficient peers for quorum: have ${peers.length}, need ${quorumSize}`);
  }
  const scored = peers.map((peer) => {
    const score = Buffer.from(
      sha3_256(Buffer.concat([Buffer.from(nullifier, 'utf8'), Buffer.from(peer.peerId, 'utf8')])),
    ).toString('hex');
    return { peer, score };
  });
  scored.sort((a, b) => (a.score < b.score ? -1 : a.score > b.score ? 1 : 0));
  return scored.slice(0, quorumSize).map((item) => item.peer);
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

function buildHeaderSlot(
  hopX25519Pk: Uint8Array,
  flag: number,
  url: string,
  bodyKey: Uint8Array,
  bodyNonce: Uint8Array,
  bodyCipherLen: number,
): Uint8Array {
  const ephem = x25519.keygen();
  const shared = x25519.getSharedSecret(ephem.secretKey, hopX25519Pk);
  const headerKey = deriveHeaderKey(shared, ephem.publicKey, hopX25519Pk);
  const headerNonce = randomBytes(24);

  const urlBytes = Buffer.from(url, 'utf8');
  if (urlBytes.length > 180) {
    throw new Error(`Onion hop URL too long (${urlBytes.length} > 180)`);
  }

  // Plaintext slot payload: 320 - 1 - 32 - 24 - 16 = 247 bytes
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

/**
 * Wraps a payload (<= 15,374 bytes) into a fixed 16,384-byte 3-hop XChaCha20-Poly1305 onion packet.
 * Every hop on the wire sees an identical 16,384-byte opaque binary frame.
 */
export function wrapOnionPacket(
  hops: [OnionHopTarget, OnionHopTarget, OnionHopTarget],
  terminalUrl: string,
  payload: Uint8Array,
): Uint8Array {
  if (payload.length > ONION_MAX_CHUNK_DATA_SIZE) {
    throw new RangeError(
      `Onion chunk exceeds max capacity (${payload.length} > ${ONION_MAX_CHUNK_DATA_SIZE})`,
    );
  }

  // Construct innermost plaintext frame: [len:2B][payload][CSPRNG pad] -> 15,376 bytes
  const innerPlain = new Uint8Array(ONION_MAX_PLAINTEXT_SIZE);
  randomBytes(ONION_MAX_PLAINTEXT_SIZE).copy(innerPlain);
  innerPlain[0] = (payload.length >> 8) & 0xff;
  innerPlain[1] = payload.length & 0xff;
  innerPlain.set(payload, 2);

  const bodyKeys = [randomBytes(32), randomBytes(32), randomBytes(32)];
  const bodyNonces = [randomBytes(24), randomBytes(24), randomBytes(24)];

  // Layer 3 (innermost, decrypted by Hop 3) -> 15,392 bytes
  const c3 = xchacha20poly1305(bodyKeys[2]!, bodyNonces[2]!).encrypt(innerPlain);
  // Layer 2 (decrypted by Hop 2) -> 15,408 bytes
  const c2 = xchacha20poly1305(bodyKeys[1]!, bodyNonces[1]!).encrypt(c3);
  // Layer 1 (outermost, decrypted by Hop 1) -> 15,424 bytes
  const c1 = xchacha20poly1305(bodyKeys[0]!, bodyNonces[0]!).encrypt(c2);

  const slot0 = buildHeaderSlot(
    new Uint8Array(Buffer.from(hops[0].x25519PkHex, 'hex')),
    0x01,
    hops[1].hopUrl,
    bodyKeys[0]!,
    bodyNonces[0]!,
    c1.length,
  );
  const slot1 = buildHeaderSlot(
    new Uint8Array(Buffer.from(hops[1].x25519PkHex, 'hex')),
    0x01,
    hops[2].hopUrl,
    bodyKeys[1]!,
    bodyNonces[1]!,
    c2.length,
  );
  const slot2 = buildHeaderSlot(
    new Uint8Array(Buffer.from(hops[2].x25519PkHex, 'hex')),
    0x02,
    terminalUrl,
    bodyKeys[2]!,
    bodyNonces[2]!,
    c3.length,
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
    // Shift header slots left by 1 slot and append 320 random bytes so wire size stays 16,384 bytes
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

import { randomBytes } from 'node:crypto';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { argon2idAsync } from '@noble/hashes/argon2.js';
import { sha3_256 } from '@noble/hashes/sha3.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { combine, split } from 'shamir-secret-sharing';
import { bytesToFieldScalar, computeOwnerPk, normalizeFieldHex } from '@nuverther/zk';
import { signHybrid, type HybridSignature } from '@nuverther/node';

export interface Argon2Params {
  t: number;
  m: number;
  p: number;
}

export const DEFAULT_ARGON2_PARAMS: Argon2Params = {
  t: 3,
  m: 65536, // 64 MiB
  p: 1,
};

export interface NuvertherWalletKeys {
  masterSeed: Uint8Array;
  spendSecret: bigint;
  ownerPk: bigint;
  ownerPkHex: string;
  ed25519Sk: Uint8Array;
  ed25519Pk: Uint8Array;
  ed25519PkHex: string;
  mldsa65Sk: Uint8Array;
  mldsa65Pk: Uint8Array;
  mldsa65PkB64: string;
}

export interface EncryptedKeystore {
  version: 1;
  kdf: 'argon2id';
  kdfParams: Argon2Params;
  saltHex: string;
  nonceHex: string;
  ciphertextB64: string;
  ownerPkHex: string;
  ed25519PkHex: string;
}

export async function deriveWalletFromSeed(masterSeed: Uint8Array): Promise<NuvertherWalletKeys> {
  if (masterSeed.length !== 32) {
    throw new RangeError(`Master seed must be 32 bytes, got ${masterSeed.length}`);
  }
  const spendSeed = sha3_256(Buffer.concat([masterSeed, Buffer.from('nuv-spend-v1', 'utf8')]));
  const edSeed = sha3_256(Buffer.concat([masterSeed, Buffer.from('nuv-ed25519-v1', 'utf8')]));
  const pqSeed = sha3_256(Buffer.concat([masterSeed, Buffer.from('nuv-mldsa65-v1', 'utf8')]));

  const spendSecret = bytesToFieldScalar(spendSeed);
  const ownerPk = await computeOwnerPk(spendSecret);
  const edKeys = ed25519.keygen(edSeed);
  const pqKeys = ml_dsa65.keygen(pqSeed);

  return {
    masterSeed: new Uint8Array(masterSeed),
    spendSecret,
    ownerPk,
    ownerPkHex: normalizeFieldHex(ownerPk),
    ed25519Sk: edKeys.secretKey,
    ed25519Pk: edKeys.publicKey,
    ed25519PkHex: Buffer.from(edKeys.publicKey).toString('hex'),
    mldsa65Sk: pqKeys.secretKey,
    mldsa65Pk: pqKeys.publicKey,
    mldsa65PkB64: Buffer.from(pqKeys.publicKey).toString('base64'),
  };
}

export async function generateWallet(): Promise<NuvertherWalletKeys> {
  const masterSeed = new Uint8Array(randomBytes(32));
  return deriveWalletFromSeed(masterSeed);
}

export async function encryptWalletKeystore(
  keys: NuvertherWalletKeys,
  passphrase: string,
  kdfParams: Argon2Params = DEFAULT_ARGON2_PARAMS,
): Promise<EncryptedKeystore> {
  if (passphrase.length < 8) {
    throw new Error('Passphrase must be at least 8 characters');
  }
  const salt = new Uint8Array(randomBytes(16));
  const nonce = new Uint8Array(randomBytes(24));
  const derivedKey = await argon2idAsync(passphrase, salt, {
    t: kdfParams.t,
    m: kdfParams.m,
    p: kdfParams.p,
    dkLen: 32,
  });

  const aad = Buffer.from(`${keys.ownerPkHex}|${keys.ed25519PkHex}`, 'utf8');
  const sealed = xchacha20poly1305(derivedKey, nonce, aad).encrypt(keys.masterSeed);

  return {
    version: 1,
    kdf: 'argon2id',
    kdfParams,
    saltHex: Buffer.from(salt).toString('hex'),
    nonceHex: Buffer.from(nonce).toString('hex'),
    ciphertextB64: Buffer.from(sealed).toString('base64'),
    ownerPkHex: keys.ownerPkHex,
    ed25519PkHex: keys.ed25519PkHex,
  };
}

export async function decryptWalletKeystore(
  keystore: EncryptedKeystore,
  passphrase: string,
): Promise<NuvertherWalletKeys> {
  const salt = new Uint8Array(Buffer.from(keystore.saltHex, 'hex'));
  const nonce = new Uint8Array(Buffer.from(keystore.nonceHex, 'hex'));
  const ciphertext = new Uint8Array(Buffer.from(keystore.ciphertextB64, 'base64'));
  const derivedKey = await argon2idAsync(passphrase, salt, {
    t: keystore.kdfParams.t,
    m: keystore.kdfParams.m,
    p: keystore.kdfParams.p,
    dkLen: 32,
  });

  const aad = Buffer.from(`${keystore.ownerPkHex}|${keystore.ed25519PkHex}`, 'utf8');
  const masterSeed = xchacha20poly1305(derivedKey, nonce, aad).decrypt(ciphertext);
  return deriveWalletFromSeed(masterSeed);
}

export async function splitMasterSeedShamir(
  masterSeed: Uint8Array,
  totalShares: number,
  threshold: number,
): Promise<string[]> {
  if (threshold < 2 || totalShares < threshold || totalShares > 255) {
    throw new RangeError(`Invalid Shamir threshold ${threshold}-of-${totalShares}`);
  }
  const shares = await split(masterSeed, totalShares, threshold);
  return shares.map((s) => Buffer.from(s).toString('hex'));
}

export async function recoverWalletFromShamirShares(
  shareHexList: string[],
): Promise<NuvertherWalletKeys> {
  if (shareHexList.length < 2) {
    throw new RangeError('At least 2 Shamir shares are required for recovery');
  }
  const shares = shareHexList.map((hex) => new Uint8Array(Buffer.from(hex, 'hex')));
  const recoveredSeed = await combine(shares);
  return deriveWalletFromSeed(recoveredSeed);
}

export function signCanonicalMessage(
  payload: string | Uint8Array,
  keys: NuvertherWalletKeys,
): HybridSignature {
  return signHybrid(payload, keys.ed25519Sk, keys.mldsa65Sk);
}

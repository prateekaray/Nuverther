import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  Barretenberg,
  BN254_FR_MODULUS,
  UltraHonkBackend,
  UltraHonkVerifierBackend,
} from '@aztec/bb.js';
import { Noir, type CompiledCircuit } from '@noir-lang/noir_js';

export { BN254_FR_MODULUS };

export const DOMAIN_OWNER = 0x4e55565f4f574e4552n;
export const DOMAIN_COMMITMENT = 0x4e55565f434f4d4d4954n;
export const DOMAIN_NULLIFIER = 0x4e55565f4e554c4cn;
export const DOMAIN_FEE = 0x4e55565f464545n;

export const MAX_U64 = (1n << 64n) - 1n;

const __dirname = dirname(fileURLToPath(import.meta.url));
const ARTIFACTS_DIR = resolve(__dirname, '../artifacts');

export interface ZkArtifactManifest {
  circuitName: string;
  noirVersion: string;
  noirJsVersion: string;
  bbJsVersion: string;
  circuitSha256: string;
  vkSha256: string;
  vkBytes: number;
}

export interface SpendWitnessInput {
  spendSecret: bigint;
  inAmounts: [bigint, bigint];
  inBlindings: [bigint, bigint];
  inThreadIds: [bigint, bigint];
  outAmounts: [bigint, bigint];
  outOwnerPks: [bigint, bigint];
  outBlindings: [bigint, bigint];
  fee: bigint;
  feeBlinding: bigint;
  txBinding: bigint;
}

export interface SpendPublicSignals {
  inputCommitments: [string, string];
  nullifiers: [string, string];
  outputCommitments: [string, string];
  feeCommitment: string;
  txBinding: string;
}

export interface SpendProofBundle {
  proofBase64: string;
  publicInputs: string[];
  publicSignals: SpendPublicSignals;
  vkSha256: string;
}

let cachedCircuit: CompiledCircuit | null = null;
let cachedVk: Uint8Array | null = null;
let cachedManifest: ZkArtifactManifest | null = null;
let bbPromise: Promise<Barretenberg> | null = null;

function sha256Hex(data: Uint8Array | string): string {
  return createHash('sha256').update(data).digest('hex');
}

export function loadZkArtifacts(): {
  circuit: CompiledCircuit;
  vk: Uint8Array;
  manifest: ZkArtifactManifest;
} {
  if (!cachedCircuit || !cachedVk || !cachedManifest) {
    const manifestRaw = readFileSync(resolve(ARTIFACTS_DIR, 'manifest.json'), 'utf8');
    const manifest = JSON.parse(manifestRaw) as ZkArtifactManifest;
    const circuitRaw = readFileSync(resolve(ARTIFACTS_DIR, 'nuverther_spend.json'), 'utf8');
    const vk = new Uint8Array(readFileSync(resolve(ARTIFACTS_DIR, 'nuverther_spend.vk.bin')));

    if (sha256Hex(circuitRaw) !== manifest.circuitSha256) {
      throw new Error('ZK circuit artifact SHA-256 mismatch against manifest');
    }
    if (sha256Hex(vk) !== manifest.vkSha256) {
      throw new Error('ZK verification key SHA-256 mismatch against manifest');
    }

    cachedManifest = manifest;
    cachedCircuit = JSON.parse(circuitRaw) as CompiledCircuit;
    cachedVk = vk;
  }
  return { circuit: cachedCircuit, vk: cachedVk, manifest: cachedManifest };
}

export async function getBarretenberg(): Promise<Barretenberg> {
  if (!bbPromise) {
    bbPromise = Barretenberg.new({ threads: 1 });
  }
  return bbPromise;
}

export async function destroyBarretenberg(): Promise<void> {
  if (bbPromise) {
    const bb = await bbPromise;
    bbPromise = null;
    await bb.destroy();
  }
}

export function bigintToFieldBytes(value: bigint): Uint8Array {
  if (value < 0n || value >= BN254_FR_MODULUS) {
    throw new RangeError(`Field value out of BN254 Fr range: ${value.toString()}`);
  }
  const buf = new Uint8Array(32);
  let v = value;
  for (let i = 31; i >= 0; i--) {
    buf[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return buf;
}

export function fieldBytesToBigint(bytes: Uint8Array): bigint {
  if (bytes.length !== 32) {
    throw new RangeError(`Expected 32-byte field element, got ${bytes.length}`);
  }
  let v = 0n;
  for (let i = 0; i < 32; i++) {
    v = (v << 8n) | BigInt(bytes[i]!);
  }
  return v;
}

export function normalizeFieldHex(input: string | bigint): string {
  const value = typeof input === 'bigint' ? input : BigInt(input);
  if (value < 0n || value >= BN254_FR_MODULUS) {
    throw new RangeError(`Field value out of BN254 Fr range: ${value.toString()}`);
  }
  return '0x' + value.toString(16).padStart(64, '0');
}

export function randomFieldElement(): bigint {
  const bytes = globalThis.crypto.getRandomValues(new Uint8Array(32));
  let val = 0n;
  for (const b of bytes) {
    val = (val << 8n) | BigInt(b);
  }
  return val % BN254_FR_MODULUS;
}

export function bytesToFieldScalar(bytes: Uint8Array): bigint {
  const digest = createHash('sha256').update(bytes).digest();
  let val = 0n;
  for (const b of digest) {
    val = (val << 8n) | BigInt(b);
  }
  const reduced = val % BN254_FR_MODULUS;
  return reduced === 0n ? 1n : reduced;
}

async function poseidon2Hash(inputs: bigint[]): Promise<bigint> {
  const bb = await getBarretenberg();
  const res = await bb.poseidon2Hash({
    inputs: inputs.map((v) => bigintToFieldBytes(v)),
  });
  return fieldBytesToBigint(res.hash);
}

export async function computeOwnerPk(spendSecret: bigint): Promise<bigint> {
  return poseidon2Hash([DOMAIN_OWNER, spendSecret]);
}

export async function computeCommitment(
  amount: bigint,
  ownerPk: bigint,
  blinding: bigint,
): Promise<bigint> {
  return poseidon2Hash([DOMAIN_COMMITMENT, amount, ownerPk, blinding]);
}

export async function computeNullifier(
  spendSecret: bigint,
  threadId: bigint,
): Promise<bigint> {
  return poseidon2Hash([DOMAIN_NULLIFIER, spendSecret, threadId]);
}

export async function computeFeeCommitment(
  fee: bigint,
  feeBlinding: bigint,
): Promise<bigint> {
  return poseidon2Hash([DOMAIN_FEE, fee, feeBlinding]);
}

export async function generateSpendProof(
  witnessInput: SpendWitnessInput,
): Promise<SpendProofBundle> {
  const { circuit, vk, manifest } = loadZkArtifacts();
  const bb = await getBarretenberg();

  const ownerPk = await computeOwnerPk(witnessInput.spendSecret);
  const inputCommitments: [string, string] = [
    normalizeFieldHex(
      await computeCommitment(
        witnessInput.inAmounts[0],
        ownerPk,
        witnessInput.inBlindings[0],
      ),
    ),
    normalizeFieldHex(
      await computeCommitment(
        witnessInput.inAmounts[1],
        ownerPk,
        witnessInput.inBlindings[1],
      ),
    ),
  ];

  const nullifiers: [string, string] = [
    normalizeFieldHex(
      await computeNullifier(witnessInput.spendSecret, witnessInput.inThreadIds[0]),
    ),
    normalizeFieldHex(
      await computeNullifier(witnessInput.spendSecret, witnessInput.inThreadIds[1]),
    ),
  ];

  const outputCommitments: [string, string] = [
    normalizeFieldHex(
      await computeCommitment(
        witnessInput.outAmounts[0],
        witnessInput.outOwnerPks[0],
        witnessInput.outBlindings[0],
      ),
    ),
    normalizeFieldHex(
      await computeCommitment(
        witnessInput.outAmounts[1],
        witnessInput.outOwnerPks[1],
        witnessInput.outBlindings[1],
      ),
    ),
  ];

  const feeCommitment = normalizeFieldHex(
    await computeFeeCommitment(witnessInput.fee, witnessInput.feeBlinding),
  );
  const txBinding = normalizeFieldHex(witnessInput.txBinding);

  const noir = new Noir(circuit);
  const { witness } = await noir.execute({
    spend_secret: normalizeFieldHex(witnessInput.spendSecret),
    in_amounts: witnessInput.inAmounts.map((v) => v.toString()),
    in_blindings: witnessInput.inBlindings.map((v) => normalizeFieldHex(v)),
    in_thread_ids: witnessInput.inThreadIds.map((v) => normalizeFieldHex(v)),
    out_amounts: witnessInput.outAmounts.map((v) => v.toString()),
    out_owner_pks: witnessInput.outOwnerPks.map((v) => normalizeFieldHex(v)),
    out_blindings: witnessInput.outBlindings.map((v) => normalizeFieldHex(v)),
    fee: witnessInput.fee.toString(),
    fee_blinding: normalizeFieldHex(witnessInput.feeBlinding),
    input_commitments: inputCommitments,
    nullifiers,
    output_commitments: outputCommitments,
    fee_commitment: feeCommitment,
    tx_binding: txBinding,
  });

  const backend = new UltraHonkBackend(circuit.bytecode, bb);
  const proofData = await backend.generateProof(witness);

  const verifiedLocally = await new UltraHonkVerifierBackend(bb).verifyProof({
    proof: proofData.proof,
    publicInputs: proofData.publicInputs,
    verificationKey: vk,
  });
  if (!verifiedLocally) {
    throw new Error('Generated proof failed local VK verification');
  }

  return {
    proofBase64: Buffer.from(proofData.proof).toString('base64'),
    publicInputs: proofData.publicInputs.map((p) => normalizeFieldHex(p)),
    publicSignals: {
      inputCommitments,
      nullifiers,
      outputCommitments,
      feeCommitment,
      txBinding,
    },
    vkSha256: manifest.vkSha256,
  };
}

export async function verifySpendProof(bundle: SpendProofBundle): Promise<boolean> {
  try {
    const { vk, manifest } = loadZkArtifacts();
    if (bundle.vkSha256 !== manifest.vkSha256) {
      return false;
    }
    if (!Array.isArray(bundle.publicInputs) || bundle.publicInputs.length !== 8) {
      return false;
    }

    const expectedOrder = [
      bundle.publicSignals.inputCommitments[0],
      bundle.publicSignals.inputCommitments[1],
      bundle.publicSignals.nullifiers[0],
      bundle.publicSignals.nullifiers[1],
      bundle.publicSignals.outputCommitments[0],
      bundle.publicSignals.outputCommitments[1],
      bundle.publicSignals.feeCommitment,
      bundle.publicSignals.txBinding,
    ].map((x) => normalizeFieldHex(x));

    const actualOrder = bundle.publicInputs.map((x) => normalizeFieldHex(x));
    for (let i = 0; i < 8; i++) {
      if (expectedOrder[i] !== actualOrder[i]) {
        return false;
      }
    }

    if (BigInt(expectedOrder[7]!) === 0n) {
      return false;
    }
    if (expectedOrder[2] === expectedOrder[3]) {
      return false;
    }

    const proofBytes = new Uint8Array(Buffer.from(bundle.proofBase64, 'base64'));
    if (proofBytes.length === 0) {
      return false;
    }

    const bb = await getBarretenberg();
    const verifier = new UltraHonkVerifierBackend(bb);
    return await verifier.verifyProof({
      proof: proofBytes,
      publicInputs: actualOrder,
      verificationKey: vk,
    });
  } catch {
    return false;
  }
}

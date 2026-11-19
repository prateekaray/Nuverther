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

export const TREE_DEPTH = 20;
export const MAX_TREE_LEAVES = 1 << TREE_DEPTH;

export const DOMAIN_OWNER = 0x4e55565f4f574e4552n;       // "NUV_OWNER"
export const DOMAIN_COMMITMENT = 0x4e55565f434f4d4d4954n; // "NUV_COMMIT"
export const DOMAIN_LEAF = 0x4e55565f4c454146n;           // "NUV_LEAF"
export const DOMAIN_MERKLE = 0x4e55565f4d45524b4c45n;     // "NUV_MERKLE"
export const DOMAIN_NULLIFIER = 0x4e55565f4e554c4cn;    // "NUV_NULL"
export const DOMAIN_FEE = 0x4e55565f464545n;            // "NUV_FEE"

export const MAX_U64 = (1n << 64n) - 1n;

const __dirname = dirname(fileURLToPath(import.meta.url));
const ARTIFACTS_DIR = resolve(__dirname, '../artifacts');

export interface ZkArtifactManifest {
  circuitName: string;
  treeDepth: number;
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
  inLeafIndices: [number, number];
  inMerklePaths: [bigint[], bigint[]];
  outAmounts: [bigint, bigint];
  outOwnerPks: [bigint, bigint];
  outBlindings: [bigint, bigint];
  fee: bigint;
  feeBlinding: bigint;
  authPkHash: bigint;
  txBinding: bigint;
  merkleRoot: bigint;
}

export interface SpendPublicSignals {
  merkleRoot: string;
  nullifiers: [string, string];
  outputCommitments: [string, string];
  feeCommitment: string;
  authPkHash: string;
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
    if (manifest.treeDepth !== TREE_DEPTH) {
      throw new Error(`ZK manifest treeDepth mismatch: ${manifest.treeDepth} !== ${TREE_DEPTH}`);
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
  const reduced = val % BN254_FR_MODULUS;
  return reduced === 0n ? 1n : reduced;
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

export async function poseidon2Hash(inputs: bigint[]): Promise<bigint> {
  const bb = await getBarretenberg();
  const res = await bb.poseidon2Hash({
    inputs: inputs.map((v) => bigintToFieldBytes(v)),
  });
  return fieldBytesToBigint(res.hash);
}

export async function computeOwnerPk(spendSecret: bigint, authPkHash: bigint): Promise<bigint> {
  return poseidon2Hash([DOMAIN_OWNER, spendSecret, authPkHash]);
}

export async function computeCommitment(
  amount: bigint,
  ownerPk: bigint,
  blinding: bigint,
): Promise<bigint> {
  return poseidon2Hash([DOMAIN_COMMITMENT, amount, ownerPk, blinding]);
}

export async function computeLeaf(commitment: bigint, leafIndex: number | bigint): Promise<bigint> {
  const idx = BigInt(leafIndex);
  if (idx < 0n || idx >= BigInt(MAX_TREE_LEAVES)) {
    throw new RangeError(`Leaf index out of range [0, ${MAX_TREE_LEAVES - 1}]: ${idx}`);
  }
  return poseidon2Hash([DOMAIN_LEAF, commitment, idx]);
}

export async function computeMerkleNode(left: bigint, right: bigint): Promise<bigint> {
  return poseidon2Hash([DOMAIN_MERKLE, left, right]);
}

export async function computeNullifier(spendSecret: bigint, leaf: bigint): Promise<bigint> {
  return poseidon2Hash([DOMAIN_NULLIFIER, spendSecret, leaf]);
}

export async function computeFeeCommitment(
  fee: bigint,
  feeBlinding: bigint,
): Promise<bigint> {
  return poseidon2Hash([DOMAIN_FEE, fee, feeBlinding]);
}

let cachedZeroHashes: bigint[] | null = null;

export async function getMerkleZeroHashes(): Promise<bigint[]> {
  if (!cachedZeroHashes) {
    const zeros: bigint[] = [0n];
    for (let lvl = 0; lvl < TREE_DEPTH; lvl++) {
      zeros.push(await computeMerkleNode(zeros[lvl]!, zeros[lvl]!));
    }
    cachedZeroHashes = zeros;
  }
  return cachedZeroHashes;
}

/**
 * Deterministic append-only Poseidon2 Merkle tree of depth 20.
 * Mirrors verify_merkle_path() in packages/zk/src/main.nr bit-for-bit.
 */
export class Poseidon2MerkleTree {
  private readonly leaves: bigint[] = [];
  private readonly levels: Map<number, bigint>[] = Array.from(
    { length: TREE_DEPTH + 1 },
    () => new Map<number, bigint>(),
  );

  private constructor(private readonly zeroHashes: bigint[]) {
    this.levels[TREE_DEPTH]!.set(0, zeroHashes[TREE_DEPTH]!);
  }

  static async create(initialCommitments: readonly bigint[] = []): Promise<Poseidon2MerkleTree> {
    const zeros = await getMerkleZeroHashes();
    const tree = new Poseidon2MerkleTree(zeros);
    for (const c of initialCommitments) {
      await tree.appendCommitment(c);
    }
    return tree;
  }

  get size(): number {
    return this.leaves.length;
  }

  getRoot(): bigint {
    return this.levels[TREE_DEPTH]!.get(0) ?? this.zeroHashes[TREE_DEPTH]!;
  }

  getRootHex(): string {
    return normalizeFieldHex(this.getRoot());
  }

  async appendCommitment(commitment: bigint): Promise<{ leafIndex: number; leaf: bigint; root: bigint }> {
    const leafIndex = this.leaves.length;
    if (leafIndex >= MAX_TREE_LEAVES) {
      throw new RangeError(`Merkle tree capacity reached (${MAX_TREE_LEAVES})`);
    }
    const leaf = await computeLeaf(commitment, leafIndex);
    this.leaves.push(leaf);
    this.levels[0]!.set(leafIndex, leaf);

    let idx = leafIndex;
    let current = leaf;
    for (let lvl = 0; lvl < TREE_DEPTH; lvl++) {
      const siblingIdx = idx ^ 1;
      const sibling = this.levels[lvl]!.get(siblingIdx) ?? this.zeroHashes[lvl]!;
      const isRight = (idx & 1) === 1;
      current = isRight
        ? await computeMerkleNode(sibling, current)
        : await computeMerkleNode(current, sibling);
      idx >>= 1;
      this.levels[lvl + 1]!.set(idx, current);
    }

    return { leafIndex, leaf, root: current };
  }

  getProof(leafIndex: number): { leaf: bigint; path: bigint[]; root: bigint } {
    if (leafIndex < 0 || leafIndex >= this.leaves.length) {
      throw new RangeError(`Leaf index ${leafIndex} does not exist in tree (size=${this.leaves.length})`);
    }
    const path: bigint[] = [];
    let idx = leafIndex;
    for (let lvl = 0; lvl < TREE_DEPTH; lvl++) {
      const siblingIdx = idx ^ 1;
      path.push(this.levels[lvl]!.get(siblingIdx) ?? this.zeroHashes[lvl]!);
      idx >>= 1;
    }
    return {
      leaf: this.leaves[leafIndex]!,
      path,
      root: this.getRoot(),
    };
  }
}

export async function generateSpendProof(
  witnessInput: SpendWitnessInput,
): Promise<SpendProofBundle> {
  const { circuit, vk, manifest } = loadZkArtifacts();
  const bb = await getBarretenberg();

  if (
    witnessInput.inMerklePaths[0].length !== TREE_DEPTH ||
    witnessInput.inMerklePaths[1].length !== TREE_DEPTH
  ) {
    throw new RangeError(`Merkle paths must have length ${TREE_DEPTH}`);
  }

  const ownerPk = await computeOwnerPk(witnessInput.spendSecret, witnessInput.authPkHash);
  const inLeaf0 = await computeLeaf(
    await computeCommitment(witnessInput.inAmounts[0], ownerPk, witnessInput.inBlindings[0]),
    witnessInput.inLeafIndices[0],
  );
  const inLeaf1 = await computeLeaf(
    await computeCommitment(witnessInput.inAmounts[1], ownerPk, witnessInput.inBlindings[1]),
    witnessInput.inLeafIndices[1],
  );

  const nullifiers: [string, string] = [
    normalizeFieldHex(await computeNullifier(witnessInput.spendSecret, inLeaf0)),
    normalizeFieldHex(await computeNullifier(witnessInput.spendSecret, inLeaf1)),
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

  const merkleRoot = normalizeFieldHex(witnessInput.merkleRoot);
  const feeCommitment = normalizeFieldHex(
    await computeFeeCommitment(witnessInput.fee, witnessInput.feeBlinding),
  );
  const authPkHash = normalizeFieldHex(witnessInput.authPkHash);
  const txBinding = normalizeFieldHex(witnessInput.txBinding);

  const noir = new Noir(circuit);
  const { witness } = await noir.execute({
    spend_secret: normalizeFieldHex(witnessInput.spendSecret),
    in_amounts: witnessInput.inAmounts.map((v) => v.toString()),
    in_blindings: witnessInput.inBlindings.map((v) => normalizeFieldHex(v)),
    in_leaf_indices: witnessInput.inLeafIndices.map((idx) => idx.toString()),
    in_merkle_paths: witnessInput.inMerklePaths.map((path) =>
      path.map((sibling) => normalizeFieldHex(sibling)),
    ),
    out_amounts: witnessInput.outAmounts.map((v) => v.toString()),
    out_owner_pks: witnessInput.outOwnerPks.map((v) => normalizeFieldHex(v)),
    out_blindings: witnessInput.outBlindings.map((v) => normalizeFieldHex(v)),
    fee: witnessInput.fee.toString(),
    fee_blinding: normalizeFieldHex(witnessInput.feeBlinding),
    merkle_root: merkleRoot,
    nullifiers,
    output_commitments: outputCommitments,
    fee_commitment: feeCommitment,
    auth_pk_hash: authPkHash,
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
      merkleRoot,
      nullifiers,
      outputCommitments,
      feeCommitment,
      authPkHash,
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
      bundle.publicSignals.merkleRoot,
      bundle.publicSignals.nullifiers[0],
      bundle.publicSignals.nullifiers[1],
      bundle.publicSignals.outputCommitments[0],
      bundle.publicSignals.outputCommitments[1],
      bundle.publicSignals.feeCommitment,
      bundle.publicSignals.authPkHash,
      bundle.publicSignals.txBinding,
    ].map((x) => normalizeFieldHex(x));

    const actualOrder = bundle.publicInputs.map((x) => normalizeFieldHex(x));
    for (let i = 0; i < 8; i++) {
      if (expectedOrder[i] !== actualOrder[i]) {
        return false;
      }
    }

    if (
      BigInt(expectedOrder[0]!) === 0n ||
      BigInt(expectedOrder[6]!) === 0n ||
      BigInt(expectedOrder[7]!) === 0n
    ) {
      return false;
    }
    if (expectedOrder[1] === expectedOrder[2]) {
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

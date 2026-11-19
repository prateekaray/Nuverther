import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Barretenberg, UltraHonkBackend } from '@aztec/bb.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const pkgRoot = resolve(__dirname, '..');
const rootPkgPath = resolve(pkgRoot, '../../package.json');
const targetJsonPath = resolve(pkgRoot, 'target/nuverther_spend.json');
const artifactsDir = resolve(pkgRoot, 'artifacts');
const artifactCircuitPath = resolve(artifactsDir, 'nuverther_spend.json');
const artifactVkPath = resolve(artifactsDir, 'nuverther_spend.vk.bin');
const manifestPath = resolve(artifactsDir, 'manifest.json');

const PINNED_NOIR_PREFIX = 'nargo version = 1.0.0';

function findNargo() {
  const candidates = ['nargo', `${process.env.HOME ?? '/root'}/.nargo/bin/nargo`];
  for (const bin of candidates) {
    try {
      const version = execFileSync(bin, ['--version'], { encoding: 'utf8' });
      return { bin, version: version.trim() };
    } catch {
      // try next candidate
    }
  }
  return null;
}

function sha256Hex(buf) {
  return createHash('sha256').update(buf).digest('hex');
}

function sortKeysDeterministic(value) {
  if (Array.isArray(value)) {
    return value.map(sortKeysDeterministic);
  }
  if (value && typeof value === 'object') {
    const out = {};
    for (const key of Object.keys(value).sort()) {
      out[key] = sortKeysDeterministic(value[key]);
    }
    return out;
  }
  return value;
}

async function main() {
  mkdirSync(artifactsDir, { recursive: true });
  const nargo = findNargo();
  if (nargo) {
    if (!nargo.version.startsWith(PINNED_NOIR_PREFIX)) {
      throw new Error(
        `Pinned Noir compiler mismatch: expected "${PINNED_NOIR_PREFIX}...", found "${nargo.version.split('\n')[0]}"`,
      );
    }
    execFileSync(nargo.bin, ['compile', '--program-dir', pkgRoot], { stdio: 'inherit' });
  } else if (!existsSync(targetJsonPath)) {
    throw new Error(
      'nargo binary not found and compiled circuit target/nuverther_spend.json is missing.',
    );
  }

  const circuitRaw = readFileSync(targetJsonPath, 'utf8');
  const circuit = JSON.parse(circuitRaw);
  // Strip nondeterministic file/path debug fields if present before canonical JSON serialization
  const sanitized = {
    noir_version: circuit.noir_version,
    hash: circuit.hash,
    abi: sortKeysDeterministic(circuit.abi),
    bytecode: circuit.bytecode,
    debug_symbols: circuit.debug_symbols,
    file_map: sortKeysDeterministic(circuit.file_map ?? {}),
  };
  const canonicalCircuit = JSON.stringify(sanitized);
  writeFileSync(artifactCircuitPath, canonicalCircuit, 'utf8');

  const rootPkg = JSON.parse(readFileSync(rootPkgPath, 'utf8'));
  const bb = await Barretenberg.new({ threads: 1 });
  try {
    const backend = new UltraHonkBackend(sanitized.bytecode, bb);
    const vk = await backend.getVerificationKey();
    writeFileSync(artifactVkPath, vk);

    const manifest = {
      circuitName: 'nuverther_spend',
      treeDepth: 20,
      noirVersion: nargo ? nargo.version.split('\n')[0] : PINNED_NOIR_PREFIX,
      noirJsVersion: rootPkg.dependencies['@noir-lang/noir_js'],
      bbJsVersion: rootPkg.dependencies['@aztec/bb.js'],
      circuitSha256: sha256Hex(Buffer.from(canonicalCircuit, 'utf8')),
      vkSha256: sha256Hex(vk),
      vkBytes: vk.length,
    };
    writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + '\n', 'utf8');
    console.log('Compiled Nuverther ZK artifacts:', manifest);
  } finally {
    await bb.destroy();
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

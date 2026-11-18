# Nuverther

**A non-blockchain, quantum-resistant shielded value mesh.**

Nuverther replaces global replicated ledgers and linear blocks with deterministic **7-of-11 Witness quorums**, **hash-based Poseidon2 zero-knowledge proofs** (Noir / UltraHonk), **hybrid Ed25519 + ML-DSA-65 (FIPS 204)** post-quantum signatures, **stateless 3-hop 16 KB XChaCha20-Poly1305 onion relays**, **2-of-3 Shamir blind shard storage**, and **PostgreSQL `SERIALIZABLE` atomic nullifier consensus**.

For the formal cryptographic specification, threat model, and impossibility arguments, read the **[Nuverther Whitepaper](./WHITEPAPER.md)**.

---

## Core Architecture

```
  ┌───────────────────────────────────────────────────────────────────────┐
  │ Client SDK & CLI (packages/client)                                    │
  │  • Argon2id + XChaCha20-Poly1305 encrypted keystore                   │
  │  • M-of-N GF(256) Shamir seed backup & recovery                       │
  │  • Local Noir UltraHonk proof generation (packages/zk)                │
  │  • Hybrid Ed25519 + ML-DSA-65 spend authorization                     │
  │  • 2-of-3 Shamir encrypted Thread sharding                            │
  │  • Fixed 16,384 B 3-hop X25519 + XChaCha20-Poly1305 onion framing     │
  └───────────────────┬─────────────────────────────────┬─────────────────┘
                      │ 3-hop 16 KB onion frames        │ 3-hop 16 KB onion frames
                      ▼                                 ▼
  ┌─────────────────────────────────┐ ┌───────────────────────────────────┐
  │ Stateless Relay Hop 1 -> Hop 2  │ │ Terminal Hop 3 (/v1/relay)        │
  │  • Unwraps 1 header slot (320 B)│ │  • Reassembles 0x01 / 0x02 frames │
  │  • Re-pads to 16,384 B          │ │  • Dispatches without user IP     │
  └───────────────────┬─────────────┘ └─────────────────┬─────────────────┘
                      │                                 │
                      ▼                                 ▼
  ┌───────────────────────────────────────────────────────────────────────┐
  │ 7-of-11 VRF Witness & Blind Shard Nodes (packages/node)               │
  │  • Quorum selected deterministically: SHA3-256(nullifier || peer_id)  │
  │  • Sybil-resistant peer registry: SHA3-256 Hash-Cash + hybrid self-sig│
  │  • Verifies txBinding, Ed25519 + ML-DSA-65, and UltraHonk ZK proof    │
  │  • PostgreSQL SERIALIZABLE INSERT ... ON CONFLICT DO NOTHING          │
  │  • Blind Shard Storage: XChaCha20-Poly1305 + SHA3-256 MAC only        │
  └───────────────────────────────────────────────────────────────────────┘
```

### Repository Layout

| Path | Package / Role | Description |
| :--- | :--- | :--- |
| `packages/zk` | `@nuverther/zk` | Noir `1.0.0` Poseidon2 2-in-2-out spend circuit, deterministic compiler, Barretenberg UltraHonk prover/verifier, and integrity manifest |
| `packages/node` | `@nuverther/node` | Express 5 Witness, Stateless Onion Relay, Blind Shard Storage, Hash-Cash Peer Directory, PostgreSQL `SERIALIZABLE` DB layer, and Prometheus metrics |
| `packages/client` | `@nuverther/client` | Argon2id keystore custody, Shamir recovery, 3-hop onion client transport, Witness receipt verification, and CLI (`nuverther`) |
| `tests/adversarial.test.ts` | Adversarial Suite | Zero-mock Vitest verification suite against live PostgreSQL and an 11-node HTTP mesh |
| `Dockerfile` & `docker-compose.yml` | Deployment | Non-root multi-stage container build + 11-node cluster + PostgreSQL 15 + Caddy TLS reverse proxy (`Caddyfile`) |
| `WHITEPAPER.md` | Protocol Spec | Formal cryptographic design, security proofs, wire framing, and PostgreSQL concurrency invariants |

---

## Cryptographic Primitives & Invariants

No custom cryptography is used; every primitive comes from standard, audited implementations:

- **Zero-Knowledge Spend Circuit (`packages/zk/src/main.nr`)**
  - **Commitments**: `C = Poseidon2("NUV_COMMIT", amount, owner_pk, blinding)` over BN254 `Fr` (`rate = 3`, `width = 4`, `iv = len * 2^64`).
  - **Nullifiers**: `N = Poseidon2("NUV_NULL", spend_secret, thread_id)` — unique per spent input thread and unlinkable to commitments.
  - **Range & Overflow Safety**: Strict `assert_max_bit_size::<64>()` on `in_amounts[0..1]`, `out_amounts[0..1]`, and `fee`. Maximum sum is $< 2^{65} \ll p_{\text{BN254}}$, making integer overflow and field wrap-around impossible.
  - **Conservation**: Proves `sum(in_amounts) == sum(out_amounts) + fee` with **zero plaintext amounts or keys** in the 8 public inputs.
  - **Context Binding**: `tx_binding != 0` binds spender hybrid public keys, output commitments, and the hidden `fee_commitment` into the ZK proof.
- **Hybrid Post-Quantum Authentication (`@noble/post-quantum` + `@noble/curves`)**
  - Every spend authorization, Witness attestation receipt, and peer directory record carries **both** `Ed25519` (64 B signature) and FIPS 204 `ML-DSA-65` (3,309 B signature) over `SHA3-256("NUV_HYBRID_SIG_V1" || payload)`. Both must verify.
- **Stateless 3-Hop Onion Relay (`16,384` B fixed cells)**
  - Fixed `16,384`-byte binary packets (`960 B` 3-slot `X25519 + HKDF-SHA3-256 + XChaCha20-Poly1305` header + `15,424 B` nested AEAD body).
  - Intermediate relays unwrap one slot, shift slots left, CSPRNG-pad tail bytes to `16,384` B, and forward without retaining state.
  - Payloads exceeding a single `15,373` B cell (such as UltraHonk proofs + ML-DSA-65 signatures) are split into uniform `16,384` B `0x02` frames reassembled strictly at Hop 3, keeping Hops 1–2 stateless and hiding the originating IP from target Witnesses.
- **Atomic Double-Spend Prevention (`PostgreSQL SERIALIZABLE`)**
  - Every Witness node executes `BEGIN ISOLATION LEVEL SERIALIZABLE` followed by `INSERT INTO spent_nullifiers (...) VALUES (...), (...) ON CONFLICT (nullifier) DO NOTHING RETURNING nullifier`.
  - Transactions claiming fewer than 2 rows or raising `40001` / `23505` roll back and return `409 ERR_DOUBLE_SPEND`.
  - The client sequences the deterministic VRF leader `quorum[0]` (`SHA3-256(nullifier || peer_id)`) before fanning out to `quorum[1..6]` in parallel, preventing split-quorum livelocks under concurrent races.

---

## Quick Start

### Prerequisites

- **Node.js** `>= 22.0.0`
- **PostgreSQL** `>= 15`
- **Noir (`nargo`)** `1.0.0` (optional; deterministic compiled artifacts are committed in `packages/zk/artifacts/`, required only when modifying `packages/zk/src/main.nr`)

### 1. Install Dependencies

```bash
npm install
cp .env.example .env
```

### 2. Verify Circuit & Build Artifacts

```bash
# Run Noir unit tests (valid spend, 2^64 - 1 overflow rejection, > 2^64 rejection)
npm run zk:test

# Recompile circuit + UltraHonk verification key + SHA-256 manifest
npm run zk:compile

# Strict TypeScript compilation & ESLint
npm run typecheck
npm run lint
```

Pinned artifact checksums in `packages/zk/artifacts/manifest.json`:
- `circuitSha256`: `a4077034987c92441951b377cc4232da304caed7b2b8996a791a768028a93a8d`
- `vkSha256`: `b90f3c8c5087d8d901e46b94f655cdd1c55c2693bdc05d73c55868f9d128a2e7` (`3,680` bytes)

### 3. Run the Adversarial & Concurrency Verification Suite

Ensure PostgreSQL 15+ is running and `DATABASE_URL` points to an accessible instance:

```bash
DATABASE_URL="postgresql://postgres:postgres@127.0.0.1:5432/postgres" npm test
```

The zero-mock Vitest suite boots **11 live HTTP Witness/Relay/Shard nodes** backed by PostgreSQL and verifies:
0. **Quantum-safe key custody**: `Argon2id` + `XChaCha20-Poly1305` encryption and `2-of-3` Shamir recovery.
1. **50-way concurrent double-spend race**: 50 parallel spends of the same nullifier routed through 3-hop onion circuits $\rightarrow$ **1 succeeds**, **49 fail atomically** with `ERR_DOUBLE_SPEND`.
2. **Amount inflation & 64-bit overflow**: `2^64 - 1` wrap-around, `>= 2^64` range violation, and modified output commitment $\rightarrow$ rejected by Noir proving and Witness verification (`403`).
3. **Node breach & IP privacy**: Dumping every PostgreSQL table across all 11 nodes confirms zero plaintext amounts, zero keys, and zero client IP addresses on Witness/Storage schemas, plus strict `16,384` B packet enforcement on `/v1/relay`.
4. **Tampered shard / forged PQ & ZK signatures**: 1-byte bit flips in blind shard ciphertext, `Ed25519` signature, `ML-DSA-65` signature, or UltraHonk proof $\rightarrow$ rejected immediately (`400` / `403`) with zero nullifiers claimed.

---

## Deploying an 11-Node Cluster (Docker Compose)

The included `Dockerfile`, `docker-compose.yml`, and `Caddyfile` deploy a complete 11-node mesh (`node-01` through `node-11`) with PostgreSQL 15 and internal TLS termination via Caddy:

```bash
POSTGRES_PASSWORD="change_me_in_production" \
NUVERTHER_NODE_SEED="change_me_cluster_seed" \
docker compose up --build -d
```

Every node container runs as non-root user `nuverther` (`uid 1001`) with a `read_only: true` root filesystem, `/healthz` container healthcheck, and `NUVERTHER_HASHCASH_BITS=16`.

---

## Node HTTP API (`packages/node`)

| Method & Path | Description |
| :--- | :--- |
| `GET /healthz` | Liveness probe (`200 { status: "ok", peerId }`) |
| `GET /readyz` | PostgreSQL connectivity readiness probe (`200` / `503`) |
| `GET /metrics` | Prometheus metrics (`nuverther_witness_attestations_total`, `nuverther_onion_relay_packets_total`, `nuverther_witness_attest_seconds`, default Node metrics) |
| `GET /v1/identity` | Returns node's Hash-Cash + hybrid self-signed `SignedPeerRecord` |
| `GET /v1/peers` | Lists verified Witness peers registered in PostgreSQL |
| `POST /v1/peers` | Registers a new peer after verifying Hash-Cash difficulty and `Ed25519 + ML-DSA-65` self-signature |
| `POST /v1/relay` | Accepts strictly `16,384` B `application/octet-stream` onion cells; forwards Hop 1/2 or reassembles Hop 3 |
| `POST /v1/witness/attest` | Verifies `txBinding`, `Ed25519 + ML-DSA-65` spender sig, and Noir UltraHonk proof; commits nullifiers atomically (`SERIALIZABLE`) and returns signed receipt |
| `POST /v1/shards` | Stores an encrypted 2-of-3 Shamir share after verifying `SHA3-256` MAC tag (`NUV_SHARD_V1`) |
| `GET /v1/shards/:shardId` | Retrieves a blind encrypted shard and verifies stored MAC integrity |

---

## Client CLI Usage (`packages/client`)

```bash
# 1. Generate an Argon2id + XChaCha20-Poly1305 encrypted wallet
npx tsx packages/client/src/cli.ts keygen --out alice.json --passphrase "correct-horse-quantum-battery"

# 2. Split master seed into 2-of-3 Shamir threshold recovery shares
npx tsx packages/client/src/cli.ts split-key --wallet alice.json --passphrase "correct-horse-quantum-battery" --total 3 --threshold 2

# 3. Recover a wallet from any 2 Shamir shares
npx tsx packages/client/src/cli.ts recover-key --shares "<share1_hex>,<share3_hex>" --out recovered.json --passphrase "new-strong-passphrase"

# 4. Discover Hash-Cash + PQ verified mesh peers
npx tsx packages/client/src/cli.ts peers --seeds "http://127.0.0.1:4101"

# 5. Execute a shielded 2-in-2-out spend across 3-hop onion circuits & 7-of-11 Witnesses
npx tsx packages/client/src/cli.ts spend \
  --wallet alice.json \
  --passphrase "correct-horse-quantum-battery" \
  --seeds "http://127.0.0.1:4101" \
  --in0 1000 --in1 500 --out0 1200 --out1 290 --fee 10
```

---

## Security & Operational Hardening Checklist

- **Database Isolation**: Each Witness node uses its own PostgreSQL schema (`NUVERTHER_DB_SCHEMA`) or isolated PostgreSQL instance to prevent shared-table bypasses in production.
- **Transport Security**: Always terminate TLS in front of Witness/Relay/Shard endpoints (via `Caddyfile` or `NUVERTHER_TLS_CERT` / `NUVERTHER_TLS_KEY`) when operating over untrusted networks.
- **Rate Limiting & Validation**: All inputs are validated by strict `zod` schemas, security headers are enforced by `helmet`, and per-IP `TokenBucketRateLimiter` caps request bursts (`429 RATE_LIMIT_EXCEEDED`).
- **Zero-Log IP Policy**: `pino` explicitly redacts `req.headers.x-forwarded-for` and `req.remoteAddress`, and Witness/Shard PostgreSQL tables contain no IP address, amount, or plaintext key columns.

---

## License

Released under the [MIT License](./LICENSE).

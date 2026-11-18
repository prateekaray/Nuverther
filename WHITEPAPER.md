# Nuverther: A Non-Blockchain, Quantum-Resistant Shielded Value Mesh

**Version 1.0 — November 2026**

---

## Abstract

Public blockchains couple transaction finality to a globally replicated, monotonically growing sequence of blocks. That coupling imposes fundamental bottlenecks—global broadcast overhead, MEV/mempool metadata leakage, and permanent on-chain linkability—even when zero-knowledge proofs conceal plaintext amounts. Moreover, deployed elliptic-curve signature schemes and commitment assumptions face long-term harvest-now, decrypt-later exposure against fault-tolerant quantum computers.

**Nuverther** eliminates the global blockchain entirely. Instead of mining or ordering transactions into blocks, Nuverther settles confidential value transfers directly across a decentralized **Shielded Value Mesh** of independent Witness, Onion Relay, and Blind Shard nodes. Each transfer proves strict 64-bit value conservation inside a **pure hash-based Poseidon2 Noir UltraHonk circuit**, binds authorization with **hybrid classical + post-quantum signatures (Ed25519 + FIPS 204 ML-DSA-65)**, conceals client network identity behind **stateless 3-hop fixed 16 KB XChaCha20-Poly1305 onion circuits**, splits encrypted note payloads into **2-of-3 GF(256) Shamir blind shards**, and prevents double-spends atomically via **PostgreSQL `SERIALIZABLE` nullifier consensus** over deterministic **7-of-11 VRF Witness quorums**.

---

## 1. Design Goals & Threat Model

### 1.1 Design Goals

1. **No Global Ledger / No Blocks**: Transfers settle in one round of deterministic quorum attestation without waiting for block intervals or storing global state history on every client.
2. **Post-Quantum Authenticity & Long-Term Privacy**: Spend authorization and Witness attestations require *both* `Ed25519` and NIST FIPS 204 `ML-DSA-65`, while note commitments and nullifiers rely purely on algebraic hashing (`Poseidon2`) rather than hiding Pedersen exponents against Shor's algorithm.
3. **Zero Plaintext Exposure at Rest or in Transit**: Witness and Blind Shard databases never observe plaintext amounts, memos, private spend secrets, recipient public keys, or client IP addresses.
4. **Concurrency-Safe Atomic Double-Spend Prevention**: Parallel spend races for the same nullifier resolve deterministically with at most one winner and zero phantom state corruption.
5. **Single-Developer Maintainability**: Clean 3-package TypeScript (Node.js 22 strict mode) + Noir monorepo using audited standard libraries (`@aztec/bb.js`, `@noir-lang/noir_js`, `@noble/*`, `pg`) with zero custom cryptographic primitives.

### 1.2 Adversarial Model

Nuverther assumes a Byzantine adversary $\mathcal{A}$ capable of:
- Submitting $k$-way concurrent double-spend races for identical or overlapping input threads across all quorum Witnesses;
- Controlling up to $f < \lfloor N/3 \rfloor$ colluding Witness/Relay/Storage nodes (for $N=11, k=7$, up to $3$ Byzantine Witnesses cannot forge a 7-of-11 quorum or break safety);
- Compromising PostgreSQL snapshots of arbitrary Witness or Storage nodes (`node breach`);
- Inspecting wire-level packet sizes and timing between onion hops;
- Mutating arbitrary bytes in shards, `Ed25519` signatures, `ML-DSA-65` signatures, or Noir proof bytes;
- Possessing a future quantum computer capable of breaking discrete logarithms over Curve25519 (`Ed25519` / `X25519`) retrospectively or prospectively.

**Honesty Assumption**: Because `ML-DSA-65` relies on Module-LWE/SIS lattice assumptions and `Poseidon2` / `SHA3-256` / `XChaCha20-Poly1305` rely on symmetric/algebraic hash security, spend authorization and hash commitments resist quantum polynomial-time attacks. Note that current Barretenberg `UltraHonk` over BN254 provides classical zero-knowledge soundness; swapping the proving backend to a pure hash-based SNARK/STARK requires zero changes to the Noir circuit (`Poseidon2` only) or client/node protocol framing.

---

## 2. Cryptographic State Model

### 2.1 Shielded Notes and Threads

Value in Nuverther lives in confidential **Notes** carried over off-ledger encrypted **Threads**. A Note with integer value $v \in [0, 2^{64} - 1]$, owner public key $\mathsf{pk}_{\text{owner}}$, unique thread identifier $\mathsf{tid} \in \mathbb{F}_r$, and random blinding scalar $b \in \mathbb{F}_r$ is committed as:

$$C = \mathrm{Poseidon2}\big(\mathsf{DOM\_COMMIT}, v, \mathsf{pk}_{\text{owner}}, b\big)$$

where $\mathsf{DOM\_COMMIT} = \text{0x4e55565f434f4d4d4954}$ (`"NUV_COMMIT"` in ASCII) and $\mathbb{F}_r$ is the BN254 scalar field ($r \approx 2^{254}$).

An owner's zero-knowledge public key derives from a 256-bit master seed $S$ via domain-separated `SHA3-256` key expansion:

$$\mathsf{sk}_{\text{spend}} = \mathrm{SHA3\text{-}256}(S \parallel \text{"nuv-spend-v1"}) \bmod r$$
$$\mathsf{pk}_{\text{owner}} = \mathrm{Poseidon2}\big(\mathsf{DOM\_OWNER}, \mathsf{sk}_{\text{spend}}\big)$$

### 2.2 Nullifiers

Spending an input thread $\mathsf{tid}_i$ deterministically reveals a domain-separated **nullifier**:

$$N_i = \mathrm{Poseidon2}\big(\mathsf{DOM\_NULL}, \mathsf{sk}_{\text{spend}}, \mathsf{tid}_i\big)$$

Without knowledge of $\mathsf{sk}_{\text{spend}}$, $N_i$ is computationally indistinguishable from a uniform random field element and cannot be linked to its input commitment $C_i$.

### 2.3 Poseidon2 Sponge Alignment

To prevent circuit-to-TypeScript prover divergence without external Noir dependencies, `packages/zk/src/main.nr` implements the exact Barretenberg `poseidon2Hash` sponge specification over `std::hash::poseidon2_permutation` (state width $t = 4$, rate $R = 3$, initial capacity $\text{iv} = \text{len} \cdot 2^{64}$):
- 2-ary hash: $\Pi([a, b, 0, 2 \cdot 2^{64}])[0]$
- 3-ary hash: $\Pi([a, b, c, 3 \cdot 2^{64}])[0]$
- 4-ary hash: $s_1 = \Pi([a, b, c, 4 \cdot 2^{64}])$, $s_2 = \Pi([s_1[0] + d, s_1[1], s_1[2], s_1[3]])$, output $s_2[0]$.

Every compiled circuit artifact is pinned via SHA-256 in `packages/zk/artifacts/manifest.json` (`circuitSha256` and `vkSha256`), and both prover and Witness verify manifest integrity before loading the UltraHonk verification key (`3,680` bytes).

---

## 3. Zero-Knowledge Circuit Specification (`packages/zk`)

The Nuverther 2-in-2-out spend relation $\mathcal{R}_{\text{spend}}$ enforces five invariants over **private witness** inputs `(spend_secret, in_amounts[2], in_blindings[2], in_thread_ids[2], out_amounts[2], out_owner_pks[2], out_blindings[2], fee, fee_blinding)` and **8 public inputs** `(input_commitments[2], nullifiers[2], output_commitments[2], fee_commitment, tx_binding)`:

1. **Non-Zero Context Binding**:
   $$\mathsf{tx\_binding} \neq 0$$
2. **Distinct Input Threads**:
   $$\mathsf{in\_thread\_ids}[0] \neq \mathsf{in\_thread\_ids}[1]$$
   (combined with runtime verifier check $N_0 \neq N_1$).
3. **Strict 64-Bit Unsigned Range Enforcement**:
   $$\forall i \in \{0,1\}: \quad 0 \le v^{\text{in}}_i < 2^{64}, \quad 0 \le v^{\text{out}}_i < 2^{64}, \quad 0 \le \mathsf{fee} < 2^{64}$$
   enforced via `assert_max_bit_size::<64>()`.
4. **Commitment & Nullifier Consistency**:
   $$\mathsf{pk}_{\text{owner}} = \mathrm{Poseidon2}(\mathsf{DOM\_OWNER}, \mathsf{spend\_secret})$$
   $$\forall i \in \{0,1\}: \quad C^{\text{in}}_i = \mathrm{Poseidon2}(\mathsf{DOM\_COMMIT}, v^{\text{in}}_i, \mathsf{pk}_{\text{owner}}, b^{\text{in}}_i)$$
   $$\forall i \in \{0,1\}: \quad N_i = \mathrm{Poseidon2}(\mathsf{DOM\_NULL}, \mathsf{spend\_secret}, \mathsf{tid}_i)$$
   $$\forall i \in \{0,1\}: \quad C^{\text{out}}_i = \mathrm{Poseidon2}(\mathsf{DOM\_COMMIT}, v^{\text{out}}_i, \mathsf{pk}^{\text{out}}_i, b^{\text{out}}_i)$$
   $$C_{\text{fee}} = \mathrm{Poseidon2}(\mathsf{DOM\_FEE}, \mathsf{fee}, b_{\text{fee}})$$
5. **Overflow-Proof Value Conservation**:
   $$v^{\text{in}}_0 + v^{\text{in}}_1 = v^{\text{out}}_0 + v^{\text{out}}_1 + \mathsf{fee}$$

**Proof of Non-Overflow**: Because every summand is strictly bounded by $2^{64} - 1$, the maximum achievable sum on either side is:

$$3 \cdot (2^{64} - 1) < 2^{66} \ll r \approx 2^{254}$$

Therefore, addition inside $\mathbb{F}_r$ never wraps modulo $r$, eliminating modular arithmetic inflation attacks (`2^64 - 1` wrap-around) unconditionally. Plaintext amounts, keys, and recipient identities never enter the public input vector.

---

## 4. Hybrid Post-Quantum Authorization & Context Binding

Zero-knowledge proofs alone do not bind a transaction to a post-quantum spending authorization key unless the signature payload and public keys are cryptographically anchored into the proof's public inputs.

1. **Transaction Context Binding (`tx_binding`)**:
   $$\mathsf{tx\_binding} = \mathrm{SHA3\text{-}256}\Big(\text{JSON}\big([\text{"NUV\_TX\_BIND\_V1"}, \mathsf{pk}_{\text{ed}}, \mathsf{pk}_{\text{mldsa}}, C^{\text{out}}_0, C^{\text{out}}_1, C_{\text{fee}}]\big)\Big) \bmod r$$
   (mapped to `1` if `0 mod r`). Because $\mathsf{tx\_binding}$ is a public input to the Noir proof, an attacker cannot strip or substitute the spender's public keys onto an existing proof.

2. **Hybrid Dual-Signature Scheme (`signHybrid` / `verifyHybrid`)**:
   For any canonical payload $M$:
   $$d = \mathrm{SHA3\text{-}256}(\text{"NUV\_HYBRID\_SIG\_V1"} \parallel M)$$
   $$\sigma = \big(\mathrm{Ed25519.Sign}(\mathsf{sk}_{\text{ed}}, d),\; \mathrm{ML\text{-}DSA\text{-}65.Sign}(\mathsf{sk}_{\text{mldsa}}, d)\big)$$
   Verification accepts if and only if exact key/signature byte lengths match (`32 B`/`64 B` for `Ed25519`, `1,952 B`/`3,309 B` for `ML-DSA-65`) **and both signatures verify over $d$**.

3. **Key Custody at Rest (`packages/client/src/custody.ts`)**:
   - The 256-bit `masterSeed` is encrypted using `Argon2id` ($t = 3, m = 65536\text{ KiB}, p = 1$) + `XChaCha20-Poly1305` with Associated Authenticated Data $\mathsf{AAD} = \mathsf{pk}_{\text{owner}} \parallel \text{"|"} \parallel \mathsf{pk}_{\text{ed}}$.
   - Optional M-of-N recovery splits `masterSeed` over $\mathrm{GF}(256)$ Shamir secret sharing (`splitMasterSeedShamir` / `recoverWalletFromShamirShares`).

---

## 5. Dynamic Witness Registry, Sybil Defense & Quorum Consensus

### 5.1 Hash-Cash Sybil Admission

Every Witness/Relay/Shard node proves computational admission work before entering the peer directory (`/v1/peers`):

$$\mathrm{CLZ}\Big(\mathrm{SHA3\text{-}256}\big(\text{"NUV\_HASHCASH\_V1"} \parallel \text{"|"} \parallel \mathsf{peerId} \parallel \mathsf{pk}_{\text{ed}} \parallel \mathsf{pk}_{\text{mldsa}} \parallel \mathsf{pk}_{\text{x25519}} \parallel \mathsf{nonce}\big)\Big) \ge b_{\min}$$

The peer record is additionally self-signed using the node's hybrid `Ed25519 + ML-DSA-65` keys (`NUV_PEER_V1`). Peers failing either the leading-zero-bit difficulty $b_{\min}$ or dual signature verification are rejected (`403 INVALID_HASHCASH_OR_SIGNATURE`) and ignored by clients during discovery.

### 5.2 Deterministic VRF Quorum Selection

For any spend transaction, the deterministic quorum of $k = 7$ Witnesses out of the verified $N = 11$ peer set $\mathcal{P}$ is computed from the primary nullifier $N_0$:

$$\mathsf{score}(p) = \mathrm{SHA3\text{-}256}(N_0 \parallel \mathsf{peerId}_p), \quad p \in \mathcal{P}$$

$$\mathcal{Q}(N_0) = \text{first } k \text{ peers sorted lexicographically by } \mathsf{score}(p)$$

Because $\mathcal{Q}(N_0)$ depends solely on $N_0$ and the verified directory, two independent spenders attempting to double-spend $N_0$ deterministically converge on the same 7-of-11 Witness set.

### 5.3 Eliminating Split-Quorum Livelocks Under Concurrency

If 50 concurrent double-spend attempts contact all 7 Witnesses in parallel without ordering, distinct racers can win different subsets of the 7 Witnesses (e.g., Racer A claims Witnesses $\{1,2,3\}$, Racer B claims $\{4,5,6,7\}$), causing a classical **split-quorum livelock** where $0$ racers achieve a $7/7$ quorum.

Nuverther resolves this cleanly without sacrificing decentralization:
1. Every Witness node independently enforces `SERIALIZABLE` atomic nullifier uniqueness in PostgreSQL.
2. The client contacts the deterministic VRF leader $w_0 = \mathcal{Q}(N_0)[0]$ **first** via a 3-hop onion route.
3. Only the single racer whose transaction commits atomically on $w_0$ proceeds to fan out in parallel to $w_1, \dots, w_6$. All 49 losing racers immediately receive `409 ERR_DOUBLE_SPEND` from $w_0$ without polluting remaining Witnesses.
4. Each Witness $w_j$ persists:
   ```sql
   BEGIN ISOLATION LEVEL SERIALIZABLE;
   INSERT INTO spent_nullifiers (
     nullifier, tx_binding, proof_sha256, attestation_ed25519, attestation_mldsa65
   ) VALUES ($1, $3, $4, $5, $6), ($2, $3, $4, $5, $6)
   ON CONFLICT (nullifier) DO NOTHING
   RETURNING nullifier;
   ```
   and commits **only if `rowCount === 2`**, guaranteeing both input nullifiers are claimed all-or-nothing.

---

## 6. Network Privacy: Stateless 3-Hop 16 KB Onion Relay

### 6.1 Fixed-Size Sphinx-Style Framing

To prevent packet-size correlation and conceal originating client IPs from target Witnesses and Blind Shard servers, every wire frame sent to `POST /v1/relay` is strictly **$16,384$ bytes (`ONION_PACKET_SIZE`)**:

```
┌──────────────────┬──────────────────┬──────────────────┬─────────────────────────────────┐
│ Slot 0 (320 B)   │ Slot 1 (320 B)   │ Slot 2 (320 B)   │ Nested AEAD Body (15,424 B)     │
└──────────────────┴──────────────────┴──────────────────┴─────────────────────────────────┘
 ◄─────────────────── 960 B Header ─────────────────────► ◄───── 15,424 B Encrypted Body ───►
```

Each `320`-byte header slot contains:
- `1 B` version (`0x01`)
- `32 B` ephemeral `X25519` public key $\mathsf{ephemPk}$
- `24 B` `XChaCha20-Poly1305` header nonce
- `263 B` encrypted routing instruction (`247 B` plaintext + `16 B` Poly1305 MAC tag), holding `[flag:1B][bodyCipherLen:2B][bodyKey:32B][bodyNonce:24B][urlLen:1B][nextHopUrl][CSPRNG pad]`

Symmetric slot keys derive via:

$$k_{\text{hdr}} = \mathrm{HKDF\text{-}SHA3\text{-}256}\big(\text{ikm}=\mathrm{X25519}(\mathsf{sk}_{\text{hop}}, \mathsf{ephemPk}),\; \text{salt}=\mathsf{ephemPk} \parallel \mathsf{pk}_{\text{hop}},\; \text{info}=\text{"NUV\_ONION\_XCHACHA\_V1"}\big)$$

- **Intermediate Relays (Hops 1 & 2, `flag = 0x01`)**: Decrypt `Slot 0` and `bodyCipherLen` bytes of the body, left-shift `[Slot 1, Slot 2]` to `[0..640)`, fill `[640..960)` with `320` random CSPRNG bytes, pad the decrypted inner body back to `15,424` bytes with CSPRNG bytes, and POST the exact `16,384`-byte packet to `nextHopUrl`. Intermediate hops maintain **zero state**.
- **Terminal Relay (Hop 3, `flag = 0x02`)**: Extracts the inner payload (`<= 15,374 B`). Single-cell messages (`0x01`) execute directly; larger messages—such as UltraHonk proofs (~14.6 KB) + `ML-DSA-65` payloads (~20 KB total)—are transparently split by the sender into `0x02` frames (`[0x02][msgId:16B][chunkIdx:1B][totalChunks:1B][slice]`), each independently onion-encrypted to `16,384` bytes across 3 hops and reassembled strictly at Hop 3 before dispatching to the target `/v1/*` endpoint. Thus, the target Witness receives the request only from the Hop 3 exit relay, never the client's IP.

---

## 7. Blind Shard Storage (2-of-3 Shamir Threshold Encryption)

Recipient note recovery metadata (`ThreadPayload`: `threadId`, `recipientOwnerPk`, `amount`, `blinding`, optional `memo`) never touches Witness consensus tables. Instead:

1. The sender encrypts the serialized `ThreadPayload` under a fresh 256-bit `threadKey` using `XChaCha20-Poly1305`.
2. The sealed envelope (`nonce || ciphertext`) is split into **2-of-3 GF(256) Shamir shares**.
3. Each share $i \in \{1,2,3\}$ is encrypted under its own independent 256-bit `shareKey_i` with `XChaCha20-Poly1305`, tagged with `SHA3-256(["NUV_SHARD_V1", shardId, threadDigest, shareIndex, nonceHex, ciphertextB64])`, and stored on 3 distinct storage peers via 3-hop onion routes.
4. Any storage peer compromise yields only an opaque ciphertext share; recovering the Thread requires obtaining $\ge 2$ intact shares and possessing `threadKey` + the corresponding `shareKey`s. Any 1-byte mutation fails `TAMPERED_SHARD_MAC` on storage or AEAD verification on decryption.

---

## 8. Security Properties Verified Experimentally

Every security invariant above is continuously exercised without mocks against PostgreSQL 15 and an 11-node HTTP mesh (`tests/adversarial.test.ts` + `packages/zk/src/main.nr`):

| Adversarial Vector | Observed Enforcement |
| :--- | :--- |
| **50-way parallel double-spend of identical nullifier** | Exactly `1` succeeds (`7/7` Witness attestations verified); `49` rejected atomically with `409 ERR_DOUBLE_SPEND`; PostgreSQL holds 1 row per nullifier across all quorum nodes. |
| **`2^64 - 1` wrap-around / `>= 2^64` amount inflation** | Rejected by Noir `assert_max_bit_size::<64>()` (`nargo test` & witness generation throw). |
| **Tampered output commitment (`+999,999`)** | `verifySpendProof` returns `false`; Witness rejects HTTP attestation with `403`. |
| **Full PostgreSQL dump of all 11 nodes** | Zero plaintext amounts, zero secret memos, zero private keys, and zero client IP columns or loopback IP strings across `spent_nullifiers` and `blind_shards`. |
| **Non-`16,384` B packet sent to `/v1/relay`** | Rejected immediately with `400 INVALID_ONION_PACKET_SIZE`. |
| **1-byte bit flip in Blind Shard / `Ed25519` / `ML-DSA-65` / ZK proof** | Rejected immediately (`400 TAMPERED_SHARD_MAC`, `403 INVALID_HYBRID_PQ_SIGNATURE`, `403 INVALID_ZK_PROOF`) with zero nullifiers committed. |

---

## 9. Conclusion

Nuverther demonstrates that confidential, quantum-resistant value settlement does not require global blockchains, replicated transaction histories, or trusted sequencers. By combining pure hash-based Poseidon2 Noir proofs, hybrid classical + FIPS 204 post-quantum authentication, fixed-frame stateless 3-hop onion routing, 2-of-3 blind Shamir shards, and PostgreSQL `SERIALIZABLE` atomic nullifier consensus, Nuverther achieves deterministic finality, end-to-end metadata privacy, and clean single-developer maintainability.

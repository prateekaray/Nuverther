use std::hash::poseidon2_permutation;

// Depth of the append-only Poseidon2 note commitment Merkle tree (2^20 = 1,048,576 notes per epoch).
global TREE_DEPTH: u32 = 20;

// Domain separation constants (ASCII-encoded into BN254 Fr) to prevent cross-domain hash collisions.
global DOMAIN_OWNER: Field = 0x4e55565f4f574e4552;       // "NUV_OWNER"
global DOMAIN_COMMITMENT: Field = 0x4e55565f434f4d4d4954; // "NUV_COMMIT"
global DOMAIN_LEAF: Field = 0x4e55565f4c454146;           // "NUV_LEAF"
global DOMAIN_MERKLE: Field = 0x4e55565f4d45524b4c45;     // "NUV_MERKLE"
global DOMAIN_NULLIFIER: Field = 0x4e55565f4e554c4c;    // "NUV_NULL"
global DOMAIN_FEE: Field = 0x4e55565f464545;            // "NUV_FEE"

// Barretenberg-aligned Poseidon2 sponge parameters: iv = len * 2^64, rate = 3, width = 4.
global TWO_POW_64: Field = 18446744073709551616;

fn poseidon2_hash_3(a: Field, b: Field, c: Field) -> Field {
    let iv: Field = 3 * TWO_POW_64;
    let state: [Field; 4] = poseidon2_permutation([a, b, c, iv]);
    state[0]
}

fn poseidon2_hash_4(a: Field, b: Field, c: Field, d: Field) -> Field {
    let iv: Field = 4 * TWO_POW_64;
    let s1: [Field; 4] = poseidon2_permutation([a, b, c, iv]);
    let s2: [Field; 4] = poseidon2_permutation([s1[0] + d, s1[1], s1[2], s1[3]]);
    s2[0]
}

// Binds spender's hybrid signing public key hash directly into owner_pk inside the circuit.
pub fn compute_owner_pk(spend_secret: Field, auth_pk_hash: Field) -> Field {
    poseidon2_hash_3(DOMAIN_OWNER, spend_secret, auth_pk_hash)
}

pub fn compute_commitment(amount: Field, owner_pk: Field, blinding: Field) -> Field {
    poseidon2_hash_4(DOMAIN_COMMITMENT, amount, owner_pk, blinding)
}

// Binds a note commitment to its immutable canonical leaf index in the append-only registry.
pub fn compute_leaf(commitment: Field, leaf_index: Field) -> Field {
    poseidon2_hash_3(DOMAIN_LEAF, commitment, leaf_index)
}

pub fn compute_merkle_node(left: Field, right: Field) -> Field {
    poseidon2_hash_3(DOMAIN_MERKLE, left, right)
}

// Nullifier depends exclusively on spend_secret and the committed Merkle leaf (commitment + leaf_index).
// There is no spender-chosen nonce/thread_id, making double-spends of a registered note impossible.
pub fn compute_nullifier(spend_secret: Field, leaf: Field) -> Field {
    poseidon2_hash_3(DOMAIN_NULLIFIER, spend_secret, leaf)
}

pub fn compute_fee_commitment(fee: Field, fee_blinding: Field) -> Field {
    poseidon2_hash_3(DOMAIN_FEE, fee, fee_blinding)
}

pub fn verify_merkle_path(leaf: Field, leaf_index: Field, path: [Field; 20]) -> Field {
    leaf_index.assert_max_bit_size::<20>();
    let index_bits: [bool; 20] = leaf_index.to_le_bits();
    let mut current = leaf;
    for level in 0..TREE_DEPTH {
        let sibling = path[level];
        let is_right = index_bits[level];
        let (left, right) = if is_right {
            (sibling, current)
        } else {
            (current, sibling)
        };
        current = compute_merkle_node(left, right);
    }
    current
}

fn main(
    // Private witness values (never exposed in public inputs)
    spend_secret: Field,
    in_amounts: [Field; 2],
    in_blindings: [Field; 2],
    in_leaf_indices: [Field; 2],
    in_merkle_paths: [[Field; 20]; 2],
    out_amounts: [Field; 2],
    out_owner_pks: [Field; 2],
    out_blindings: [Field; 2],
    fee: Field,
    fee_blinding: Field,
    // Public inputs (8 Field elements; zero plaintext amounts, zero keys, zero leaf indices)
    merkle_root: pub Field,
    nullifiers: pub [Field; 2],
    output_commitments: pub [Field; 2],
    fee_commitment: pub Field,
    auth_pk_hash: pub Field,
    tx_binding: pub Field,
) {
    // Reject degenerate zero public bindings or roots.
    assert(merkle_root != 0);
    assert(auth_pk_hash != 0);
    assert(tx_binding != 0);

    // Derive owner_pk bound to BOTH spend_secret and the external hybrid signing key hash.
    let owner_pk = compute_owner_pk(spend_secret, auth_pk_hash);

    // Prevent spending the exact same note index twice inside one 2-in-2-out transaction.
    assert(in_leaf_indices[0] != in_leaf_indices[1]);

    // Validate both registered inputs: 64-bit unsigned range, Merkle membership, and leaf-bound nullifier.
    let mut sum_in: Field = 0;
    for i in 0..2 {
        in_amounts[i].assert_max_bit_size::<64>();
        let commitment = compute_commitment(in_amounts[i], owner_pk, in_blindings[i]);
        let leaf = compute_leaf(commitment, in_leaf_indices[i]);
        let computed_root = verify_merkle_path(leaf, in_leaf_indices[i], in_merkle_paths[i]);
        assert(computed_root == merkle_root);

        let expected_nullifier = compute_nullifier(spend_secret, leaf);
        assert(expected_nullifier == nullifiers[i]);

        sum_in += in_amounts[i];
    }
    assert(nullifiers[0] != nullifiers[1]);

    // Validate both outputs: strict 64-bit unsigned range, non-zero recipient owner_pk, commitment derivation.
    let mut sum_out: Field = 0;
    for i in 0..2 {
        out_amounts[i].assert_max_bit_size::<64>();
        assert(out_owner_pks[i] != 0);
        let expected_out_commit = compute_commitment(
            out_amounts[i],
            out_owner_pks[i],
            out_blindings[i],
        );
        assert(expected_out_commit == output_commitments[i]);

        sum_out += out_amounts[i];
    }

    // Validate fee: strict 64-bit unsigned range and commitment derivation.
    fee.assert_max_bit_size::<64>();
    let expected_fee_commit = compute_fee_commitment(fee, fee_blinding);
    assert(expected_fee_commit == fee_commitment);

    // Conservation of value: every term < 2^64 => max sum < 2^66 << BN254 Fr modulus,
    // so integer overflow and modular wrap-around are impossible.
    assert(sum_in == sum_out + fee);
}

// Helper for unit tests: builds a canonical 2-leaf depth-20 Poseidon2 Merkle tree root and paths.
fn build_two_leaf_tree(leaf0: Field, leaf1: Field) -> (Field, [Field; 20], [Field; 20]) {
    let mut zeros: [Field; 20] = [0; 20];
    let mut z: Field = 0;
    for lvl in 0..TREE_DEPTH {
        zeros[lvl] = z;
        z = compute_merkle_node(z, z);
    }

    let mut path0: [Field; 20] = [0; 20];
    let mut path1: [Field; 20] = [0; 20];
    path0[0] = leaf1;
    path1[0] = leaf0;
    for lvl in 1..TREE_DEPTH {
        path0[lvl] = zeros[lvl];
        path1[lvl] = zeros[lvl];
    }

    let mut curr = compute_merkle_node(leaf0, leaf1);
    for lvl in 1..TREE_DEPTH {
        curr = compute_merkle_node(curr, zeros[lvl]);
    }
    (curr, path0, path1)
}

#[test]
fn test_valid_merkle_shielded_spend() {
    let spend_secret = 0x123456789abcdef;
    let auth_pk_hash = 0x77777777;
    let owner_pk = compute_owner_pk(spend_secret, auth_pk_hash);
    let in_amounts = [1000, 500];
    let in_blindings = [111, 222];
    let leaf0 = compute_leaf(compute_commitment(in_amounts[0], owner_pk, in_blindings[0]), 0);
    let leaf1 = compute_leaf(compute_commitment(in_amounts[1], owner_pk, in_blindings[1]), 1);
    let (root, path0, path1) = build_two_leaf_tree(leaf0, leaf1);

    let out_amounts = [1200, 290];
    let out_owner_pks = [compute_owner_pk(0xdeadbeef, 0x8888), owner_pk];
    let out_blindings = [333, 444];
    let fee = 10;
    let fee_blinding = 555;

    let nullifiers = [
        compute_nullifier(spend_secret, leaf0),
        compute_nullifier(spend_secret, leaf1),
    ];
    let output_commitments = [
        compute_commitment(out_amounts[0], out_owner_pks[0], out_blindings[0]),
        compute_commitment(out_amounts[1], out_owner_pks[1], out_blindings[1]),
    ];
    let fee_commitment = compute_fee_commitment(fee, fee_blinding);

    main(
        spend_secret,
        in_amounts,
        in_blindings,
        [0, 1],
        [path0, path1],
        out_amounts,
        out_owner_pks,
        out_blindings,
        fee,
        fee_blinding,
        root,
        nullifiers,
        output_commitments,
        fee_commitment,
        auth_pk_hash,
        0x9999,
    );
}

#[test(should_fail)]
fn test_rejects_unregistered_input() {
    let spend_secret = 0x123456789abcdef;
    let auth_pk_hash = 0x77777777;
    let owner_pk = compute_owner_pk(spend_secret, auth_pk_hash);

    // Real tree only has (leaf0, leaf1)
    let leaf0 = compute_leaf(compute_commitment(1000, owner_pk, 111), 0);
    let leaf1 = compute_leaf(compute_commitment(500, owner_pk, 222), 1);
    let (root, path0, path1) = build_two_leaf_tree(leaf0, leaf1);

    // Attacker tries to invent an unregistered 9,999,999 input at index 0
    let fake_leaf0 = compute_leaf(compute_commitment(9999999, owner_pk, 111), 0);
    let nullifiers = [
        compute_nullifier(spend_secret, fake_leaf0),
        compute_nullifier(spend_secret, leaf1),
    ];
    let output_commitments = [
        compute_commitment(10000000, owner_pk, 333),
        compute_commitment(499, owner_pk, 444),
    ];

    main(
        spend_secret,
        [9999999, 500],
        [111, 222],
        [0, 1],
        [path0, path1],
        [10000000, 499],
        [owner_pk, owner_pk],
        [333, 444],
        0,
        555,
        root,
        nullifiers,
        output_commitments,
        compute_fee_commitment(0, 555),
        auth_pk_hash,
        0x9999,
    );
}

#[test(should_fail)]
fn test_rejects_nullifier_substitution_across_indices() {
    let spend_secret = 0x123456789abcdef;
    let auth_pk_hash = 0x77777777;
    let owner_pk = compute_owner_pk(spend_secret, auth_pk_hash);

    let c0 = compute_commitment(1000, owner_pk, 111);
    let leaf0 = compute_leaf(c0, 0);
    let leaf1 = compute_leaf(compute_commitment(500, owner_pk, 222), 1);
    let (root, path0, path1) = build_two_leaf_tree(leaf0, leaf1);

    // Attacker tries to derive a different nullifier by swapping leaf_index to 99 while passing real path0
    let spoofed_leaf = compute_leaf(c0, 99);
    let nullifiers = [
        compute_nullifier(spend_secret, spoofed_leaf),
        compute_nullifier(spend_secret, leaf1),
    ];
    let output_commitments = [
        compute_commitment(1200, owner_pk, 333),
        compute_commitment(290, owner_pk, 444),
    ];

    main(
        spend_secret,
        [1000, 500],
        [111, 222],
        [99, 1],
        [path0, path1],
        [1200, 290],
        [owner_pk, owner_pk],
        [333, 444],
        10,
        555,
        root,
        nullifiers,
        output_commitments,
        compute_fee_commitment(10, 555),
        auth_pk_hash,
        0x9999,
    );
}

#[test(should_fail)]
fn test_rejects_mismatched_auth_pk_hash() {
    let spend_secret = 0x123456789abcdef;
    let real_auth_hash = 0x77777777;
    let owner_pk = compute_owner_pk(spend_secret, real_auth_hash);

    let leaf0 = compute_leaf(compute_commitment(1000, owner_pk, 111), 0);
    let leaf1 = compute_leaf(compute_commitment(500, owner_pk, 222), 1);
    let (root, path0, path1) = build_two_leaf_tree(leaf0, leaf1);

    let nullifiers = [
        compute_nullifier(spend_secret, leaf0),
        compute_nullifier(spend_secret, leaf1),
    ];
    let output_commitments = [
        compute_commitment(1200, owner_pk, 333),
        compute_commitment(290, owner_pk, 444),
    ];

    // Supplying a different auth_pk_hash breaks owner_pk derivation and Merkle membership
    main(
        spend_secret,
        [1000, 500],
        [111, 222],
        [0, 1],
        [path0, path1],
        [1200, 290],
        [owner_pk, owner_pk],
        [333, 444],
        10,
        555,
        root,
        nullifiers,
        output_commitments,
        compute_fee_commitment(10, 555),
        0xdeaddead,
        0x9999,
    );
}

#[test(should_fail)]
fn test_rejects_64bit_overflow_inflation() {
    let spend_secret = 0x123456789abcdef;
    let auth_pk_hash = 0x77777777;
    let owner_pk = compute_owner_pk(spend_secret, auth_pk_hash);
    let max_u64 = 18446744073709551615;

    let leaf0 = compute_leaf(compute_commitment(100, owner_pk, 111), 0);
    let leaf1 = compute_leaf(compute_commitment(0, owner_pk, 222), 1);
    let (root, path0, path1) = build_two_leaf_tree(leaf0, leaf1);

    let nullifiers = [
        compute_nullifier(spend_secret, leaf0),
        compute_nullifier(spend_secret, leaf1),
    ];
    let output_commitments = [
        compute_commitment(max_u64, owner_pk, 333),
        compute_commitment(101, owner_pk, 444),
    ];

    main(
        spend_secret,
        [100, 0],
        [111, 222],
        [0, 1],
        [path0, path1],
        [max_u64, 101],
        [owner_pk, owner_pk],
        [333, 444],
        0,
        555,
        root,
        nullifiers,
        output_commitments,
        compute_fee_commitment(0, 555),
        auth_pk_hash,
        0x9999,
    );
}

#[test(should_fail)]
fn test_rejects_above_u64_range() {
    let spend_secret = 0x123456789abcdef;
    let auth_pk_hash = 0x77777777;
    let owner_pk = compute_owner_pk(spend_secret, auth_pk_hash);
    let above_u64 = 18446744073709551616;

    let leaf0 = compute_leaf(compute_commitment(above_u64, owner_pk, 111), 0);
    let leaf1 = compute_leaf(compute_commitment(0, owner_pk, 222), 1);
    let (root, path0, path1) = build_two_leaf_tree(leaf0, leaf1);

    let nullifiers = [
        compute_nullifier(spend_secret, leaf0),
        compute_nullifier(spend_secret, leaf1),
    ];
    let output_commitments = [
        compute_commitment(above_u64, owner_pk, 333),
        compute_commitment(0, owner_pk, 444),
    ];

    main(
        spend_secret,
        [above_u64, 0],
        [111, 222],
        [0, 1],
        [path0, path1],
        [above_u64, 0],
        [owner_pk, owner_pk],
        [333, 444],
        0,
        555,
        root,
        nullifiers,
        output_commitments,
        compute_fee_commitment(0, 555),
        auth_pk_hash,
        0x9999,
    );
}

#[test(should_fail)]
fn test_rejects_same_leaf_double_input() {
    let spend_secret = 0x123456789abcdef;
    let auth_pk_hash = 0x77777777;
    let owner_pk = compute_owner_pk(spend_secret, auth_pk_hash);

    let leaf0 = compute_leaf(compute_commitment(1000, owner_pk, 111), 0);
    let leaf1 = compute_leaf(compute_commitment(500, owner_pk, 222), 1);
    let (root, path0, _path1) = build_two_leaf_tree(leaf0, leaf1);

    let nullifier0 = compute_nullifier(spend_secret, leaf0);
    let output_commitments = [
        compute_commitment(1900, owner_pk, 333),
        compute_commitment(90, owner_pk, 444),
    ];

    main(
        spend_secret,
        [1000, 1000],
        [111, 111],
        [0, 0],
        [path0, path0],
        [1900, 90],
        [owner_pk, owner_pk],
        [333, 444],
        10,
        555,
        root,
        [nullifier0, nullifier0],
        output_commitments,
        compute_fee_commitment(10, 555),
        auth_pk_hash,
        0x9999,
    );
}

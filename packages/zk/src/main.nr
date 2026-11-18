use std::hash::poseidon2_permutation;

// Domain separation constants for Nuverther Poseidon2 commitments and nullifiers.
// Each constant is ASCII-encoded into a BN254 Field element to eliminate cross-domain collisions.
global DOMAIN_OWNER: Field = 0x4e55565f4f574e4552;       // "NUV_OWNER"
global DOMAIN_COMMITMENT: Field = 0x4e55565f434f4d4d4954; // "NUV_COMMIT"
global DOMAIN_NULLIFIER: Field = 0x4e55565f4e554c4c;    // "NUV_NULL"
global DOMAIN_FEE: Field = 0x4e55565f464545;            // "NUV_FEE"

// Two-to-one / N-ary Poseidon2 sponge matching Barretenberg's poseidon2Hash construction:
// Initial capacity element is len * 2^64, rate = 3, full state width = 4.
global TWO_POW_64: Field = 18446744073709551616;

fn poseidon2_hash_2(a: Field, b: Field) -> Field {
    let iv: Field = 2 * TWO_POW_64;
    let state: [Field; 4] = poseidon2_permutation([a, b, 0, iv]);
    state[0]
}

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

pub fn compute_owner_pk(spend_secret: Field) -> Field {
    poseidon2_hash_2(DOMAIN_OWNER, spend_secret)
}

pub fn compute_commitment(amount: Field, owner_pk: Field, blinding: Field) -> Field {
    poseidon2_hash_4(DOMAIN_COMMITMENT, amount, owner_pk, blinding)
}

pub fn compute_nullifier(spend_secret: Field, thread_id: Field) -> Field {
    poseidon2_hash_3(DOMAIN_NULLIFIER, spend_secret, thread_id)
}

pub fn compute_fee_commitment(fee: Field, fee_blinding: Field) -> Field {
    poseidon2_hash_3(DOMAIN_FEE, fee, fee_blinding)
}

fn main(
    // Private witness values (never exposed in public inputs)
    spend_secret: Field,
    in_amounts: [Field; 2],
    in_blindings: [Field; 2],
    in_thread_ids: [Field; 2],
    out_amounts: [Field; 2],
    out_owner_pks: [Field; 2],
    out_blindings: [Field; 2],
    fee: Field,
    fee_blinding: Field,
    // Public inputs (zero plaintext amounts, zero keys)
    input_commitments: pub [Field; 2],
    nullifiers: pub [Field; 2],
    output_commitments: pub [Field; 2],
    fee_commitment: pub Field,
    tx_binding: pub Field,
) {
    // Bind tx_binding into the constraint system so proofs cannot be replayed across contexts.
    assert(tx_binding != 0);

    // Derive the spender's Poseidon2 owner public key from spend_secret.
    let owner_pk = compute_owner_pk(spend_secret);

    // Prevent spending the same thread twice inside a single 2-in-2-out transaction.
    assert(in_thread_ids[0] != in_thread_ids[1]);

    // Validate all inputs: strict 64-bit unsigned range check + commitment + nullifier derivation.
    let mut sum_in: Field = 0;
    for i in 0..2 {
        in_amounts[i].assert_max_bit_size::<64>();
        let expected_in_commit = compute_commitment(in_amounts[i], owner_pk, in_blindings[i]);
        assert(expected_in_commit == input_commitments[i]);

        let expected_nullifier = compute_nullifier(spend_secret, in_thread_ids[i]);
        assert(expected_nullifier == nullifiers[i]);

        sum_in += in_amounts[i];
    }

    // Validate all outputs: strict 64-bit unsigned range check + commitment derivation.
    let mut sum_out: Field = 0;
    for i in 0..2 {
        out_amounts[i].assert_max_bit_size::<64>();
        let expected_out_commit = compute_commitment(
            out_amounts[i],
            out_owner_pks[i],
            out_blindings[i],
        );
        assert(expected_out_commit == output_commitments[i]);

        sum_out += out_amounts[i];
    }

    // Validate fee: strict 64-bit unsigned range check + commitment derivation.
    fee.assert_max_bit_size::<64>();
    let expected_fee_commit = compute_fee_commitment(fee, fee_blinding);
    assert(expected_fee_commit == fee_commitment);

    // Conservation of value: since every term is < 2^64, the maximum sum is < 2^66 << BN254 modulus,
    // so integer overflow and modular wrap-around are impossible.
    assert(sum_in == sum_out + fee);
}

#[test]
fn test_valid_shielded_spend() {
    let spend_secret = 0x123456789abcdef;
    let owner_pk = compute_owner_pk(spend_secret);
    let in_amounts = [1000, 500];
    let in_blindings = [111, 222];
    let in_thread_ids = [1001, 1002];
    let out_amounts = [1200, 290];
    let out_owner_pks = [compute_owner_pk(0xdeadbeef), owner_pk];
    let out_blindings = [333, 444];
    let fee = 10;
    let fee_blinding = 555;

    let input_commitments = [
        compute_commitment(in_amounts[0], owner_pk, in_blindings[0]),
        compute_commitment(in_amounts[1], owner_pk, in_blindings[1]),
    ];
    let nullifiers = [
        compute_nullifier(spend_secret, in_thread_ids[0]),
        compute_nullifier(spend_secret, in_thread_ids[1]),
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
        in_thread_ids,
        out_amounts,
        out_owner_pks,
        out_blindings,
        fee,
        fee_blinding,
        input_commitments,
        nullifiers,
        output_commitments,
        fee_commitment,
        0x9999,
    );
}

#[test(should_fail)]
fn test_rejects_64bit_overflow_inflation() {
    let spend_secret = 0x123456789abcdef;
    let owner_pk = compute_owner_pk(spend_secret);
    let max_u64 = 18446744073709551615;
    let in_amounts = [100, 0];
    let in_blindings = [111, 222];
    let in_thread_ids = [1001, 1002];
    // Attempt 2^64 - 1 inflation
    let out_amounts = [max_u64, 101];
    let out_owner_pks = [owner_pk, owner_pk];
    let out_blindings = [333, 444];
    let fee = 0;
    let fee_blinding = 555;

    let input_commitments = [
        compute_commitment(in_amounts[0], owner_pk, in_blindings[0]),
        compute_commitment(in_amounts[1], owner_pk, in_blindings[1]),
    ];
    let nullifiers = [
        compute_nullifier(spend_secret, in_thread_ids[0]),
        compute_nullifier(spend_secret, in_thread_ids[1]),
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
        in_thread_ids,
        out_amounts,
        out_owner_pks,
        out_blindings,
        fee,
        fee_blinding,
        input_commitments,
        nullifiers,
        output_commitments,
        fee_commitment,
        0x9999,
    );
}

#[test(should_fail)]
fn test_rejects_above_u64_range() {
    let spend_secret = 0x123456789abcdef;
    let owner_pk = compute_owner_pk(spend_secret);
    // 2^64 exceeds 64-bit unsigned limit
    let above_u64 = 18446744073709551616;
    let in_amounts = [above_u64, 0];
    let in_blindings = [111, 222];
    let in_thread_ids = [1001, 1002];
    let out_amounts = [above_u64, 0];
    let out_owner_pks = [owner_pk, owner_pk];
    let out_blindings = [333, 444];
    let fee = 0;
    let fee_blinding = 555;

    let input_commitments = [
        compute_commitment(in_amounts[0], owner_pk, in_blindings[0]),
        compute_commitment(in_amounts[1], owner_pk, in_blindings[1]),
    ];
    let nullifiers = [
        compute_nullifier(spend_secret, in_thread_ids[0]),
        compute_nullifier(spend_secret, in_thread_ids[1]),
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
        in_thread_ids,
        out_amounts,
        out_owner_pks,
        out_blindings,
        fee,
        fee_blinding,
        input_commitments,
        nullifiers,
        output_commitments,
        fee_commitment,
        0x9999,
    );
}

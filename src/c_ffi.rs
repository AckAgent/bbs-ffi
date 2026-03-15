//! C-compatible FFI layer for BBS+ operations.
//!
//! Wraps BBS+ functions with `extern "C"` ABI for consumption by Go via CGo.
//! Supports:
//!   - Key generation, signing, verification
//!   - Selective disclosure proof generation/verification
//!   - Blind signing with pseudonyms (enrollment)
//!   - Proof generation/verification with pseudonyms (per-request)
//!
//! # Memory management
//!
//! All output buffers are allocated by Rust and must be freed by the caller
//! using [`bbs_ffi_free_buffer`]. Callers must not free the buffer data
//! pointer directly — use the provided free function.

use std::alloc::{alloc, dealloc, Layout};
use std::ptr;
use std::slice;

use crate::{
    bbs_blind_sign_with_nym, bbs_commit_with_nym, bbs_generate_keypair, bbs_generate_nym_secret,
    bbs_proof_gen, bbs_proof_gen_with_nym, bbs_proof_verify, bbs_proof_verify_with_nym, bbs_sign,
    bbs_verify, bbs_verify_blind_sign_with_nym,
};

// ─── C Types ─────────────────────────────────────────────────────────────────

/// Result codes for C FFI operations.
#[repr(C)]
#[derive(Debug, PartialEq)]
pub enum BbsFfiResult {
    /// Operation succeeded.
    Ok = 0,
    /// Key generation failed.
    KeygenFailed = 1,
    /// Signing failed.
    SignFailed = 2,
    /// Verification failed.
    VerifyFailed = 3,
    /// Invalid input parameters (null pointer, wrong length, etc.).
    InvalidInput = 4,
    /// Proof generation failed.
    ProofGenFailed = 5,
    /// Proof verification failed.
    ProofVerifyFailed = 6,
    /// Commitment failed.
    CommitmentFailed = 7,
}

/// A heap-allocated byte buffer returned from Rust to C.
///
/// The caller must free this buffer using [`bbs_ffi_free_buffer`].
/// Do not modify `data`, `len`, or `cap` directly.
#[repr(C)]
pub struct BbsBuffer {
    /// Pointer to the buffer data. Null if the buffer is empty or invalid.
    pub data: *mut u8,
    /// Length of the buffer in bytes.
    pub len: usize,
    /// Capacity of the original Vec allocation. Required for correct deallocation.
    pub cap: usize,
}

impl BbsBuffer {
    /// Creates an empty (null) buffer.
    fn null() -> Self {
        BbsBuffer {
            data: ptr::null_mut(),
            len: 0,
            cap: 0,
        }
    }

    /// Creates a buffer from a Vec<u8>, taking ownership of the allocation.
    ///
    /// The Vec is leaked intentionally — the caller must use [`bbs_ffi_free_buffer`]
    /// to reclaim the memory. The capacity is preserved so that
    /// [`bbs_ffi_free_buffer`] can reconstruct the Vec correctly.
    fn from_vec(mut v: Vec<u8>) -> Self {
        let buf = BbsBuffer {
            data: v.as_mut_ptr(),
            len: v.len(),
            cap: v.capacity(),
        };
        std::mem::forget(v);
        buf
    }
}

/// A read-only byte slice passed from C to Rust for message arrays.
#[repr(C)]
pub struct BbsMessage {
    /// Pointer to the message data.
    pub data: *const u8,
    /// Length of the message in bytes.
    pub len: usize,
}

// ─── Existing FFI Functions ─────────────────────────────────────────────────

/// Generate a new BBS+ keypair (BLS12-381-SHA-256).
///
/// On success, writes the secret key to `sk_out` (32 bytes) and the public
/// key to `pk_out` (96 bytes). Both buffers must be freed with
/// [`bbs_ffi_free_buffer`].
///
/// # Safety
///
/// `sk_out` and `pk_out` must be valid, non-null pointers to `BbsBuffer`.
#[no_mangle]
pub unsafe extern "C" fn bbs_ffi_generate_keypair(
    sk_out: *mut BbsBuffer,
    pk_out: *mut BbsBuffer,
) -> BbsFfiResult {
    if sk_out.is_null() || pk_out.is_null() {
        return BbsFfiResult::InvalidInput;
    }

    match bbs_generate_keypair() {
        Ok(kp) => {
            *sk_out = BbsBuffer::from_vec(kp.secret_key);
            *pk_out = BbsBuffer::from_vec(kp.public_key);
            BbsFfiResult::Ok
        }
        Err(_) => {
            *sk_out = BbsBuffer::null();
            *pk_out = BbsBuffer::null();
            BbsFfiResult::KeygenFailed
        }
    }
}

/// Sign messages with a BBS+ secret key (BLS12-381-SHA-256).
///
/// Returns the 80-byte BBS+ signature in `sig_out`.
///
/// # Safety
///
/// All pointer arguments must be valid for the specified lengths.
#[no_mangle]
pub unsafe extern "C" fn bbs_ffi_sign(
    sk: *const u8,
    sk_len: usize,
    pk: *const u8,
    pk_len: usize,
    header: *const u8,
    header_len: usize,
    msgs: *const BbsMessage,
    msgs_count: usize,
    sig_out: *mut BbsBuffer,
) -> BbsFfiResult {
    if sig_out.is_null() {
        return BbsFfiResult::InvalidInput;
    }
    if sk.is_null() || sk_len == 0 || pk.is_null() || pk_len == 0 {
        *sig_out = BbsBuffer::null();
        return BbsFfiResult::InvalidInput;
    }

    let sk_bytes = slice::from_raw_parts(sk, sk_len).to_vec();
    let pk_bytes = slice::from_raw_parts(pk, pk_len).to_vec();
    let header_bytes = read_optional_bytes(header, header_len);
    let messages = collect_messages(msgs, msgs_count);

    match bbs_sign(sk_bytes, pk_bytes, header_bytes, messages) {
        Ok(sig) => {
            *sig_out = BbsBuffer::from_vec(sig);
            BbsFfiResult::Ok
        }
        Err(_) => {
            *sig_out = BbsBuffer::null();
            BbsFfiResult::SignFailed
        }
    }
}

/// Verify a BBS+ signature (BLS12-381-SHA-256).
///
/// On success, writes `1` (valid) or `0` (invalid) to `valid_out`.
///
/// # Safety
///
/// All pointer arguments must be valid for the specified lengths.
#[no_mangle]
pub unsafe extern "C" fn bbs_ffi_verify(
    pk: *const u8,
    pk_len: usize,
    header: *const u8,
    header_len: usize,
    sig: *const u8,
    sig_len: usize,
    msgs: *const BbsMessage,
    msgs_count: usize,
    valid_out: *mut i32,
) -> BbsFfiResult {
    if valid_out.is_null() {
        return BbsFfiResult::InvalidInput;
    }
    if pk.is_null() || pk_len == 0 || sig.is_null() || sig_len == 0 {
        *valid_out = 0;
        return BbsFfiResult::InvalidInput;
    }

    let pk_bytes = slice::from_raw_parts(pk, pk_len).to_vec();
    let header_bytes = read_optional_bytes(header, header_len);
    let sig_bytes = slice::from_raw_parts(sig, sig_len).to_vec();
    let messages = collect_messages(msgs, msgs_count);

    match bbs_verify(pk_bytes, header_bytes, sig_bytes, messages) {
        Ok(valid) => {
            *valid_out = if valid { 1 } else { 0 };
            BbsFfiResult::Ok
        }
        Err(_) => {
            *valid_out = 0;
            BbsFfiResult::VerifyFailed
        }
    }
}

// ─── Proof Generation / Verification ──────────────────────────────────────

/// Generate a BBS+ selective disclosure proof.
///
/// # Arguments
/// * `pk` / `pk_len` — Issuer public key (96 bytes).
/// * `sig` / `sig_len` — BBS+ signature (80 bytes).
/// * `header` / `header_len` — Application-specific header.
/// * `ph` / `ph_len` — Presentation header (nonce from verifier).
/// * `msgs` / `msgs_count` — All signed messages.
/// * `disclosed_indices` / `disclosed_count` — Indices of messages to disclose.
/// * `proof_out` — Output buffer for serialized proof.
///
/// # Safety
///
/// All pointer arguments must be valid for the specified lengths.
#[no_mangle]
pub unsafe extern "C" fn bbs_ffi_proof_gen(
    pk: *const u8,
    pk_len: usize,
    sig: *const u8,
    sig_len: usize,
    header: *const u8,
    header_len: usize,
    ph: *const u8,
    ph_len: usize,
    msgs: *const BbsMessage,
    msgs_count: usize,
    disclosed_indices: *const u32,
    disclosed_count: usize,
    proof_out: *mut BbsBuffer,
) -> BbsFfiResult {
    if proof_out.is_null() {
        return BbsFfiResult::InvalidInput;
    }
    if pk.is_null() || pk_len == 0 || sig.is_null() || sig_len == 0 {
        *proof_out = BbsBuffer::null();
        return BbsFfiResult::InvalidInput;
    }

    let pk_bytes = slice::from_raw_parts(pk, pk_len).to_vec();
    let sig_bytes = slice::from_raw_parts(sig, sig_len).to_vec();
    let header_bytes = read_optional_bytes(header, header_len);
    let ph_bytes = read_optional_bytes(ph, ph_len);
    let messages = collect_messages(msgs, msgs_count);
    let indices = collect_u32_array(disclosed_indices, disclosed_count);

    match bbs_proof_gen(
        pk_bytes,
        sig_bytes,
        header_bytes,
        ph_bytes,
        messages,
        indices,
    ) {
        Ok(proof) => {
            *proof_out = BbsBuffer::from_vec(proof);
            BbsFfiResult::Ok
        }
        Err(_) => {
            *proof_out = BbsBuffer::null();
            BbsFfiResult::ProofGenFailed
        }
    }
}

/// Verify a BBS+ selective disclosure proof.
///
/// On success, writes `1` (valid) or `0` (invalid) to `valid_out`.
///
/// # Safety
///
/// All pointer arguments must be valid for the specified lengths.
#[no_mangle]
pub unsafe extern "C" fn bbs_ffi_proof_verify(
    pk: *const u8,
    pk_len: usize,
    proof: *const u8,
    proof_len: usize,
    header: *const u8,
    header_len: usize,
    ph: *const u8,
    ph_len: usize,
    disclosed_msgs: *const BbsMessage,
    disclosed_msgs_count: usize,
    disclosed_indices: *const u32,
    disclosed_count: usize,
    valid_out: *mut i32,
) -> BbsFfiResult {
    if valid_out.is_null() {
        return BbsFfiResult::InvalidInput;
    }
    if pk.is_null() || pk_len == 0 || proof.is_null() || proof_len == 0 {
        *valid_out = 0;
        return BbsFfiResult::InvalidInput;
    }

    let pk_bytes = slice::from_raw_parts(pk, pk_len).to_vec();
    let proof_bytes = slice::from_raw_parts(proof, proof_len).to_vec();
    let header_bytes = read_optional_bytes(header, header_len);
    let ph_bytes = read_optional_bytes(ph, ph_len);
    let disc_messages = collect_messages(disclosed_msgs, disclosed_msgs_count);
    let indices = collect_u32_array(disclosed_indices, disclosed_count);

    match bbs_proof_verify(
        pk_bytes,
        proof_bytes,
        header_bytes,
        ph_bytes,
        disc_messages,
        indices,
    ) {
        Ok(valid) => {
            *valid_out = if valid { 1 } else { 0 };
            BbsFfiResult::Ok
        }
        Err(_) => {
            *valid_out = 0;
            BbsFfiResult::ProofVerifyFailed
        }
    }
}

// ─── Blind Signing with Pseudonyms ──────────────────────────────────────

/// Generate a random pseudonym secret (32-byte BLS12-381 scalar).
///
/// # Safety
///
/// `secret_out` must be a valid, non-null pointer to `BbsBuffer`.
#[no_mangle]
pub unsafe extern "C" fn bbs_ffi_generate_nym_secret(secret_out: *mut BbsBuffer) -> BbsFfiResult {
    if secret_out.is_null() {
        return BbsFfiResult::InvalidInput;
    }

    match bbs_generate_nym_secret() {
        Ok(secret) => {
            *secret_out = BbsBuffer::from_vec(secret);
            BbsFfiResult::Ok
        }
        Err(_) => {
            *secret_out = BbsBuffer::null();
            BbsFfiResult::KeygenFailed
        }
    }
}

/// Create a blind commitment with pseudonym for enrollment.
///
/// # Arguments
/// * `committed_msgs` / `committed_msgs_count` — Holder's committed messages (can be null/0).
/// * `prover_nym` / `prover_nym_len` — 32-byte prover pseudonym secret.
/// * `commitment_out` — Output: serialized commitment with proof.
/// * `blind_factor_out` — Output: blind factor (keep secret).
///
/// # Safety
///
/// All pointer arguments must be valid for the specified lengths.
#[no_mangle]
pub unsafe extern "C" fn bbs_ffi_commit_with_nym(
    committed_msgs: *const BbsMessage,
    committed_msgs_count: usize,
    prover_nym: *const u8,
    prover_nym_len: usize,
    commitment_out: *mut BbsBuffer,
    blind_factor_out: *mut BbsBuffer,
) -> BbsFfiResult {
    if commitment_out.is_null() || blind_factor_out.is_null() {
        return BbsFfiResult::InvalidInput;
    }
    if prover_nym.is_null() || prover_nym_len == 0 {
        *commitment_out = BbsBuffer::null();
        *blind_factor_out = BbsBuffer::null();
        return BbsFfiResult::InvalidInput;
    }

    let committed_messages = collect_messages(committed_msgs, committed_msgs_count);
    let nym_bytes = slice::from_raw_parts(prover_nym, prover_nym_len).to_vec();

    match bbs_commit_with_nym(committed_messages, nym_bytes) {
        Ok(result) => {
            *commitment_out = BbsBuffer::from_vec(result.commitment_with_proof);
            *blind_factor_out = BbsBuffer::from_vec(result.blind_factor);
            BbsFfiResult::Ok
        }
        Err(_) => {
            *commitment_out = BbsBuffer::null();
            *blind_factor_out = BbsBuffer::null();
            BbsFfiResult::CommitmentFailed
        }
    }
}

/// Issuer blind-signs a credential with pseudonym.
///
/// # Arguments
/// * `sk` / `sk_len` — 32-byte issuer secret key.
/// * `pk` / `pk_len` — 96-byte issuer public key.
/// * `commitment` / `commitment_len` — Holder's commitment with proof.
/// * `header` / `header_len` — Application-specific header.
/// * `signer_nym` / `signer_nym_len` — 32-byte issuer nym entropy.
/// * `msgs` / `msgs_count` — Issuer-known messages.
/// * `sig_out` — Output: 80-byte blind signature.
///
/// # Safety
///
/// All pointer arguments must be valid for the specified lengths.
#[no_mangle]
pub unsafe extern "C" fn bbs_ffi_blind_sign_with_nym(
    sk: *const u8,
    sk_len: usize,
    pk: *const u8,
    pk_len: usize,
    commitment: *const u8,
    commitment_len: usize,
    header: *const u8,
    header_len: usize,
    signer_nym: *const u8,
    signer_nym_len: usize,
    msgs: *const BbsMessage,
    msgs_count: usize,
    sig_out: *mut BbsBuffer,
) -> BbsFfiResult {
    if sig_out.is_null() {
        return BbsFfiResult::InvalidInput;
    }
    if sk.is_null() || sk_len == 0 || pk.is_null() || pk_len == 0 {
        *sig_out = BbsBuffer::null();
        return BbsFfiResult::InvalidInput;
    }
    if signer_nym.is_null() || signer_nym_len == 0 {
        *sig_out = BbsBuffer::null();
        return BbsFfiResult::InvalidInput;
    }

    let sk_bytes = slice::from_raw_parts(sk, sk_len).to_vec();
    let pk_bytes = slice::from_raw_parts(pk, pk_len).to_vec();
    let commitment_bytes = read_optional_bytes(commitment, commitment_len);
    let header_bytes = read_optional_bytes(header, header_len);
    let signer_nym_bytes = slice::from_raw_parts(signer_nym, signer_nym_len).to_vec();
    let messages = collect_messages(msgs, msgs_count);

    match bbs_blind_sign_with_nym(
        sk_bytes,
        pk_bytes,
        commitment_bytes,
        header_bytes,
        signer_nym_bytes,
        messages,
    ) {
        Ok(sig) => {
            *sig_out = BbsBuffer::from_vec(sig);
            BbsFfiResult::Ok
        }
        Err(_) => {
            *sig_out = BbsBuffer::null();
            BbsFfiResult::SignFailed
        }
    }
}

/// Holder verifies blind signature and extracts combined pseudonym secret.
///
/// # Arguments
/// * `pk` / `pk_len` — 96-byte issuer public key.
/// * `blind_sig` / `blind_sig_len` — 80-byte blind signature.
/// * `header` / `header_len` — Application-specific header.
/// * `msgs` / `msgs_count` — Issuer-known messages.
/// * `committed_msgs` / `committed_msgs_count` — Holder's committed messages.
/// * `prover_nym` / `prover_nym_len` — 32-byte prover nym secret.
/// * `signer_nym` / `signer_nym_len` — 32-byte issuer nym entropy.
/// * `blind_factor` / `blind_factor_len` — Blind factor from commitment.
/// * `nym_secret_out` — Output: 32-byte combined nym secret.
///
/// # Safety
///
/// All pointer arguments must be valid for the specified lengths.
#[no_mangle]
pub unsafe extern "C" fn bbs_ffi_verify_blind_sign_with_nym(
    pk: *const u8,
    pk_len: usize,
    blind_sig: *const u8,
    blind_sig_len: usize,
    header: *const u8,
    header_len: usize,
    msgs: *const BbsMessage,
    msgs_count: usize,
    committed_msgs: *const BbsMessage,
    committed_msgs_count: usize,
    prover_nym: *const u8,
    prover_nym_len: usize,
    signer_nym: *const u8,
    signer_nym_len: usize,
    blind_factor: *const u8,
    blind_factor_len: usize,
    nym_secret_out: *mut BbsBuffer,
) -> BbsFfiResult {
    if nym_secret_out.is_null() {
        return BbsFfiResult::InvalidInput;
    }
    if pk.is_null()
        || pk_len == 0
        || blind_sig.is_null()
        || blind_sig_len == 0
        || prover_nym.is_null()
        || prover_nym_len == 0
        || signer_nym.is_null()
        || signer_nym_len == 0
        || blind_factor.is_null()
        || blind_factor_len == 0
    {
        *nym_secret_out = BbsBuffer::null();
        return BbsFfiResult::InvalidInput;
    }

    let pk_bytes = slice::from_raw_parts(pk, pk_len).to_vec();
    let sig_bytes = slice::from_raw_parts(blind_sig, blind_sig_len).to_vec();
    let header_bytes = read_optional_bytes(header, header_len);
    let messages = collect_messages(msgs, msgs_count);
    let committed_messages = collect_messages(committed_msgs, committed_msgs_count);
    let prover_nym_bytes = slice::from_raw_parts(prover_nym, prover_nym_len).to_vec();
    let signer_nym_bytes = slice::from_raw_parts(signer_nym, signer_nym_len).to_vec();
    let blind_factor_bytes = slice::from_raw_parts(blind_factor, blind_factor_len).to_vec();

    match bbs_verify_blind_sign_with_nym(
        pk_bytes,
        sig_bytes,
        header_bytes,
        messages,
        committed_messages,
        prover_nym_bytes,
        signer_nym_bytes,
        blind_factor_bytes,
    ) {
        Ok(result) => {
            *nym_secret_out = BbsBuffer::from_vec(result.nym_secret);
            BbsFfiResult::Ok
        }
        Err(_) => {
            *nym_secret_out = BbsBuffer::null();
            BbsFfiResult::VerifyFailed
        }
    }
}

/// Generate a BBS+ proof with pseudonym.
///
/// # Arguments
/// * `pk` / `pk_len` — 96-byte issuer public key.
/// * `sig` / `sig_len` — 80-byte blind signature.
/// * `header` / `header_len` — Application-specific header.
/// * `ph` / `ph_len` — Presentation header.
/// * `nym_secret` / `nym_secret_len` — 32-byte combined nym secret.
/// * `scope` / `scope_len` — Scope for pseudonym derivation.
/// * `msgs` / `msgs_count` — Issuer-known messages.
/// * `committed_msgs` / `committed_msgs_count` — Holder's committed messages.
/// * `disclosed_indices` / `disclosed_count` — Indices of issuer messages to disclose.
/// * `disclosed_commitment_indices` / `disclosed_commitment_count` — Indices of committed messages to disclose.
/// * `blind_factor` / `blind_factor_len` — Blind factor from commitment.
/// * `proof_out` — Output: serialized proof.
/// * `pseudonym_out` — Output: 48-byte pseudonym (compressed G1).
///
/// # Safety
///
/// All pointer arguments must be valid for the specified lengths.
#[no_mangle]
pub unsafe extern "C" fn bbs_ffi_proof_gen_with_nym(
    pk: *const u8,
    pk_len: usize,
    sig: *const u8,
    sig_len: usize,
    header: *const u8,
    header_len: usize,
    ph: *const u8,
    ph_len: usize,
    nym_secret: *const u8,
    nym_secret_len: usize,
    scope: *const u8,
    scope_len: usize,
    msgs: *const BbsMessage,
    msgs_count: usize,
    committed_msgs: *const BbsMessage,
    committed_msgs_count: usize,
    disclosed_indices: *const u32,
    disclosed_count: usize,
    disclosed_commitment_indices: *const u32,
    disclosed_commitment_count: usize,
    blind_factor: *const u8,
    blind_factor_len: usize,
    proof_out: *mut BbsBuffer,
    pseudonym_out: *mut BbsBuffer,
) -> BbsFfiResult {
    if proof_out.is_null() || pseudonym_out.is_null() {
        return BbsFfiResult::InvalidInput;
    }
    if pk.is_null()
        || pk_len == 0
        || sig.is_null()
        || sig_len == 0
        || nym_secret.is_null()
        || nym_secret_len == 0
        || scope.is_null()
        || scope_len == 0
    {
        *proof_out = BbsBuffer::null();
        *pseudonym_out = BbsBuffer::null();
        return BbsFfiResult::InvalidInput;
    }

    let pk_bytes = slice::from_raw_parts(pk, pk_len).to_vec();
    let sig_bytes = slice::from_raw_parts(sig, sig_len).to_vec();
    let header_bytes = read_optional_bytes(header, header_len);
    let ph_bytes = read_optional_bytes(ph, ph_len);
    let nym_bytes = slice::from_raw_parts(nym_secret, nym_secret_len).to_vec();
    let scope_bytes = slice::from_raw_parts(scope, scope_len).to_vec();
    let messages = collect_messages(msgs, msgs_count);
    let committed_messages = collect_messages(committed_msgs, committed_msgs_count);
    let d_indices = collect_u32_array(disclosed_indices, disclosed_count);
    let dc_indices = collect_u32_array(disclosed_commitment_indices, disclosed_commitment_count);
    let bf_bytes = read_optional_bytes(blind_factor, blind_factor_len);

    match bbs_proof_gen_with_nym(
        pk_bytes,
        sig_bytes,
        header_bytes,
        ph_bytes,
        nym_bytes,
        scope_bytes,
        messages,
        committed_messages,
        d_indices,
        dc_indices,
        bf_bytes,
    ) {
        Ok(result) => {
            *proof_out = BbsBuffer::from_vec(result.proof);
            *pseudonym_out = BbsBuffer::from_vec(result.pseudonym);
            BbsFfiResult::Ok
        }
        Err(_) => {
            *proof_out = BbsBuffer::null();
            *pseudonym_out = BbsBuffer::null();
            BbsFfiResult::ProofGenFailed
        }
    }
}

/// Verify a BBS+ proof with pseudonym.
///
/// On success, writes `1` (valid) or `0` (invalid) to `valid_out`.
///
/// # Arguments
/// * `pk` / `pk_len` — 96-byte issuer public key.
/// * `proof` / `proof_len` — Serialized proof.
/// * `pseudonym` / `pseudonym_len` — 48-byte pseudonym.
/// * `header` / `header_len` — Application-specific header.
/// * `ph` / `ph_len` — Presentation header.
/// * `scope` / `scope_len` — Scope for pseudonym verification.
/// * `total_signer_msgs` — Total count of issuer messages signed.
/// * `disclosed_msgs` / `disclosed_msgs_count` — Disclosed issuer messages.
/// * `disclosed_committed_msgs` / `disclosed_committed_msgs_count` — Disclosed committed messages.
/// * `disclosed_indices` / `disclosed_count` — Indices of disclosed issuer messages.
/// * `disclosed_commitment_indices` / `disclosed_commitment_count` — Indices of disclosed committed messages.
/// * `valid_out` — Output: 1 if valid, 0 if invalid.
///
/// # Safety
///
/// All pointer arguments must be valid for the specified lengths.
#[no_mangle]
pub unsafe extern "C" fn bbs_ffi_proof_verify_with_nym(
    pk: *const u8,
    pk_len: usize,
    proof: *const u8,
    proof_len: usize,
    pseudonym: *const u8,
    pseudonym_len: usize,
    header: *const u8,
    header_len: usize,
    ph: *const u8,
    ph_len: usize,
    scope: *const u8,
    scope_len: usize,
    total_signer_msgs: u32,
    disclosed_msgs: *const BbsMessage,
    disclosed_msgs_count: usize,
    disclosed_committed_msgs: *const BbsMessage,
    disclosed_committed_msgs_count: usize,
    disclosed_indices: *const u32,
    disclosed_count: usize,
    disclosed_commitment_indices: *const u32,
    disclosed_commitment_count: usize,
    valid_out: *mut i32,
) -> BbsFfiResult {
    if valid_out.is_null() {
        return BbsFfiResult::InvalidInput;
    }
    if pk.is_null()
        || pk_len == 0
        || proof.is_null()
        || proof_len == 0
        || pseudonym.is_null()
        || pseudonym_len == 0
        || scope.is_null()
        || scope_len == 0
    {
        *valid_out = 0;
        return BbsFfiResult::InvalidInput;
    }

    let pk_bytes = slice::from_raw_parts(pk, pk_len).to_vec();
    let proof_bytes = slice::from_raw_parts(proof, proof_len).to_vec();
    let nym_bytes = slice::from_raw_parts(pseudonym, pseudonym_len).to_vec();
    let header_bytes = read_optional_bytes(header, header_len);
    let ph_bytes = read_optional_bytes(ph, ph_len);
    let scope_bytes = slice::from_raw_parts(scope, scope_len).to_vec();
    let disc_messages = collect_messages(disclosed_msgs, disclosed_msgs_count);
    let disc_committed_messages =
        collect_messages(disclosed_committed_msgs, disclosed_committed_msgs_count);
    let d_indices = collect_u32_array(disclosed_indices, disclosed_count);
    let dc_indices = collect_u32_array(disclosed_commitment_indices, disclosed_commitment_count);

    match bbs_proof_verify_with_nym(
        pk_bytes,
        proof_bytes,
        nym_bytes,
        header_bytes,
        ph_bytes,
        scope_bytes,
        total_signer_msgs,
        disc_messages,
        disc_committed_messages,
        d_indices,
        dc_indices,
    ) {
        Ok(valid) => {
            *valid_out = if valid { 1 } else { 0 };
            BbsFfiResult::Ok
        }
        Err(_) => {
            *valid_out = 0;
            BbsFfiResult::ProofVerifyFailed
        }
    }
}

// ─── Free ────────────────────────────────────────────────────────────────────

/// Free a buffer previously allocated by any `bbs_ffi_*` function.
///
/// After calling this function, the buffer's `data` pointer is invalid and
/// must not be dereferenced.
///
/// # Safety
///
/// The buffer must have been allocated by one of the `bbs_ffi_*` functions.
/// Calling this on a buffer not allocated by this crate is undefined behavior.
/// It is safe to call this on a null buffer (no-op).
#[no_mangle]
pub unsafe extern "C" fn bbs_ffi_free_buffer(buf: BbsBuffer) {
    if !buf.data.is_null() && buf.cap > 0 {
        let _ = Vec::from_raw_parts(buf.data, buf.len, buf.cap);
    }
}

/// Allocate a raw byte region owned by Rust and return its pointer.
///
/// This is primarily used by non-C callers (for example, WebAssembly hosts)
/// to marshal input buffers for `bbs_ffi_*` functions.
///
/// The returned memory must be released with [`bbs_ffi_dealloc`], using the
/// same `len` and `align`.
///
/// # Safety
///
/// The caller must ensure:
/// - `align` is a non-zero power of two.
/// - `len` and `align` match the values later passed to [`bbs_ffi_dealloc`].
#[no_mangle]
pub unsafe extern "C" fn bbs_ffi_alloc(len: usize, align: usize) -> *mut u8 {
    if len == 0 {
        return ptr::null_mut();
    }
    let Ok(layout) = Layout::from_size_align(len, align) else {
        return ptr::null_mut();
    };
    alloc(layout)
}

/// Free a raw byte region previously allocated by [`bbs_ffi_alloc`].
///
/// # Safety
///
/// `ptr`, `len`, and `align` must exactly match a previous allocation from
/// [`bbs_ffi_alloc`]. Passing arbitrary pointers is undefined behavior.
#[no_mangle]
pub unsafe extern "C" fn bbs_ffi_dealloc(ptr: *mut u8, len: usize, align: usize) {
    if ptr.is_null() || len == 0 {
        return;
    }
    let Ok(layout) = Layout::from_size_align(len, align) else {
        return;
    };
    dealloc(ptr, layout);
}

// ─── Internal Helpers ────────────────────────────────────────────────────────

/// Reads optional bytes from a C pointer, returning empty Vec if null.
///
/// # Safety
///
/// `ptr` must be valid for `len` bytes if non-null.
unsafe fn read_optional_bytes(ptr: *const u8, len: usize) -> Vec<u8> {
    if ptr.is_null() || len == 0 {
        Vec::new()
    } else {
        slice::from_raw_parts(ptr, len).to_vec()
    }
}

/// Collects a C array of [`BbsMessage`] into a `Vec<Vec<u8>>`.
///
/// # Safety
///
/// `msgs` must be a valid pointer to `count` contiguous `BbsMessage` structs,
/// or null if `count` is 0.
unsafe fn collect_messages(msgs: *const BbsMessage, count: usize) -> Vec<Vec<u8>> {
    if msgs.is_null() || count == 0 {
        return Vec::new();
    }

    let msg_slice = slice::from_raw_parts(msgs, count);
    msg_slice
        .iter()
        .map(|m| {
            if m.data.is_null() || m.len == 0 {
                Vec::new()
            } else {
                slice::from_raw_parts(m.data, m.len).to_vec()
            }
        })
        .collect()
}

/// Collects a C array of u32 into a `Vec<u32>`.
///
/// # Safety
///
/// `arr` must be a valid pointer to `count` contiguous u32 values,
/// or null if `count` is 0.
unsafe fn collect_u32_array(arr: *const u32, count: usize) -> Vec<u32> {
    if arr.is_null() || count == 0 {
        return Vec::new();
    }
    slice::from_raw_parts(arr, count).to_vec()
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_c_ffi_generate_keypair() {
        let mut sk = BbsBuffer::null();
        let mut pk = BbsBuffer::null();

        let result = unsafe { bbs_ffi_generate_keypair(&mut sk, &mut pk) };
        assert_eq!(result, BbsFfiResult::Ok);

        assert!(!sk.data.is_null());
        assert_eq!(sk.len, 32, "BBS+ secret key should be 32 bytes");

        assert!(!pk.data.is_null());
        assert_eq!(pk.len, 96, "BBS+ public key should be 96 bytes");

        unsafe {
            bbs_ffi_free_buffer(sk);
            bbs_ffi_free_buffer(pk);
        }
    }

    #[test]
    fn test_c_ffi_sign_verify_roundtrip() {
        let mut sk = BbsBuffer::null();
        let mut pk = BbsBuffer::null();
        let result = unsafe { bbs_ffi_generate_keypair(&mut sk, &mut pk) };
        assert_eq!(result, BbsFfiResult::Ok);

        let header = b"test-header";
        let msg1 = b"message1";
        let msg2 = b"message2";
        let msgs = [
            BbsMessage {
                data: msg1.as_ptr(),
                len: msg1.len(),
            },
            BbsMessage {
                data: msg2.as_ptr(),
                len: msg2.len(),
            },
        ];

        let mut sig = BbsBuffer::null();
        let result = unsafe {
            bbs_ffi_sign(
                sk.data,
                sk.len,
                pk.data,
                pk.len,
                header.as_ptr(),
                header.len(),
                msgs.as_ptr(),
                msgs.len(),
                &mut sig,
            )
        };
        assert_eq!(result, BbsFfiResult::Ok);
        assert_eq!(sig.len, 80, "BBS+ signature should be 80 bytes");

        let mut valid: i32 = 0;
        let result = unsafe {
            bbs_ffi_verify(
                pk.data,
                pk.len,
                header.as_ptr(),
                header.len(),
                sig.data,
                sig.len,
                msgs.as_ptr(),
                msgs.len(),
                &mut valid,
            )
        };
        assert_eq!(result, BbsFfiResult::Ok);
        assert_eq!(valid, 1, "signature should be valid");

        unsafe {
            bbs_ffi_free_buffer(sk);
            bbs_ffi_free_buffer(pk);
            bbs_ffi_free_buffer(sig);
        }
    }

    #[test]
    fn test_c_ffi_proof_gen_verify_roundtrip() {
        let mut sk = BbsBuffer::null();
        let mut pk = BbsBuffer::null();
        unsafe { bbs_ffi_generate_keypair(&mut sk, &mut pk) };

        let header = b"test-header";
        let msg1 = b"attestationType";
        let msg2 = b"deviceType";
        let msg3 = b"expiresAt";
        let msgs = [
            BbsMessage {
                data: msg1.as_ptr(),
                len: msg1.len(),
            },
            BbsMessage {
                data: msg2.as_ptr(),
                len: msg2.len(),
            },
            BbsMessage {
                data: msg3.as_ptr(),
                len: msg3.len(),
            },
        ];

        // Sign
        let mut sig = BbsBuffer::null();
        unsafe {
            bbs_ffi_sign(
                sk.data,
                sk.len,
                pk.data,
                pk.len,
                header.as_ptr(),
                header.len(),
                msgs.as_ptr(),
                msgs.len(),
                &mut sig,
            )
        };

        // Proof gen - disclose indices 0 and 2
        let ph = b"nonce-123";
        let indices: [u32; 2] = [0, 2];
        let mut proof = BbsBuffer::null();
        let result = unsafe {
            bbs_ffi_proof_gen(
                pk.data,
                pk.len,
                sig.data,
                sig.len,
                header.as_ptr(),
                header.len(),
                ph.as_ptr(),
                ph.len(),
                msgs.as_ptr(),
                msgs.len(),
                indices.as_ptr(),
                indices.len(),
                &mut proof,
            )
        };
        assert_eq!(result, BbsFfiResult::Ok);
        assert!(!proof.data.is_null());

        // Proof verify - disclosed messages at indices 0 and 2
        let disc_msgs = [
            BbsMessage {
                data: msg1.as_ptr(),
                len: msg1.len(),
            },
            BbsMessage {
                data: msg3.as_ptr(),
                len: msg3.len(),
            },
        ];
        let mut valid: i32 = 0;
        let result = unsafe {
            bbs_ffi_proof_verify(
                pk.data,
                pk.len,
                proof.data,
                proof.len,
                header.as_ptr(),
                header.len(),
                ph.as_ptr(),
                ph.len(),
                disc_msgs.as_ptr(),
                disc_msgs.len(),
                indices.as_ptr(),
                indices.len(),
                &mut valid,
            )
        };
        assert_eq!(result, BbsFfiResult::Ok);
        assert_eq!(valid, 1, "proof should be valid");

        unsafe {
            bbs_ffi_free_buffer(sk);
            bbs_ffi_free_buffer(pk);
            bbs_ffi_free_buffer(sig);
            bbs_ffi_free_buffer(proof);
        }
    }

    #[test]
    fn test_c_ffi_nym_secret_generation() {
        let mut secret = BbsBuffer::null();
        let result = unsafe { bbs_ffi_generate_nym_secret(&mut secret) };
        assert_eq!(result, BbsFfiResult::Ok);
        assert_eq!(secret.len, 32, "nym secret should be 32 bytes");

        unsafe { bbs_ffi_free_buffer(secret) };
    }

    #[test]
    fn test_c_ffi_null_pointer_safety() {
        // generate_keypair with null outputs
        let result = unsafe { bbs_ffi_generate_keypair(ptr::null_mut(), ptr::null_mut()) };
        assert_eq!(result, BbsFfiResult::InvalidInput);

        // sign with null sig_out
        let result = unsafe {
            bbs_ffi_sign(
                ptr::null(),
                0,
                ptr::null(),
                0,
                ptr::null(),
                0,
                ptr::null(),
                0,
                ptr::null_mut(),
            )
        };
        assert_eq!(result, BbsFfiResult::InvalidInput);

        // verify with null valid_out
        let result = unsafe {
            bbs_ffi_verify(
                ptr::null(),
                0,
                ptr::null(),
                0,
                ptr::null(),
                0,
                ptr::null(),
                0,
                ptr::null_mut(),
            )
        };
        assert_eq!(result, BbsFfiResult::InvalidInput);

        // proof gen with null outputs
        let result = unsafe {
            bbs_ffi_proof_gen(
                ptr::null(),
                0,
                ptr::null(),
                0,
                ptr::null(),
                0,
                ptr::null(),
                0,
                ptr::null(),
                0,
                ptr::null(),
                0,
                ptr::null_mut(),
            )
        };
        assert_eq!(result, BbsFfiResult::InvalidInput);

        // generate_nym_secret with null output
        let result = unsafe { bbs_ffi_generate_nym_secret(ptr::null_mut()) };
        assert_eq!(result, BbsFfiResult::InvalidInput);
    }

    #[test]
    fn test_c_ffi_free_buffer_null() {
        unsafe {
            bbs_ffi_free_buffer(BbsBuffer::null());
        }
    }

    #[test]
    fn test_c_ffi_buffer_preserves_capacity() {
        let mut v = Vec::with_capacity(256);
        v.extend_from_slice(b"hello");
        assert!(v.capacity() > v.len(), "test requires excess capacity");

        let buf = BbsBuffer::from_vec(v);
        assert_eq!(buf.len, 5);
        assert_eq!(buf.cap, 256);
        assert!(
            buf.cap > buf.len,
            "cap must preserve original allocation size"
        );

        unsafe {
            bbs_ffi_free_buffer(buf);
        }
    }

    #[test]
    fn test_c_ffi_signature_is_80_bytes() {
        let mut sk = BbsBuffer::null();
        let mut pk = BbsBuffer::null();
        unsafe { bbs_ffi_generate_keypair(&mut sk, &mut pk) };

        let header = b"test";
        let msg = b"data";
        let msgs = [BbsMessage {
            data: msg.as_ptr(),
            len: msg.len(),
        }];

        let mut sig = BbsBuffer::null();
        let result = unsafe {
            bbs_ffi_sign(
                sk.data,
                sk.len,
                pk.data,
                pk.len,
                header.as_ptr(),
                header.len(),
                msgs.as_ptr(),
                msgs.len(),
                &mut sig,
            )
        };
        assert_eq!(result, BbsFfiResult::Ok);
        assert_eq!(
            sig.len, 80,
            "BBS+ BLS12-381-SHA-256 signature must be exactly 80 bytes"
        );

        unsafe {
            bbs_ffi_free_buffer(sk);
            bbs_ffi_free_buffer(pk);
            bbs_ffi_free_buffer(sig);
        }
    }
}

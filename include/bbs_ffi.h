/*
 * C header for bbs-ffi: BBS+ signature, proof, and pseudonym operations (BLS12-381-SHA-256).
 *
 * This header declares the C-compatible FFI functions exported by the
 * bbs-ffi Rust crate. It is used by Go's CGo to link against the static
 * library (libbbs_ffi.a).
 *
 * Memory management: All BbsBuffer outputs are allocated by Rust. Callers
 * must free them with bbs_ffi_free_buffer(). Do not use free() directly.
 */

#ifndef BBS_FFI_H
#define BBS_FFI_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Result codes for BBS+ FFI operations. */
typedef enum {
    BBS_FFI_OK                  = 0,
    BBS_FFI_KEYGEN_FAILED       = 1,
    BBS_FFI_SIGN_FAILED         = 2,
    BBS_FFI_VERIFY_FAILED       = 3,
    BBS_FFI_INVALID_INPUT       = 4,
    BBS_FFI_PROOF_GEN_FAILED    = 5,
    BBS_FFI_PROOF_VERIFY_FAILED = 6,
    BBS_FFI_COMMITMENT_FAILED   = 7,
} BbsFfiResult;

/* A heap-allocated byte buffer returned from Rust. Free with bbs_ffi_free_buffer(). */
typedef struct {
    uint8_t *data;
    size_t   len;
    size_t   cap;  /* Original allocation capacity — required for correct deallocation. */
} BbsBuffer;

/* A read-only byte slice passed from C to Rust (for message arrays). */
typedef struct {
    const uint8_t *data;
    size_t         len;
} BbsMessage;

/* ── Key Generation ──────────────────────────────────────────────────────── */

/*
 * Generate a new BBS+ keypair (BLS12-381-SHA-256).
 *
 * On success (BBS_FFI_OK):
 *   sk_out: 32-byte secret key
 *   pk_out: 96-byte public key (compressed G2)
 *
 * Both output buffers must be freed with bbs_ffi_free_buffer().
 */
BbsFfiResult bbs_ffi_generate_keypair(BbsBuffer *sk_out, BbsBuffer *pk_out);

/* ── Signing / Verification ──────────────────────────────────────────────── */

/*
 * Sign messages with a BBS+ secret key.
 *
 * Parameters:
 *   sk, sk_len:           Secret key (32 bytes)
 *   pk, pk_len:           Public key (96 bytes)
 *   header, header_len:   Application-specific header bytes
 *   msgs, msgs_count:     Array of BbsMessage structs
 *   sig_out:              Output: 80-byte BBS+ signature
 *
 * The output buffer must be freed with bbs_ffi_free_buffer().
 */
BbsFfiResult bbs_ffi_sign(
    const uint8_t *sk, size_t sk_len,
    const uint8_t *pk, size_t pk_len,
    const uint8_t *header, size_t header_len,
    const BbsMessage *msgs, size_t msgs_count,
    BbsBuffer *sig_out
);

/*
 * Verify a BBS+ signature.
 *
 * Parameters:
 *   pk, pk_len:           Public key (96 bytes)
 *   header, header_len:   Application-specific header bytes
 *   sig, sig_len:         BBS+ signature (80 bytes)
 *   msgs, msgs_count:     Array of BbsMessage structs
 *   valid_out:            Output: 1 if valid, 0 if invalid
 */
BbsFfiResult bbs_ffi_verify(
    const uint8_t *pk, size_t pk_len,
    const uint8_t *header, size_t header_len,
    const uint8_t *sig, size_t sig_len,
    const BbsMessage *msgs, size_t msgs_count,
    int32_t *valid_out
);

/* ── Selective Disclosure Proofs ─────────────────────────────────────────── */

/*
 * Generate a BBS+ selective disclosure proof.
 *
 * Parameters:
 *   pk, pk_len:                    Issuer public key (96 bytes)
 *   sig, sig_len:                  BBS+ signature (80 bytes)
 *   header, header_len:            Application-specific header
 *   ph, ph_len:                    Presentation header (nonce from verifier)
 *   msgs, msgs_count:              All signed messages
 *   disclosed_indices, disclosed_count:  Indices of messages to disclose
 *   proof_out:                     Output: serialized proof
 */
BbsFfiResult bbs_ffi_proof_gen(
    const uint8_t *pk, size_t pk_len,
    const uint8_t *sig, size_t sig_len,
    const uint8_t *header, size_t header_len,
    const uint8_t *ph, size_t ph_len,
    const BbsMessage *msgs, size_t msgs_count,
    const uint32_t *disclosed_indices, size_t disclosed_count,
    BbsBuffer *proof_out
);

/*
 * Verify a BBS+ selective disclosure proof.
 *
 * Parameters:
 *   pk, pk_len:                    Issuer public key (96 bytes)
 *   proof, proof_len:              Serialized proof
 *   header, header_len:            Application-specific header
 *   ph, ph_len:                    Presentation header
 *   disclosed_msgs, disclosed_msgs_count:  Disclosed messages only
 *   disclosed_indices, disclosed_count:    Indices of disclosed messages
 *   valid_out:                     Output: 1 if valid, 0 if invalid
 */
BbsFfiResult bbs_ffi_proof_verify(
    const uint8_t *pk, size_t pk_len,
    const uint8_t *proof, size_t proof_len,
    const uint8_t *header, size_t header_len,
    const uint8_t *ph, size_t ph_len,
    const BbsMessage *disclosed_msgs, size_t disclosed_msgs_count,
    const uint32_t *disclosed_indices, size_t disclosed_count,
    int32_t *valid_out
);

/* ── Blind Signing with Pseudonyms ───────────────────────────────────────── */

/*
 * Generate a random pseudonym secret (32-byte BLS12-381 scalar).
 *
 * The secret is used as the prover's contribution to the combined
 * pseudonym secret. Store securely (e.g., biometric-protected Keychain).
 */
BbsFfiResult bbs_ffi_generate_nym_secret(BbsBuffer *secret_out);

/*
 * Create a blind commitment with pseudonym for credential enrollment.
 *
 * The holder generates a Pedersen commitment over committed messages
 * and their nym secret. The commitment (with ZK proof) is sent to the
 * issuer; the blind_factor is kept secret.
 *
 * Parameters:
 *   committed_msgs, committed_msgs_count:  Holder's committed messages (can be NULL/0)
 *   prover_nym, prover_nym_len:            32-byte prover nym secret
 *   commitment_out:                        Output: commitment with proof
 *   blind_factor_out:                      Output: blind factor (keep secret)
 */
BbsFfiResult bbs_ffi_commit_with_nym(
    const BbsMessage *committed_msgs, size_t committed_msgs_count,
    const uint8_t *prover_nym, size_t prover_nym_len,
    BbsBuffer *commitment_out,
    BbsBuffer *blind_factor_out
);

/*
 * Issuer blind-signs a credential with pseudonym.
 *
 * Parameters:
 *   sk, sk_len:                 32-byte issuer secret key
 *   pk, pk_len:                 96-byte issuer public key
 *   commitment, commitment_len: Holder's commitment with proof
 *   header, header_len:         Application-specific header
 *   signer_nym, signer_nym_len: 32-byte issuer nym entropy
 *   msgs, msgs_count:           Issuer-known messages
 *   sig_out:                    Output: 80-byte blind signature
 */
BbsFfiResult bbs_ffi_blind_sign_with_nym(
    const uint8_t *sk, size_t sk_len,
    const uint8_t *pk, size_t pk_len,
    const uint8_t *commitment, size_t commitment_len,
    const uint8_t *header, size_t header_len,
    const uint8_t *signer_nym, size_t signer_nym_len,
    const BbsMessage *msgs, size_t msgs_count,
    BbsBuffer *sig_out
);

/*
 * Holder verifies blind signature and extracts combined nym secret.
 *
 * Parameters:
 *   pk, pk_len:                               96-byte issuer public key
 *   blind_sig, blind_sig_len:                 80-byte blind signature
 *   header, header_len:                       Application-specific header
 *   msgs, msgs_count:                         Issuer-known messages
 *   committed_msgs, committed_msgs_count:     Holder's committed messages
 *   prover_nym, prover_nym_len:               32-byte prover nym secret
 *   signer_nym, signer_nym_len:               32-byte issuer nym entropy
 *   blind_factor, blind_factor_len:           Blind factor from commitment
 *   nym_secret_out:                           Output: 32-byte combined nym secret
 */
BbsFfiResult bbs_ffi_verify_blind_sign_with_nym(
    const uint8_t *pk, size_t pk_len,
    const uint8_t *blind_sig, size_t blind_sig_len,
    const uint8_t *header, size_t header_len,
    const BbsMessage *msgs, size_t msgs_count,
    const BbsMessage *committed_msgs, size_t committed_msgs_count,
    const uint8_t *prover_nym, size_t prover_nym_len,
    const uint8_t *signer_nym, size_t signer_nym_len,
    const uint8_t *blind_factor, size_t blind_factor_len,
    BbsBuffer *nym_secret_out
);

/*
 * Generate a BBS+ proof with pseudonym (per-verifier linkability).
 *
 * Creates a selective disclosure proof that also proves correct derivation
 * of a scope-bound pseudonym from the holder's nym_secret.
 *
 * Parameters:
 *   pk, pk_len:                          96-byte issuer public key
 *   sig, sig_len:                        80-byte blind signature
 *   header, header_len:                  Application-specific header
 *   ph, ph_len:                          Presentation header
 *   nym_secret, nym_secret_len:          32-byte combined nym secret
 *   scope, scope_len:                    Scope for pseudonym derivation
 *   msgs, msgs_count:                    Issuer-known messages
 *   committed_msgs, committed_msgs_count: Holder's committed messages
 *   disclosed_indices, disclosed_count:  Indices of issuer messages to disclose
 *   disclosed_commitment_indices, disclosed_commitment_count: Indices of committed messages to disclose
 *   blind_factor, blind_factor_len:      Blind factor from commitment
 *   proof_out:                           Output: serialized proof
 *   pseudonym_out:                       Output: 48-byte pseudonym (compressed G1)
 */
BbsFfiResult bbs_ffi_proof_gen_with_nym(
    const uint8_t *pk, size_t pk_len,
    const uint8_t *sig, size_t sig_len,
    const uint8_t *header, size_t header_len,
    const uint8_t *ph, size_t ph_len,
    const uint8_t *nym_secret, size_t nym_secret_len,
    const uint8_t *scope, size_t scope_len,
    const BbsMessage *msgs, size_t msgs_count,
    const BbsMessage *committed_msgs, size_t committed_msgs_count,
    const uint32_t *disclosed_indices, size_t disclosed_count,
    const uint32_t *disclosed_commitment_indices, size_t disclosed_commitment_count,
    const uint8_t *blind_factor, size_t blind_factor_len,
    BbsBuffer *proof_out,
    BbsBuffer *pseudonym_out
);

/*
 * Verify a BBS+ proof with pseudonym.
 *
 * Validates a selective disclosure proof and verifies correctness of the
 * scope-bound pseudonym.
 *
 * Parameters:
 *   pk, pk_len:                          96-byte issuer public key
 *   proof, proof_len:                    Serialized proof
 *   pseudonym, pseudonym_len:            48-byte pseudonym
 *   header, header_len:                  Application-specific header
 *   ph, ph_len:                          Presentation header
 *   scope, scope_len:                    Scope for pseudonym verification
 *   total_signer_msgs:                   Total count of issuer messages signed
 *   disclosed_msgs, disclosed_msgs_count: Disclosed issuer messages
 *   disclosed_committed_msgs, disclosed_committed_msgs_count: Disclosed committed messages
 *   disclosed_indices, disclosed_count:  Indices of disclosed issuer messages
 *   disclosed_commitment_indices, disclosed_commitment_count: Indices of disclosed committed messages
 *   valid_out:                           Output: 1 if valid, 0 if invalid
 */
BbsFfiResult bbs_ffi_proof_verify_with_nym(
    const uint8_t *pk, size_t pk_len,
    const uint8_t *proof, size_t proof_len,
    const uint8_t *pseudonym, size_t pseudonym_len,
    const uint8_t *header, size_t header_len,
    const uint8_t *ph, size_t ph_len,
    const uint8_t *scope, size_t scope_len,
    uint32_t total_signer_msgs,
    const BbsMessage *disclosed_msgs, size_t disclosed_msgs_count,
    const BbsMessage *disclosed_committed_msgs, size_t disclosed_committed_msgs_count,
    const uint32_t *disclosed_indices, size_t disclosed_count,
    const uint32_t *disclosed_commitment_indices, size_t disclosed_commitment_count,
    int32_t *valid_out
);

/* ── Buffer Management ───────────────────────────────────────────────────── */

/*
 * Allocate a raw byte region owned by Rust.
 *
 * Used by non-C hosts (for example, wasm runtimes) to marshal inputs to
 * bbs_ffi_* functions.
 *
 * The returned pointer must be released with bbs_ffi_dealloc(ptr, len, align)
 * using the same len and align.
 *
 * align must be a non-zero power of two.
 */
uint8_t *bbs_ffi_alloc(size_t len, size_t align);

/*
 * Free a raw byte region previously allocated by bbs_ffi_alloc.
 *
 * It is safe to call with ptr == NULL or len == 0.
 */
void bbs_ffi_dealloc(uint8_t *ptr, size_t len, size_t align);

/*
 * Free a buffer previously allocated by a bbs_ffi_* function.
 *
 * Safe to call on a null/zero buffer (no-op).
 * After calling, the buffer's data pointer is invalid.
 */
void bbs_ffi_free_buffer(BbsBuffer buf);

#ifdef __cplusplus
}
#endif

#endif /* BBS_FFI_H */

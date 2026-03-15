//! Rust FFI crate for AckAgent anonymous attestation.
//!
//! Exposes BBS+ (BLS12-381-SHA-256) operations to Swift via UniFFI and to Go via C FFI:
//!   - Key generation, signing, verification (existing)
//!   - Selective disclosure proof generation/verification (new)
//!   - Blind signing with pseudonyms for per-verifier linkability (new)
//!   - Pseudonym secret generation (new)

#[cfg(not(target_arch = "wasm32"))]
uniffi::setup_scaffolding!();

// UniFFI macros expect this tag type; on wasm32 we don't link UniFFI scaffolding,
// but still compile shared logic from this crate.
#[cfg(target_arch = "wasm32")]
pub struct UniFfiTag;

mod c_ffi;

// ─── UniFFI Record Types ────────────────────────────────────────────────────

/// A BBS+ keypair (BLS12-381).
#[derive(uniffi::Record)]
pub struct BbsKeyPair {
    /// Secret key (32 bytes, big-endian BLS12-381 scalar).
    pub secret_key: Vec<u8>,
    /// Public key (96 bytes, compressed G2 point).
    pub public_key: Vec<u8>,
}

/// Result of blind commitment with pseudonym.
///
/// Returned by [`bbs_commit_with_nym`]. The holder sends `commitment_with_proof`
/// to the issuer; the `blind_factor` and `prover_nym_secret` are kept secret.
#[derive(uniffi::Record)]
pub struct BbsBlindCommitmentResult {
    /// Serialized commitment with ZK proof of committed values.
    pub commitment_with_proof: Vec<u8>,
    /// Secret blinding factor (must be kept by holder for proof generation).
    pub blind_factor: Vec<u8>,
}

/// Result of verifying a blind signature with pseudonym.
///
/// Returned by [`bbs_verify_blind_sign_with_nym`]. The `nym_secret` is the
/// combined secret used for pseudonym derivation during proof generation.
#[derive(uniffi::Record)]
pub struct BbsVerifyBlindSignResult {
    /// Combined pseudonym secret (prover_nym + signer_nym_entropy).
    /// Used as input to [`bbs_proof_gen_with_nym`].
    pub nym_secret: Vec<u8>,
}

/// Result of proof generation with pseudonym.
///
/// Returned by [`bbs_proof_gen_with_nym`].
#[derive(uniffi::Record)]
pub struct BbsProofWithPseudonym {
    /// Serialized BBS+ selective disclosure proof.
    pub proof: Vec<u8>,
    /// Scope-bound pseudonym (48 bytes, compressed G1 point).
    pub pseudonym: Vec<u8>,
}

// ─── UniFFI Error Type ──────────────────────────────────────────────────────

/// Errors returned by FFI operations.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum FfiError {
    /// BBS+ key generation failed.
    #[error("Key generation failed: {msg}")]
    KeyGenerationFailed {
        /// Detail message.
        msg: String,
    },
    /// BBS+ signing failed.
    #[error("BBS+ signing failed: {msg}")]
    SigningFailed {
        /// Detail message.
        msg: String,
    },
    /// BBS+ verification failed.
    #[error("BBS+ verification failed: {msg}")]
    VerificationFailed {
        /// Detail message.
        msg: String,
    },
    /// BBS+ proof generation failed.
    #[error("BBS+ proof generation failed: {msg}")]
    ProofGenFailed {
        /// Detail message.
        msg: String,
    },
    /// BBS+ proof verification failed.
    #[error("BBS+ proof verification failed: {msg}")]
    ProofVerifyFailed {
        /// Detail message.
        msg: String,
    },
    /// Blind commitment failed.
    #[error("Blind commitment failed: {msg}")]
    CommitmentFailed {
        /// Detail message.
        msg: String,
    },
    /// BBS+ credential parsing failed.
    #[error("BBS+ credential parse failed: {msg}")]
    CredentialParseFailed {
        /// Detail message.
        msg: String,
    },
}

// ─── BBS+ Key Operations ──────────────────────────────────────────────────

/// Generate a random BBS+ keypair (BLS12-381-SHA-256).
///
/// Returns a [`BbsKeyPair`] with a 32-byte secret key and 96-byte compressed
/// public key.
#[uniffi::export]
pub fn bbs_generate_keypair() -> Result<BbsKeyPair, FfiError> {
    use zkryptium::bbsplus::keys::{BBSplusPublicKey, BBSplusSecretKey};
    use zkryptium::keys::pair::KeyPair;
    use zkryptium::schemes::algorithms::BbsBls12381Sha256;

    let keypair =
        KeyPair::<BbsBls12381Sha256>::random().map_err(|e| FfiError::KeyGenerationFailed {
            msg: format!("BBS+ key generation failed: {e:?}"),
        })?;

    let sk_bytes = BBSplusSecretKey::to_bytes(keypair.private_key()).to_vec();
    let pk_bytes = BBSplusPublicKey::to_bytes(keypair.public_key()).to_vec();

    Ok(BbsKeyPair {
        secret_key: sk_bytes,
        public_key: pk_bytes,
    })
}

// ─── BBS+ Sign / Verify ──────────────────────────────────────────────────

/// Sign messages with a BBS+ secret key (BLS12-381-SHA-256).
///
/// # Arguments
/// * `secret_key` - 32-byte BLS12-381 scalar (big-endian).
/// * `public_key` - 96-byte compressed G2 point.
/// * `header` - Application-specific header bytes.
/// * `messages` - Vector of message byte arrays to sign.
///
/// Returns the 80-byte BBS+ signature.
#[uniffi::export]
pub fn bbs_sign(
    secret_key: Vec<u8>,
    public_key: Vec<u8>,
    header: Vec<u8>,
    messages: Vec<Vec<u8>>,
) -> Result<Vec<u8>, FfiError> {
    use zkryptium::bbsplus::keys::{BBSplusPublicKey, BBSplusSecretKey};
    use zkryptium::schemes::algorithms::BbsBls12381Sha256;
    use zkryptium::schemes::generics::Signature;

    let sk = BBSplusSecretKey::from_bytes(&secret_key).map_err(|e| FfiError::SigningFailed {
        msg: format!("Invalid secret key: {e:?}"),
    })?;

    let pk = BBSplusPublicKey::from_bytes(&public_key).map_err(|e| FfiError::SigningFailed {
        msg: format!("Invalid public key: {e:?}"),
    })?;

    let sig = Signature::<BbsBls12381Sha256>::sign(Some(&messages), &sk, &pk, Some(&header))
        .map_err(|e| FfiError::SigningFailed {
            msg: format!("BBS+ sign failed: {e:?}"),
        })?;

    Ok(sig.to_bytes().to_vec())
}

/// Verify a BBS+ signature (BLS12-381-SHA-256).
///
/// # Arguments
/// * `public_key` - 96-byte compressed G2 point.
/// * `header` - Application-specific header bytes.
/// * `signature` - 80-byte BBS+ signature.
/// * `messages` - Vector of message byte arrays that were signed.
///
/// Returns `true` if the signature is valid.
#[uniffi::export]
pub fn bbs_verify(
    public_key: Vec<u8>,
    header: Vec<u8>,
    signature: Vec<u8>,
    messages: Vec<Vec<u8>>,
) -> Result<bool, FfiError> {
    use zkryptium::bbsplus::keys::BBSplusPublicKey;
    use zkryptium::bbsplus::signature::BBSplusSignature;
    use zkryptium::schemes::algorithms::BbsBls12381Sha256;
    use zkryptium::schemes::generics::Signature;

    let pk =
        BBSplusPublicKey::from_bytes(&public_key).map_err(|e| FfiError::VerificationFailed {
            msg: format!("Invalid public key: {e:?}"),
        })?;

    if signature.len() != BBSplusSignature::BYTES {
        return Err(FfiError::VerificationFailed {
            msg: format!(
                "Signature must be {} bytes, got {}",
                BBSplusSignature::BYTES,
                signature.len()
            ),
        });
    }

    let sig_bytes: [u8; 80] = signature
        .try_into()
        .map_err(|_| FfiError::VerificationFailed {
            msg: "Failed to convert signature bytes".to_string(),
        })?;

    let sig = Signature::<BbsBls12381Sha256>::from_bytes(&sig_bytes).map_err(|e| {
        FfiError::VerificationFailed {
            msg: format!("Invalid signature: {e:?}"),
        }
    })?;

    match sig.verify(&pk, Some(&messages), Some(&header)) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

// ─── BBS+ Selective Disclosure Proofs ─────────────────────────────────────

/// Generate a BBS+ selective disclosure proof (BLS12-381-SHA-256).
///
/// Creates a zero-knowledge proof-of-knowledge of a BBS+ signature, revealing
/// only the messages at the specified `disclosed_indices`.
///
/// # Arguments
/// * `public_key` - 96-byte issuer public key.
/// * `signature` - 80-byte BBS+ signature.
/// * `header` - Application-specific header (must match signing header).
/// * `presentation_header` - Presentation-specific binding (e.g., nonce from verifier).
/// * `messages` - All signed messages (same order as signing).
/// * `disclosed_indices` - Indices of messages to reveal to verifier (ascending order).
///
/// Returns the serialized proof bytes.
#[uniffi::export]
pub fn bbs_proof_gen(
    public_key: Vec<u8>,
    signature: Vec<u8>,
    header: Vec<u8>,
    presentation_header: Vec<u8>,
    messages: Vec<Vec<u8>>,
    disclosed_indices: Vec<u32>,
) -> Result<Vec<u8>, FfiError> {
    use zkryptium::bbsplus::keys::BBSplusPublicKey;
    use zkryptium::schemes::algorithms::BbsBls12381Sha256;
    use zkryptium::schemes::generics::PoKSignature;

    let pk = BBSplusPublicKey::from_bytes(&public_key).map_err(|e| FfiError::ProofGenFailed {
        msg: format!("Invalid public key: {e:?}"),
    })?;

    let indices: Vec<usize> = disclosed_indices.iter().map(|&i| i as usize).collect();

    let proof = PoKSignature::<BbsBls12381Sha256>::proof_gen(
        &pk,
        &signature,
        Some(&header),
        Some(&presentation_header),
        Some(&messages),
        Some(&indices),
    )
    .map_err(|e| FfiError::ProofGenFailed {
        msg: format!("BBS+ proof generation failed: {e:?}"),
    })?;

    Ok(proof.to_bytes())
}

/// Verify a BBS+ selective disclosure proof (BLS12-381-SHA-256).
///
/// # Arguments
/// * `public_key` - 96-byte issuer public key.
/// * `proof` - Serialized proof bytes from [`bbs_proof_gen`].
/// * `header` - Application-specific header (must match signing header).
/// * `presentation_header` - Presentation-specific binding (must match proof gen).
/// * `disclosed_messages` - Only the revealed messages (matching disclosed_indices order).
/// * `disclosed_indices` - Indices of disclosed messages (ascending order).
///
/// Returns `true` if the proof is valid.
#[uniffi::export]
pub fn bbs_proof_verify(
    public_key: Vec<u8>,
    proof: Vec<u8>,
    header: Vec<u8>,
    presentation_header: Vec<u8>,
    disclosed_messages: Vec<Vec<u8>>,
    disclosed_indices: Vec<u32>,
) -> Result<bool, FfiError> {
    use zkryptium::bbsplus::keys::BBSplusPublicKey;
    use zkryptium::schemes::algorithms::BbsBls12381Sha256;
    use zkryptium::schemes::generics::PoKSignature;

    let pk =
        BBSplusPublicKey::from_bytes(&public_key).map_err(|e| FfiError::ProofVerifyFailed {
            msg: format!("Invalid public key: {e:?}"),
        })?;

    let indices: Vec<usize> = disclosed_indices.iter().map(|&i| i as usize).collect();

    let pok = PoKSignature::<BbsBls12381Sha256>::from_bytes(&proof).map_err(|e| {
        FfiError::ProofVerifyFailed {
            msg: format!("Invalid proof bytes: {e:?}"),
        }
    })?;

    match pok.proof_verify(
        &pk,
        Some(&disclosed_messages),
        Some(&indices),
        Some(&header),
        Some(&presentation_header),
    ) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

// ─── BBS+ Blind Signing with Pseudonyms ──────────────────────────────────

/// Generate a random pseudonym secret (BLS12-381 scalar, 32 bytes).
///
/// This secret is used as the prover's contribution to the combined pseudonym
/// secret. It should be stored securely (e.g., biometric-protected Keychain).
#[uniffi::export]
pub fn bbs_generate_nym_secret() -> Result<Vec<u8>, FfiError> {
    use zkryptium::bbsplus::pseudonym::PseudonymSecret;

    let secret = PseudonymSecret::random();
    Ok(secret.to_bytes().to_vec())
}

/// Create a blind commitment with pseudonym for credential enrollment.
///
/// The holder generates a Pedersen commitment over their committed messages and
/// prover nym secret. The commitment (with ZK proof) is sent to the issuer;
/// the blind_factor must be kept secret by the holder.
///
/// # Arguments
/// * `committed_messages` - Messages the holder wants to commit (hidden from issuer).
///   Can be empty if holder only commits the nym secret.
/// * `prover_nym_secret` - 32-byte pseudonym secret from [`bbs_generate_nym_secret`].
///
/// # Returns
/// [`BbsBlindCommitmentResult`] with commitment_with_proof and blind_factor.
#[uniffi::export]
pub fn bbs_commit_with_nym(
    committed_messages: Vec<Vec<u8>>,
    prover_nym_secret: Vec<u8>,
) -> Result<BbsBlindCommitmentResult, FfiError> {
    use zkryptium::bbsplus::pseudonym::PseudonymSecret;
    use zkryptium::schemes::algorithms::BbsBls12381Sha256;
    use zkryptium::schemes::generics::Commitment;

    let nym_secret_bytes: [u8; 32] =
        prover_nym_secret
            .try_into()
            .map_err(|_| FfiError::CommitmentFailed {
                msg: "Prover nym secret must be 32 bytes".to_string(),
            })?;

    let prover_nym =
        PseudonymSecret::from_bytes(&nym_secret_bytes).map_err(|e| FfiError::CommitmentFailed {
            msg: format!("Invalid prover nym secret: {e:?}"),
        })?;

    let committed_msgs = if committed_messages.is_empty() {
        None
    } else {
        Some(committed_messages.as_slice())
    };

    let (commitment_with_proof, blind_factor) =
        Commitment::<BbsBls12381Sha256>::commit_with_nym(committed_msgs, Some(&prover_nym))
            .map_err(|e| FfiError::CommitmentFailed {
                msg: format!("Blind commitment failed: {e:?}"),
            })?;

    Ok(BbsBlindCommitmentResult {
        commitment_with_proof: commitment_with_proof.to_bytes(),
        blind_factor: blind_factor.to_bytes().to_vec(),
    })
}

/// Issuer blind-signs a credential with pseudonym support.
///
/// The issuer generates their own nym entropy and blind-signs over the holder's
/// commitment and the issuer's known messages.
///
/// # Arguments
/// * `secret_key` - 32-byte issuer secret key.
/// * `public_key` - 96-byte issuer public key.
/// * `commitment_with_proof` - From holder's [`bbs_commit_with_nym`].
/// * `header` - Application-specific header bytes.
/// * `signer_nym_entropy` - 32-byte issuer nym entropy from [`bbs_generate_nym_secret`].
/// * `messages` - Issuer-known messages (e.g., attestationType, deviceType, issuedAt, expiresAt).
///
/// Returns the blind signature bytes.
#[uniffi::export]
pub fn bbs_blind_sign_with_nym(
    secret_key: Vec<u8>,
    public_key: Vec<u8>,
    commitment_with_proof: Vec<u8>,
    header: Vec<u8>,
    signer_nym_entropy: Vec<u8>,
    messages: Vec<Vec<u8>>,
) -> Result<Vec<u8>, FfiError> {
    use zkryptium::bbsplus::keys::{BBSplusPublicKey, BBSplusSecretKey};
    use zkryptium::bbsplus::pseudonym::PseudonymSecret;
    use zkryptium::schemes::algorithms::BbsBls12381Sha256;
    use zkryptium::schemes::generics::BlindSignature;

    let sk = BBSplusSecretKey::from_bytes(&secret_key).map_err(|e| FfiError::SigningFailed {
        msg: format!("Invalid secret key: {e:?}"),
    })?;

    let pk = BBSplusPublicKey::from_bytes(&public_key).map_err(|e| FfiError::SigningFailed {
        msg: format!("Invalid public key: {e:?}"),
    })?;

    let nym_entropy_bytes: [u8; 32] =
        signer_nym_entropy
            .try_into()
            .map_err(|_| FfiError::SigningFailed {
                msg: "Signer nym entropy must be 32 bytes".to_string(),
            })?;

    let signer_nym =
        PseudonymSecret::from_bytes(&nym_entropy_bytes).map_err(|e| FfiError::SigningFailed {
            msg: format!("Invalid signer nym entropy: {e:?}"),
        })?;

    let blind_sig = BlindSignature::<BbsBls12381Sha256>::blind_sign_with_nym(
        &sk,
        &pk,
        Some(&commitment_with_proof),
        Some(&header),
        &signer_nym,
        Some(&messages),
    )
    .map_err(|e| FfiError::SigningFailed {
        msg: format!("Blind sign with nym failed: {e:?}"),
    })?;

    Ok(blind_sig.to_bytes().to_vec())
}

/// Holder verifies a blind signature and extracts the combined pseudonym secret.
///
/// After receiving the blind signature from the issuer, the holder verifies it
/// and obtains the combined `nym_secret` used for proof generation.
///
/// # Arguments
/// * `public_key` - 96-byte issuer public key.
/// * `blind_signature` - From issuer's [`bbs_blind_sign_with_nym`].
/// * `header` - Application-specific header (must match signing).
/// * `messages` - Issuer-known messages (same as signing).
/// * `committed_messages` - Holder's committed messages (same as commitment).
/// * `prover_nym_secret` - Holder's original prover nym secret (32 bytes).
/// * `signer_nym_entropy` - Issuer's nym entropy (32 bytes, returned to holder).
/// * `blind_factor` - From [`bbs_commit_with_nym`].
///
/// Returns [`BbsVerifyBlindSignResult`] with the combined nym_secret.
#[allow(clippy::too_many_arguments)]
#[uniffi::export]
pub fn bbs_verify_blind_sign_with_nym(
    public_key: Vec<u8>,
    blind_signature: Vec<u8>,
    header: Vec<u8>,
    messages: Vec<Vec<u8>>,
    committed_messages: Vec<Vec<u8>>,
    prover_nym_secret: Vec<u8>,
    signer_nym_entropy: Vec<u8>,
    blind_factor: Vec<u8>,
) -> Result<BbsVerifyBlindSignResult, FfiError> {
    use zkryptium::bbsplus::commitment::BlindFactor;
    use zkryptium::bbsplus::keys::BBSplusPublicKey;
    use zkryptium::bbsplus::pseudonym::PseudonymSecret;
    use zkryptium::bbsplus::signature::BBSplusSignature;
    use zkryptium::schemes::algorithms::BbsBls12381Sha256;
    use zkryptium::schemes::generics::BlindSignature;

    let pk =
        BBSplusPublicKey::from_bytes(&public_key).map_err(|e| FfiError::VerificationFailed {
            msg: format!("Invalid public key: {e:?}"),
        })?;

    let sig_bytes: [u8; BBSplusSignature::BYTES] =
        blind_signature
            .try_into()
            .map_err(|_| FfiError::VerificationFailed {
                msg: format!("Blind signature must be {} bytes", BBSplusSignature::BYTES),
            })?;

    let blind_sig = BlindSignature::<BbsBls12381Sha256>::from_bytes(&sig_bytes).map_err(|e| {
        FfiError::VerificationFailed {
            msg: format!("Invalid blind signature: {e:?}"),
        }
    })?;

    let prover_nym_bytes: [u8; 32] =
        prover_nym_secret
            .try_into()
            .map_err(|_| FfiError::VerificationFailed {
                msg: "Prover nym secret must be 32 bytes".to_string(),
            })?;
    let prover_nym = PseudonymSecret::from_bytes(&prover_nym_bytes).map_err(|e| {
        FfiError::VerificationFailed {
            msg: format!("Invalid prover nym secret: {e:?}"),
        }
    })?;

    let signer_nym_bytes: [u8; 32] =
        signer_nym_entropy
            .try_into()
            .map_err(|_| FfiError::VerificationFailed {
                msg: "Signer nym entropy must be 32 bytes".to_string(),
            })?;
    let signer_nym = PseudonymSecret::from_bytes(&signer_nym_bytes).map_err(|e| {
        FfiError::VerificationFailed {
            msg: format!("Invalid signer nym entropy: {e:?}"),
        }
    })?;

    let bf_bytes: [u8; 32] = blind_factor
        .try_into()
        .map_err(|_| FfiError::VerificationFailed {
            msg: "Blind factor must be 32 bytes".to_string(),
        })?;
    let bf = BlindFactor::from_bytes(&bf_bytes).map_err(|e| FfiError::VerificationFailed {
        msg: format!("Invalid blind factor: {e:?}"),
    })?;

    let committed_msgs = if committed_messages.is_empty() {
        None
    } else {
        Some(committed_messages.as_slice())
    };

    let msgs = if messages.is_empty() {
        None
    } else {
        Some(messages.as_slice())
    };

    let nym_secret = blind_sig
        .verify_blind_sign_with_nym(
            &pk,
            Some(&header),
            msgs,
            committed_msgs,
            Some(&prover_nym),
            Some(&signer_nym),
            Some(&bf),
        )
        .map_err(|e| FfiError::VerificationFailed {
            msg: format!("Blind signature verification failed: {e:?}"),
        })?;

    Ok(BbsVerifyBlindSignResult {
        nym_secret: nym_secret.to_bytes().to_vec(),
    })
}

/// Generate a BBS+ proof with pseudonym (per-verifier linkability).
///
/// Creates a selective disclosure proof that also proves correct derivation
/// of a scope-bound pseudonym from the holder's nym_secret. The pseudonym
/// enables replay detection without cross-scope correlation.
///
/// # Arguments
/// * `public_key` - 96-byte issuer public key.
/// * `signature` - 80-byte blind signature (from enrollment).
/// * `header` - Application-specific header (must match signing).
/// * `presentation_header` - Presentation-specific binding (e.g., request ID).
/// * `nym_secret` - Combined nym secret from [`bbs_verify_blind_sign_with_nym`].
/// * `scope` - Scope for pseudonym derivation (e.g., request ID bytes).
/// * `messages` - Issuer-known messages (same order as signing).
/// * `committed_messages` - Holder's committed messages (same order as commitment).
/// * `disclosed_indices` - Indices of issuer messages to reveal (ascending).
/// * `disclosed_commitment_indices` - Indices of committed messages to reveal (ascending).
/// * `blind_factor` - Blind factor from [`bbs_commit_with_nym`].
///
/// Returns [`BbsProofWithPseudonym`] with proof bytes and pseudonym.
#[allow(clippy::too_many_arguments)]
#[uniffi::export]
pub fn bbs_proof_gen_with_nym(
    public_key: Vec<u8>,
    signature: Vec<u8>,
    header: Vec<u8>,
    presentation_header: Vec<u8>,
    nym_secret: Vec<u8>,
    scope: Vec<u8>,
    messages: Vec<Vec<u8>>,
    committed_messages: Vec<Vec<u8>>,
    disclosed_indices: Vec<u32>,
    disclosed_commitment_indices: Vec<u32>,
    blind_factor: Vec<u8>,
) -> Result<BbsProofWithPseudonym, FfiError> {
    use zkryptium::bbsplus::commitment::BlindFactor;
    use zkryptium::bbsplus::keys::BBSplusPublicKey;
    use zkryptium::bbsplus::pseudonym::PseudonymSecret;
    use zkryptium::schemes::algorithms::BbsBls12381Sha256;
    use zkryptium::schemes::generics::PoKSignature;

    let pk = BBSplusPublicKey::from_bytes(&public_key).map_err(|e| FfiError::ProofGenFailed {
        msg: format!("Invalid public key: {e:?}"),
    })?;

    let nym_bytes: [u8; 32] = nym_secret
        .try_into()
        .map_err(|_| FfiError::ProofGenFailed {
            msg: "Nym secret must be 32 bytes".to_string(),
        })?;
    let nym = PseudonymSecret::from_bytes(&nym_bytes).map_err(|e| FfiError::ProofGenFailed {
        msg: format!("Invalid nym secret: {e:?}"),
    })?;

    let bf_bytes: [u8; 32] = blind_factor
        .try_into()
        .map_err(|_| FfiError::ProofGenFailed {
            msg: "Blind factor must be 32 bytes".to_string(),
        })?;
    let bf = BlindFactor::from_bytes(&bf_bytes).map_err(|e| FfiError::ProofGenFailed {
        msg: format!("Invalid blind factor: {e:?}"),
    })?;

    let d_idx: Vec<usize> = disclosed_indices.iter().map(|&i| i as usize).collect();
    let dc_idx: Vec<usize> = disclosed_commitment_indices
        .iter()
        .map(|&i| i as usize)
        .collect();

    let msgs = if messages.is_empty() {
        None
    } else {
        Some(messages.as_slice())
    };
    let committed_msgs = if committed_messages.is_empty() {
        None
    } else {
        Some(committed_messages.as_slice())
    };

    let (pok, pseudonym) = PoKSignature::<BbsBls12381Sha256>::proof_gen_with_nym(
        &pk,
        &signature,
        Some(&header),
        Some(&presentation_header),
        &nym,
        &scope,
        msgs,
        committed_msgs,
        Some(&d_idx),
        Some(&dc_idx),
        Some(&bf),
    )
    .map_err(|e| FfiError::ProofGenFailed {
        msg: format!("Proof generation with pseudonym failed: {e:?}"),
    })?;

    Ok(BbsProofWithPseudonym {
        proof: pok.to_bytes(),
        pseudonym: pseudonym.to_bytes(),
    })
}

/// Verify a BBS+ proof with pseudonym (per-verifier linkability).
///
/// Validates a BBS+ selective disclosure proof and verifies correctness of the
/// scope-bound pseudonym. The verifier learns only the disclosed messages and
/// the pseudonym — no device identity or cross-scope correlation.
///
/// # Arguments
/// * `public_key` - 96-byte issuer public key.
/// * `proof` - Serialized proof from [`bbs_proof_gen_with_nym`].
/// * `pseudonym` - Scope-bound pseudonym from proof generation (48 bytes).
/// * `header` - Application-specific header (must match signing).
/// * `presentation_header` - Presentation-specific binding (must match proof gen).
/// * `scope` - Scope for pseudonym verification (must match proof gen).
/// * `total_signer_messages` - Total count of issuer messages signed.
/// * `disclosed_messages` - Disclosed issuer messages (in index order).
/// * `disclosed_committed_messages` - Disclosed committed messages (in index order).
/// * `disclosed_indices` - Indices of disclosed issuer messages (ascending).
/// * `disclosed_commitment_indices` - Indices of disclosed committed messages (ascending).
///
/// Returns `true` if the proof and pseudonym are valid.
#[allow(clippy::too_many_arguments)]
#[uniffi::export]
pub fn bbs_proof_verify_with_nym(
    public_key: Vec<u8>,
    proof: Vec<u8>,
    pseudonym: Vec<u8>,
    header: Vec<u8>,
    presentation_header: Vec<u8>,
    scope: Vec<u8>,
    total_signer_messages: u32,
    disclosed_messages: Vec<Vec<u8>>,
    disclosed_committed_messages: Vec<Vec<u8>>,
    disclosed_indices: Vec<u32>,
    disclosed_commitment_indices: Vec<u32>,
) -> Result<bool, FfiError> {
    use zkryptium::bbsplus::keys::BBSplusPublicKey;
    use zkryptium::bbsplus::pseudonym::BBSplusPseudonym;
    use zkryptium::schemes::algorithms::BbsBls12381Sha256;
    use zkryptium::schemes::generics::PoKSignature;

    let pk =
        BBSplusPublicKey::from_bytes(&public_key).map_err(|e| FfiError::ProofVerifyFailed {
            msg: format!("Invalid public key: {e:?}"),
        })?;

    let pok = PoKSignature::<BbsBls12381Sha256>::from_bytes(&proof).map_err(|e| {
        FfiError::ProofVerifyFailed {
            msg: format!("Invalid proof bytes: {e:?}"),
        }
    })?;

    let nym =
        BBSplusPseudonym::from_bytes(&pseudonym).map_err(|e| FfiError::ProofVerifyFailed {
            msg: format!("Invalid pseudonym: {e:?}"),
        })?;

    let d_idx: Vec<usize> = disclosed_indices.iter().map(|&i| i as usize).collect();
    let dc_idx: Vec<usize> = disclosed_commitment_indices
        .iter()
        .map(|&i| i as usize)
        .collect();

    let disc_msgs = if disclosed_messages.is_empty() {
        None
    } else {
        Some(disclosed_messages.as_slice())
    };
    let disc_committed_msgs = if disclosed_committed_messages.is_empty() {
        None
    } else {
        Some(disclosed_committed_messages.as_slice())
    };

    match pok.proof_verify_with_nym(
        &pk,
        Some(&header),
        Some(&presentation_header),
        &nym,
        &scope,
        Some(total_signer_messages as usize),
        disc_msgs,
        disc_committed_msgs,
        Some(&d_idx),
        Some(&dc_idx),
    ) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

// ─── Credential Parsing ──────────────────────────────────────────────────

/// Parse a BBS+ credential to extract its message attributes.
///
/// The credential is expected to be a serialized format containing a BBS+
/// signature (80 bytes) followed by the raw message byte arrays (each prefixed
/// by a 4-byte big-endian length).
///
/// Returns the extracted messages as a vector of byte arrays.
#[uniffi::export]
pub fn parse_bbs_credential(credential_bytes: Vec<u8>) -> Result<Vec<Vec<u8>>, FfiError> {
    if credential_bytes.is_empty() {
        return Err(FfiError::CredentialParseFailed {
            msg: "Credential bytes are empty".to_string(),
        });
    }

    const SIG_LEN: usize = 80;

    if credential_bytes.len() < SIG_LEN {
        return Err(FfiError::CredentialParseFailed {
            msg: format!(
                "Credential too short for BBS+ signature: need at least {SIG_LEN} bytes, got {}",
                credential_bytes.len()
            ),
        });
    }

    // Verify the signature portion can be parsed (validates format)
    let sig_bytes: [u8; SIG_LEN] =
        credential_bytes[..SIG_LEN]
            .try_into()
            .map_err(|_| FfiError::CredentialParseFailed {
                msg: "Failed to extract signature bytes".to_string(),
            })?;

    use zkryptium::bbsplus::signature::BBSplusSignature;
    let _sig =
        BBSplusSignature::from_bytes(&sig_bytes).map_err(|e| FfiError::CredentialParseFailed {
            msg: format!("Invalid BBS+ signature: {e:?}"),
        })?;

    // Parse length-prefixed messages after the signature
    let mut messages = Vec::new();
    let mut offset = SIG_LEN;

    while offset < credential_bytes.len() {
        if offset + 4 > credential_bytes.len() {
            return Err(FfiError::CredentialParseFailed {
                msg: format!("Truncated message length at offset {offset}"),
            });
        }

        let msg_len =
            u32::from_be_bytes(credential_bytes[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;

        if offset + msg_len > credential_bytes.len() {
            return Err(FfiError::CredentialParseFailed {
                msg: format!(
                    "Truncated message data at offset {offset}, need {msg_len} bytes but only {} remain",
                    credential_bytes.len() - offset
                ),
            });
        }

        messages.push(credential_bytes[offset..offset + msg_len].to_vec());
        offset += msg_len;
    }

    Ok(messages)
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Test BBS+ key generation.
    #[test]
    fn test_bbs_generate_keypair() {
        let kp = bbs_generate_keypair().expect("BBS+ keypair generation should succeed");
        assert_eq!(kp.secret_key.len(), 32, "BBS+ sk should be 32 bytes");
        assert_eq!(kp.public_key.len(), 96, "BBS+ pk should be 96 bytes");
    }

    /// Test BBS+ sign and verify round-trip.
    #[test]
    fn test_bbs_sign_verify_roundtrip() {
        let kp = bbs_generate_keypair().expect("keypair generation should succeed");

        let header = b"test-header".to_vec();
        let messages = vec![
            b"message1".to_vec(),
            b"message2".to_vec(),
            b"message3".to_vec(),
        ];

        let sig = bbs_sign(
            kp.secret_key.clone(),
            kp.public_key.clone(),
            header.clone(),
            messages.clone(),
        )
        .expect("BBS+ signing should succeed");

        assert_eq!(sig.len(), 80, "BBS+ signature should be 80 bytes");

        let valid = bbs_verify(
            kp.public_key.clone(),
            header.clone(),
            sig.clone(),
            messages.clone(),
        )
        .expect("BBS+ verification should succeed");
        assert!(valid, "signature should be valid");

        // Verify with wrong message should fail
        let wrong_messages = vec![
            b"wrong1".to_vec(),
            b"message2".to_vec(),
            b"message3".to_vec(),
        ];
        let invalid = bbs_verify(kp.public_key, header, sig, wrong_messages)
            .expect("verification call should succeed");
        assert!(!invalid, "signature should be invalid with wrong messages");
    }

    /// Test BBS+ verify rejects wrong signature length.
    #[test]
    fn test_bbs_verify_invalid_sig_length() {
        let kp = bbs_generate_keypair().unwrap();
        let result = bbs_verify(kp.public_key, vec![], vec![0u8; 79], vec![]);
        assert!(result.is_err(), "should reject 79-byte signature");
    }

    /// Test selective disclosure proof gen/verify round-trip.
    #[test]
    fn test_bbs_proof_gen_verify_roundtrip() {
        let kp = bbs_generate_keypair().unwrap();
        let header = b"ackagent-anonymous-attestation-v2".to_vec();
        let messages = vec![
            b"attestationType".to_vec(),
            b"deviceType".to_vec(),
            b"issuedAt".to_vec(),
            b"expiresAt".to_vec(),
        ];

        let sig = bbs_sign(
            kp.secret_key,
            kp.public_key.clone(),
            header.clone(),
            messages.clone(),
        )
        .unwrap();

        let presentation_header = b"request-12345".to_vec();
        let disclosed_indices = vec![0, 1, 3]; // reveal attestationType, deviceType, expiresAt

        let proof = bbs_proof_gen(
            kp.public_key.clone(),
            sig,
            header.clone(),
            presentation_header.clone(),
            messages.clone(),
            disclosed_indices.clone(),
        )
        .expect("proof generation should succeed");

        assert!(!proof.is_empty(), "proof should not be empty");

        // Verify with disclosed messages only
        let disclosed_messages = vec![
            messages[0].clone(),
            messages[1].clone(),
            messages[3].clone(),
        ];

        let valid = bbs_proof_verify(
            kp.public_key.clone(),
            proof.clone(),
            header.clone(),
            presentation_header.clone(),
            disclosed_messages.clone(),
            disclosed_indices.clone(),
        )
        .expect("proof verification should succeed");
        assert!(valid, "proof should be valid");

        // Verify with wrong messages should fail
        let wrong_disclosed = vec![b"wrong".to_vec(), messages[1].clone(), messages[3].clone()];
        let invalid = bbs_proof_verify(
            kp.public_key,
            proof,
            header,
            presentation_header,
            wrong_disclosed,
            disclosed_indices,
        )
        .expect("verification call should succeed");
        assert!(!invalid, "proof should be invalid with wrong messages");
    }

    /// Test the full blind signing with pseudonym flow (enrollment + proof).
    #[test]
    fn test_blind_sign_with_nym_full_flow() {
        // === Issuer setup ===
        let issuer_kp = bbs_generate_keypair().unwrap();
        let header = b"ackagent-anonymous-attestation-v2".to_vec();

        // === Step 1: Holder generates nym secret and commitment ===
        let prover_nym_secret = bbs_generate_nym_secret().unwrap();
        assert_eq!(prover_nym_secret.len(), 32, "nym secret should be 32 bytes");

        let commit_result = bbs_commit_with_nym(vec![], prover_nym_secret.clone()).unwrap();
        assert!(
            !commit_result.commitment_with_proof.is_empty(),
            "commitment should not be empty"
        );
        assert!(
            !commit_result.blind_factor.is_empty(),
            "blind factor should not be empty"
        );

        // === Step 2: Issuer blind-signs ===
        let signer_nym_entropy = bbs_generate_nym_secret().unwrap();
        let signer_messages = vec![
            b"ios_secure_enclave".to_vec(),
            b"ios".to_vec(),
            b"1708646400".to_vec(), // issuedAt
            b"1711324800".to_vec(), // expiresAt
        ];

        let blind_sig = bbs_blind_sign_with_nym(
            issuer_kp.secret_key,
            issuer_kp.public_key.clone(),
            commit_result.commitment_with_proof,
            header.clone(),
            signer_nym_entropy.clone(),
            signer_messages.clone(),
        )
        .expect("blind sign should succeed");

        assert_eq!(blind_sig.len(), 80, "blind signature should be 80 bytes");

        // === Step 3: Holder verifies and extracts combined nym secret ===
        let verify_result = bbs_verify_blind_sign_with_nym(
            issuer_kp.public_key.clone(),
            blind_sig.clone(),
            header.clone(),
            signer_messages.clone(),
            vec![], // no committed messages
            prover_nym_secret,
            signer_nym_entropy,
            commit_result.blind_factor.clone(),
        )
        .expect("blind signature verification should succeed");

        assert_eq!(
            verify_result.nym_secret.len(),
            32,
            "combined nym secret should be 32 bytes"
        );

        // === Step 4: Holder generates proof with pseudonym ===
        let scope = b"request-id-12345".to_vec();
        let presentation_header = b"request-id-12345".to_vec();
        let disclosed_indices = vec![0, 1, 3]; // attestationType, deviceType, expiresAt
        let disclosed_commitment_indices: Vec<u32> = vec![];

        let proof_result = bbs_proof_gen_with_nym(
            issuer_kp.public_key.clone(),
            blind_sig,
            header.clone(),
            presentation_header.clone(),
            verify_result.nym_secret,
            scope.clone(),
            signer_messages.clone(),
            vec![], // no committed messages
            disclosed_indices.clone(),
            disclosed_commitment_indices.clone(),
            commit_result.blind_factor,
        )
        .expect("proof generation with pseudonym should succeed");

        assert!(!proof_result.proof.is_empty(), "proof should not be empty");
        assert_eq!(
            proof_result.pseudonym.len(),
            48,
            "pseudonym should be 48 bytes (compressed G1)"
        );

        // === Step 5: Verifier verifies proof with pseudonym ===
        let disclosed_messages = vec![
            signer_messages[0].clone(), // attestationType
            signer_messages[1].clone(), // deviceType
            signer_messages[3].clone(), // expiresAt
        ];

        let valid = bbs_proof_verify_with_nym(
            issuer_kp.public_key.clone(),
            proof_result.proof,
            proof_result.pseudonym,
            header,
            presentation_header,
            scope,
            signer_messages.len() as u32,
            disclosed_messages,
            vec![], // no disclosed committed messages
            disclosed_indices,
            disclosed_commitment_indices,
        )
        .expect("proof verification with pseudonym should succeed");
        assert!(valid, "proof with pseudonym should be valid");
    }

    /// Test pseudonym determinism: same nym_secret + same scope = same pseudonym.
    #[test]
    fn test_pseudonym_determinism() {
        let issuer_kp = bbs_generate_keypair().unwrap();
        let header = b"ackagent-anonymous-attestation-v2".to_vec();

        let prover_nym = bbs_generate_nym_secret().unwrap();
        let commit = bbs_commit_with_nym(vec![], prover_nym.clone()).unwrap();

        let signer_nym = bbs_generate_nym_secret().unwrap();
        let messages = vec![b"type1".to_vec(), b"ios".to_vec()];

        let blind_sig = bbs_blind_sign_with_nym(
            issuer_kp.secret_key,
            issuer_kp.public_key.clone(),
            commit.commitment_with_proof,
            header.clone(),
            signer_nym.clone(),
            messages.clone(),
        )
        .unwrap();

        let verify_result = bbs_verify_blind_sign_with_nym(
            issuer_kp.public_key.clone(),
            blind_sig.clone(),
            header.clone(),
            messages.clone(),
            vec![],
            prover_nym,
            signer_nym,
            commit.blind_factor.clone(),
        )
        .unwrap();

        let scope = b"same-scope".to_vec();
        let ph = b"ph1".to_vec();

        let proof1 = bbs_proof_gen_with_nym(
            issuer_kp.public_key.clone(),
            blind_sig.clone(),
            header.clone(),
            ph.clone(),
            verify_result.nym_secret.clone(),
            scope.clone(),
            messages.clone(),
            vec![],
            vec![0, 1],
            vec![],
            commit.blind_factor.clone(),
        )
        .unwrap();

        let proof2 = bbs_proof_gen_with_nym(
            issuer_kp.public_key,
            blind_sig,
            header,
            ph,
            verify_result.nym_secret,
            scope,
            messages,
            vec![],
            vec![0, 1],
            vec![],
            commit.blind_factor,
        )
        .unwrap();

        // Pseudonyms should be identical (deterministic derivation from same secret + scope)
        assert_eq!(
            proof1.pseudonym, proof2.pseudonym,
            "same nym_secret + same scope should produce identical pseudonyms"
        );
    }

    /// Test cross-scope unlinkability: different scopes produce different pseudonyms.
    #[test]
    fn test_cross_scope_unlinkability() {
        let issuer_kp = bbs_generate_keypair().unwrap();
        let header = b"ackagent-anonymous-attestation-v2".to_vec();

        let prover_nym = bbs_generate_nym_secret().unwrap();
        let commit = bbs_commit_with_nym(vec![], prover_nym.clone()).unwrap();

        let signer_nym = bbs_generate_nym_secret().unwrap();
        let messages = vec![b"type1".to_vec(), b"ios".to_vec()];

        let blind_sig = bbs_blind_sign_with_nym(
            issuer_kp.secret_key,
            issuer_kp.public_key.clone(),
            commit.commitment_with_proof,
            header.clone(),
            signer_nym.clone(),
            messages.clone(),
        )
        .unwrap();

        let verify_result = bbs_verify_blind_sign_with_nym(
            issuer_kp.public_key.clone(),
            blind_sig.clone(),
            header.clone(),
            messages.clone(),
            vec![],
            prover_nym,
            signer_nym,
            commit.blind_factor.clone(),
        )
        .unwrap();

        let proof1 = bbs_proof_gen_with_nym(
            issuer_kp.public_key.clone(),
            blind_sig.clone(),
            header.clone(),
            b"ph1".to_vec(),
            verify_result.nym_secret.clone(),
            b"scope-a".to_vec(),
            messages.clone(),
            vec![],
            vec![0, 1],
            vec![],
            commit.blind_factor.clone(),
        )
        .unwrap();

        let proof2 = bbs_proof_gen_with_nym(
            issuer_kp.public_key,
            blind_sig,
            header,
            b"ph2".to_vec(),
            verify_result.nym_secret,
            b"scope-b".to_vec(),
            messages,
            vec![],
            vec![0, 1],
            vec![],
            commit.blind_factor,
        )
        .unwrap();

        // Pseudonyms must differ for different scopes
        assert_ne!(
            proof1.pseudonym, proof2.pseudonym,
            "different scopes should produce different pseudonyms (unlinkability)"
        );
    }

    /// Test credential parsing with a valid BBS+ signed credential.
    #[test]
    fn test_parse_bbs_credential_roundtrip() {
        let kp = bbs_generate_keypair().unwrap();
        let header = b"credential-header".to_vec();
        let messages = vec![
            b"attestationType".to_vec(),
            b"deviceType".to_vec(),
            b"issuedAt".to_vec(),
            b"expiresAt".to_vec(),
        ];

        let sig = bbs_sign(kp.secret_key, kp.public_key, header, messages.clone()).unwrap();

        // Build credential: signature || length-prefixed messages
        let mut credential = sig;
        for msg in &messages {
            credential.extend_from_slice(&(msg.len() as u32).to_be_bytes());
            credential.extend_from_slice(msg);
        }

        let parsed = parse_bbs_credential(credential).expect("parsing should succeed");
        assert_eq!(parsed.len(), 4, "should parse 4 messages");
        assert_eq!(parsed, messages, "parsed messages should match originals");
    }

    /// Test credential parsing rejects empty input.
    #[test]
    fn test_parse_bbs_credential_empty() {
        let result = parse_bbs_credential(vec![]);
        assert!(result.is_err(), "should reject empty credential");
    }

    /// Test credential parsing rejects truncated input.
    #[test]
    fn test_parse_bbs_credential_truncated() {
        let result = parse_bbs_credential(vec![0u8; 50]);
        assert!(
            result.is_err(),
            "should reject truncated credential (< 80 bytes)"
        );
    }

    /// Test that nym secret generation produces unique values.
    #[test]
    fn test_nym_secret_uniqueness() {
        let s1 = bbs_generate_nym_secret().unwrap();
        let s2 = bbs_generate_nym_secret().unwrap();
        assert_ne!(s1, s2, "sequential nym secrets should differ");
        assert_eq!(s1.len(), 32, "nym secret should be 32 bytes");
    }
}

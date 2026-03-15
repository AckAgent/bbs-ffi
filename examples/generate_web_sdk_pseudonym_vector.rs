use bbs_ffi::{
    bbs_blind_sign_with_nym, bbs_commit_with_nym, bbs_generate_keypair, bbs_generate_nym_secret,
    bbs_proof_gen_with_nym, bbs_verify_blind_sign_with_nym,
};

fn encode_i64_be(value: i64) -> Vec<u8> {
    value.to_be_bytes().to_vec()
}

fn to_hex(data: &[u8]) -> String {
    hex::encode(data)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let header = b"ackagent-anonymous-attestation-v2".to_vec();
    let presentation_header = b"web-sdk-vector-presentation-header".to_vec();
    let scope = b"web-sdk-vector-request-id".to_vec();

    let attestation_type = b"ios_secure_enclave".to_vec();
    let device_type = b"ios".to_vec();
    let issued_at = encode_i64_be(2_100_000_000);
    let expires_at = encode_i64_be(2_200_000_000);

    let signer_messages = vec![
        attestation_type.clone(),
        device_type.clone(),
        issued_at,
        expires_at.clone(),
    ];

    let keypair = bbs_generate_keypair()?;

    let prover_nym_secret = bbs_generate_nym_secret()?;
    let commitment = bbs_commit_with_nym(vec![], prover_nym_secret.clone())?;

    let signer_nym_entropy = [0x42u8; 32].to_vec();
    let blind_signature = bbs_blind_sign_with_nym(
        keypair.secret_key.clone(),
        keypair.public_key.clone(),
        commitment.commitment_with_proof.clone(),
        header.clone(),
        signer_nym_entropy.clone(),
        signer_messages.clone(),
    )?;

    let verify_result = bbs_verify_blind_sign_with_nym(
        keypair.public_key.clone(),
        blind_signature.clone(),
        header.clone(),
        signer_messages.clone(),
        vec![],
        prover_nym_secret,
        signer_nym_entropy,
        commitment.blind_factor.clone(),
    )?;

    let proof_with_pseudonym = bbs_proof_gen_with_nym(
        keypair.public_key.clone(),
        blind_signature,
        header.clone(),
        presentation_header.clone(),
        verify_result.nym_secret.clone(),
        scope.clone(),
        signer_messages,
        vec![],
        vec![0, 1, 3],
        vec![],
        commitment.blind_factor,
    )?;

    println!(
        "{{\n  \"issuerPublicKeyHex\": \"{}\",\n  \"proofHex\": \"{}\",\n  \"pseudonymHex\": \"{}\",\n  \"headerHex\": \"{}\",\n  \"presentationHeaderHex\": \"{}\",\n  \"scopeHex\": \"{}\",\n  \"totalSignerMessages\": 4,\n  \"disclosedMessages\": [\n    {{\"index\": 0, \"valueHex\": \"{}\"}},\n    {{\"index\": 1, \"valueHex\": \"{}\"}},\n    {{\"index\": 3, \"valueHex\": \"{}\"}}\n  ],\n  \"disclosedCommittedMessages\": [],\n  \"disclosedCommitmentIndices\": []\n}}",
        to_hex(&keypair.public_key),
        to_hex(&proof_with_pseudonym.proof),
        to_hex(&proof_with_pseudonym.pseudonym),
        to_hex(&header),
        to_hex(&presentation_header),
        to_hex(&scope),
        to_hex(&attestation_type),
        to_hex(&device_type),
        to_hex(&expires_at),
    );

    Ok(())
}

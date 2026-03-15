use bbs_ffi::{
    bbs_blind_sign_with_nym, bbs_commit_with_nym, bbs_generate_keypair, bbs_generate_nym_secret,
    bbs_proof_gen_with_nym, bbs_proof_verify_with_nym, bbs_verify_blind_sign_with_nym,
};
use std::time::Instant;

#[derive(Clone)]
struct BenchResult {
    proof_size_bytes: usize,
    proof_gen_avg_us: u128,
    proof_gen_p95_us: u128,
    proof_verify_avg_us: u128,
    proof_verify_p95_us: u128,
}

fn encode_i64_be(value: i64) -> Vec<u8> {
    value.to_be_bytes().to_vec()
}

fn avg(samples: &[u128]) -> u128 {
    if samples.is_empty() {
        return 0;
    }
    samples.iter().sum::<u128>() / samples.len() as u128
}

fn p95(samples: &[u128]) -> u128 {
    if samples.is_empty() {
        return 0;
    }
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let idx = ((sorted.len() as f64) * 0.95).ceil() as usize - 1;
    sorted[idx.min(sorted.len() - 1)]
}

fn run_case(
    expires_at_value: i64,
    iterations: usize,
) -> Result<BenchResult, Box<dyn std::error::Error>> {
    let header = b"ackagent-anonymous-attestation-v2".to_vec();
    let scope = b"predicate-prototype-request".to_vec();

    let attestation_type = b"ios_secure_enclave".to_vec();
    let device_type = b"ios".to_vec();
    let issued_at = encode_i64_be(2_100_000_000);
    let expires_at = encode_i64_be(expires_at_value);

    let signer_messages = vec![
        attestation_type.clone(),
        device_type.clone(),
        issued_at,
        expires_at.clone(),
    ];

    let keypair = bbs_generate_keypair()?;
    let prover_nym_secret = bbs_generate_nym_secret()?;
    let commitment = bbs_commit_with_nym(vec![], prover_nym_secret.clone())?;
    let signer_nym_entropy = [0x22u8; 32].to_vec();

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

    let disclosed_messages = vec![attestation_type, device_type, expires_at];

    let mut proof_gen_samples = Vec::with_capacity(iterations);
    let mut proof_verify_samples = Vec::with_capacity(iterations);
    let mut proof_size = 0usize;

    for i in 0..iterations {
        let presentation_header = format!("predicate-prototype-presentation-{i}").into_bytes();

        let start_gen = Instant::now();
        let proof_with_pseudonym = bbs_proof_gen_with_nym(
            keypair.public_key.clone(),
            blind_signature.clone(),
            header.clone(),
            presentation_header.clone(),
            verify_result.nym_secret.clone(),
            scope.clone(),
            signer_messages.clone(),
            vec![],
            vec![0, 1, 3],
            vec![],
            commitment.blind_factor.clone(),
        )?;
        proof_gen_samples.push(start_gen.elapsed().as_micros());
        proof_size = proof_with_pseudonym.proof.len();

        let start_verify = Instant::now();
        let verified = bbs_proof_verify_with_nym(
            keypair.public_key.clone(),
            proof_with_pseudonym.proof,
            proof_with_pseudonym.pseudonym,
            header.clone(),
            presentation_header,
            scope.clone(),
            4,
            disclosed_messages.clone(),
            vec![],
            vec![0, 1, 3],
            vec![],
        )?;
        proof_verify_samples.push(start_verify.elapsed().as_micros());

        if !verified {
            return Err("proof verification failed in benchmark loop".into());
        }
    }

    Ok(BenchResult {
        proof_size_bytes: proof_size,
        proof_gen_avg_us: avg(&proof_gen_samples),
        proof_gen_p95_us: p95(&proof_gen_samples),
        proof_verify_avg_us: avg(&proof_verify_samples),
        proof_verify_p95_us: p95(&proof_verify_samples),
    })
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let iterations = std::env::var("ACKAGENT_BBS_PREDICATE_BENCH_ITERS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(150);

    // Baseline: reveal exact expiresAt (current production behavior).
    let exact = run_case(2_200_000_000, iterations)?;

    // Prototype fallback: reveal coarse daily bucket index instead of exact timestamp.
    let bucket_index = 2_200_000_000 / 86_400;
    let bucketed = run_case(bucket_index, iterations)?;

    println!("{{");
    println!("  \"iterations\": {iterations},");
    println!("  \"baselineExact\": {{");
    println!("    \"proofSizeBytes\": {},", exact.proof_size_bytes);
    println!("    \"proofGenAvgUs\": {},", exact.proof_gen_avg_us);
    println!("    \"proofGenP95Us\": {},", exact.proof_gen_p95_us);
    println!("    \"proofVerifyAvgUs\": {},", exact.proof_verify_avg_us);
    println!("    \"proofVerifyP95Us\": {}", exact.proof_verify_p95_us);
    println!("  }},");
    println!("  \"prototypeBucketed\": {{");
    println!("    \"proofSizeBytes\": {},", bucketed.proof_size_bytes);
    println!("    \"proofGenAvgUs\": {},", bucketed.proof_gen_avg_us);
    println!("    \"proofGenP95Us\": {},", bucketed.proof_gen_p95_us);
    println!(
        "    \"proofVerifyAvgUs\": {},",
        bucketed.proof_verify_avg_us
    );
    println!("    \"proofVerifyP95Us\": {}", bucketed.proof_verify_p95_us);
    println!("  }},");
    println!(
        "  \"deltaVsBaseline\": {{\"proofSizeBytes\": {}, \"proofGenAvgUs\": {}, \"proofVerifyAvgUs\": {}}}",
        bucketed.proof_size_bytes as i64 - exact.proof_size_bytes as i64,
        bucketed.proof_gen_avg_us as i64 - exact.proof_gen_avg_us as i64,
        bucketed.proof_verify_avg_us as i64 - exact.proof_verify_avg_us as i64,
    );
    println!("}}");

    Ok(())
}

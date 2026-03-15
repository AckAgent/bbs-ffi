/// Prints a fresh BBS issuer keypair as hex strings suitable for keystore tooling:
///   - ISSUER_PRIVATE_KEY_HEX (64 chars)
///   - ISSUER_PUBLIC_KEY_HEX  (192 chars)
///
/// Usage:
///   cargo run --release --example generate_issuer_keypair
fn main() {
    let keypair = bbs_ffi::bbs_generate_keypair().expect("failed to generate BBS issuer keypair");

    println!("ISSUER_PRIVATE_KEY_HEX={}", to_hex(&keypair.secret_key));
    println!("ISSUER_PUBLIC_KEY_HEX={}", to_hex(&keypair.public_key));
}

fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

use anyhow::{anyhow, Result};
use p256::ecdh::EphemeralSecret;
use p256::PublicKey;
use rand_core::{CryptoRng, RngCore};
use sha2::Sha256;
use std::io::{Read, Write};
use std::net::IpAddr;
use std::str::FromStr;

// Conduct the ECDH key exchange
pub fn play_dh_kex<T: RngCore + CryptoRng, A: Write>(
    writeable: &mut A,
    pub_b: PublicKey,
    rng: &mut T,
) -> Result<[u8; 32]> {
    // Generate local keys
    let secret_a = EphemeralSecret::random(rng);
    let pub_a = secret_a.public_key().to_string();
    writeable.write(pub_a.as_bytes())?;

    // Calculate the shared secret
    let secret_hkdf = secret_a.diffie_hellman(&pub_b).extract::<Sha256>(None);
    let mut key = [0u8; 32];
    secret_hkdf
        .expand(&vec![0u8; 0], &mut key)
        .or(Err(anyhow!("Unable to expand shared secret")))?;
    Ok(key)
}

#[allow(unused_variables)]
pub fn play_auth_challenge<T: RngCore + CryptoRng, A: Write + Read>(
    sock: &mut A,
    key: &[u8; 32],
    rng: &mut T,
) -> Result<()> {
    unimplemented!()
}

// Get remote info from argv
pub fn get_remote_info() -> Result<(IpAddr, PublicKey)> {
    // Parse the IP
    let argv1 = std::env::args()
        .nth(1)
        .ok_or(anyhow!("argv[1] must exist"))?;
    let ip = argv1.parse()?;
    // Parse the public key which should just be the base64 component on a single line
    let argv2 = std::env::args()
        .nth(2)
        .ok_or(anyhow!("argv[2] must exist"))?;
    let pubkey = PublicKey::from_str(&format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----",
        argv2
    ))?;
    Ok((ip, pubkey))
}

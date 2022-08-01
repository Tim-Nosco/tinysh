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

// Get remote's public key appended the end of this ELF
pub fn get_remote_info() -> Result<(IpAddr, PublicKey)> {
    // TODO: actually read from the tail of this file
    let test_str = "-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEdojljdsw2oUJ/CoGn6p9Bs30yKPd
pKK0Lb4fC+7c+9lnukYL5WOTsFzfUIZkGdrM5WyoEmDNISrh/mwzAB8m7w==
-----END PUBLIC KEY-----";
    Ok(("127.0.0.1".parse()?, PublicKey::from_str(test_str)?))
}

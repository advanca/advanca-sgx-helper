#[cfg(feature = "std_env")]
use sgx_ucrypto::sgx_read_rand;
#[cfg(feature = "sgx_enclave")]
use sgx_types::sgx_read_rand;

use advanca_types::*;

use sgx_types::*;


#[cfg(feature = "sgx_enclave")]
use std::vec::Vec;

// use rand::rngs::StdRng;
// use rand::SeedableRng;

use tiny_keccak::{Keccak, Hasher};

use rust_secp256k1::{Secp256k1, SecretKey, PublicKey, Message};
use rust_secp256k1::ffi::types::AlignedType;

use advanca_macros::handle_sgx;

pub fn secp256k1_gen_keypair() -> Result<(Secp256k1PrivateKey, Secp256k1PublicKey), CryptoError> {
    let mut seed_bytes = [0_u8; 32];
    unsafe {
        handle_sgx!(sgx_read_rand(seed_bytes.as_mut_ptr(), seed_bytes.len()))?;
    }

    let secp_size = Secp256k1::preallocate_size();
    let mut buf = vec![AlignedType::zeroed(); secp_size];
    let mut secp = Secp256k1::preallocated_new(&mut buf).unwrap();
    secp.seeded_randomize(&seed_bytes);

    let prvkey = loop {
        unsafe {
            handle_sgx!(sgx_read_rand(seed_bytes.as_mut_ptr(), seed_bytes.len()))?;
        }
        if let Ok(secret_key) = SecretKey::from_slice(&seed_bytes) {
            break secret_key;
        }
    };
    let pubkey = PublicKey::from_secret_key(&secp, &prvkey);

    Ok((prvkey.into(), pubkey.into()))
}

pub fn secp256k1_sign_msg(
    prvkey: &Secp256k1PrivateKey,
    msg: &[u8],
) -> Result<Secp256k1SignedMsg, CryptoError> {
    let mut seed_bytes = [0_u8; 32];
    unsafe {
        handle_sgx!(sgx_read_rand(seed_bytes.as_mut_ptr(), seed_bytes.len()))?;
    }
    let secp_size = Secp256k1::preallocate_size();
    let mut buf = vec![AlignedType::zeroed(); secp_size];
    let mut secp = Secp256k1::preallocated_new(&mut buf).unwrap();
    secp.seeded_randomize(&seed_bytes);

    // hash the message with keccak-256
    let mut keccak = Keccak::v256();
    let mut msg_hash = [0_u8; 32];
    keccak.update(msg);
    keccak.finalize(&mut msg_hash);

    let message = Message::from_slice(&msg_hash).expect("32 bytes");
    let signature = secp.sign(&message, &(prvkey.clone().into()));

    Ok(Secp256k1SignedMsg {
        msg: msg.to_vec(),
        signature: signature.into(),
    })
}


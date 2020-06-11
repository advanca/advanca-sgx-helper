use advanca_crypto_types::*;
use sgx_types::*;

use ring::{rand, agreement};
use ring::signature::{EcdsaKeyPair};
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING};
use ring::agreement::{EphemeralPrivateKey, PublicKey};

use cmac::{Cmac, Mac};
use aes::Aes128;
// use generic_array::GenericArray;
// use typenum::U16;

pub fn from_advanca_keypair(prvkey: &Secp256r1PrivateKey, pubkey: &Secp256r1PublicKey) -> EcdsaKeyPair {
    let mut prvkey_bytes_be = prvkey.to_raw_bytes();
    prvkey_bytes_be.reverse();
    let mut pubkey_bytes_be = pubkey.to_raw_bytes();
    pubkey_bytes_be[..32].reverse();
    pubkey_bytes_be[32..].reverse();

    let keypair = EcdsaKeyPair::from_private_key_and_public_key(&ECDSA_P256_SHA256_FIXED_SIGNING, &prvkey_bytes_be, &pubkey.to_ring_bytes()).unwrap();
    keypair
}

pub fn gen_ephemeral_key() -> (EphemeralPrivateKey, PublicKey) {
    let rng = rand::SystemRandom::new();
    let prvkey = EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rng).unwrap();
    let pubkey = prvkey.compute_public_key().unwrap();
    (prvkey, pubkey)
}

pub fn derive_kdk(prvkey: EphemeralPrivateKey, pubkey: &agreement::UnparsedPublicKey<Vec<u8>>) -> Aes128Key {
    let kdk = agreement::agree_ephemeral(prvkey, pubkey, ring::error::Unspecified, 
        |gab_x| {
            // agree_ephemeral outputs gab_x in big-endian format
            // sgx dev ref 2.9.1 states in page 374 that aes-cmac(key0, le(gab_x))
            let mut gab_x_le = [0_u8;32];
            gab_x_le.copy_from_slice(gab_x);
            gab_x_le.reverse();
            let mut mac = Cmac::<Aes128>::new_varkey(&[0_u8;16]).unwrap();
            mac.input(&gab_x_le);
            let result = mac.result();
            Ok(result.code())
        }
    ).unwrap();
    let mut kdk_bytes = [0_u8;16];
    kdk_bytes.copy_from_slice(kdk.as_slice());
    Aes128Key {
        key: kdk_bytes,
    }
}

/// Derive SMK, SK, MK, and VK according to 
/// https://software.intel.com/en-us/articles/code-sample-intel-software-guard-extensions-remote-attestation-end-to-end-example
pub fn derive_secret_keys(kdk: &Aes128Key) -> (Aes128Key, Aes128Key, Aes128Key, Aes128Key) {
    let mut mac = Cmac::<Aes128>::new_varkey(&kdk.key).unwrap();
    let smk_data = [0x01, 'S' as u8, 'M' as u8, 'K' as u8, 0x00, 0x80, 0x00];
    mac.input(&smk_data);
    let mut smk = Aes128Key::from_slice(mac.result_reset().code().as_slice());

    let sk_data = [0x01, 'S' as u8, 'K' as u8, 0x00, 0x80, 0x00];
    mac.input(&sk_data);
    let mut sk = Aes128Key::from_slice(mac.result_reset().code().as_slice());

    let mk_data = [0x01, 'M' as u8, 'K' as u8, 0x00, 0x80, 0x00];
    mac.input(&mk_data);
    let mut mk = Aes128Key::from_slice(mac.result_reset().code().as_slice());

    let vk_data = [0x01, 'V' as u8, 'K' as u8, 0x00, 0x80, 0x00];
    mac.input(&vk_data);
    let mut vk = Aes128Key::from_slice(mac.result_reset().code().as_slice());

    println!("smk: {:02x?}", smk);
    println!("sk : {:02x?}", sk);
    println!("mk : {:02x?}", mk);
    println!("vk : {:02x?}", vk);
    (smk, sk, mk, vk)
}

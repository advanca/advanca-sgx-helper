#![cfg_attr(any(feature = "sgx_enclave"), no_std)]

#[cfg(feature = "sgx_enclave")]
#[macro_use]
extern crate sgx_tstd as std;

#[cfg(feature = "untrusted")]
extern crate sgx_ucrypto;

mod advanca_cryptolib;
pub use advanca_cryptolib::*;


//#[cfg(feature = "sgx_enclave")]
pub mod sgx_enclave {
    pub mod sgx_enclave_utils {
        use sgx_types::*;
        use sgx_types::sgx_ra_key_type_t::*;


        // TODO: Change functions to return Result instead of using a mutable output parameter
        pub fn aes128_cmac(key: &sgx_cmac_128bit_key_t, p_data: &[u8], p_mac: &mut sgx_cmac_128bit_tag_t) -> sgx_status_t {
            // derive the kdk from the shared dhkey
            // KDK = AES-CMAC(key0, gab x-coordinate)
            let src_len = p_data.len() as u32;
            unsafe {sgx_rijndael128_cmac_msg(key, p_data.as_ptr(), src_len, p_mac)}
        }

        // TODO: Change functions to return Result instead of using a mutable output parameter
        pub fn aes128_cmac_sk(context: sgx_ra_context_t, p_data: &[u8], p_mac: &mut sgx_cmac_128bit_tag_t) -> sgx_status_t {
            let mut key = sgx_cmac_128bit_key_t::default();
            let ret = unsafe {sgx_ra_get_keys(context, SGX_RA_KEY_SK, &mut key)};
            if ret == sgx_status_t::SGX_SUCCESS {
                aes128_cmac(&key, p_data, p_mac);
            };
            ret
        }

        // TODO: Change functions to return Result instead of using a mutable output parameter
        pub fn derive_ec256_shared_dhkey (pubkey: &sgx_ec256_public_t, prvkey: &sgx_ec256_private_t, shared_dhkey: &mut sgx_ec256_dh_shared_t) -> sgx_status_t {
            let mut g_a_pub = *pubkey;
            let mut g_b_prv = *prvkey;
            let mut gab_x = sgx_ec256_dh_shared_t::default();

            let mut p_ecc_handle:sgx_ecc_state_handle_t = 0 as sgx_ecc_state_handle_t;

            let mut ret;
            ret = unsafe {sgx_ecc256_open_context(&mut p_ecc_handle)};
            if ret == sgx_status_t::SGX_SUCCESS {
                ret = unsafe {sgx_ecc256_compute_shared_dhkey(&mut g_b_prv, &mut g_a_pub, &mut gab_x, p_ecc_handle)};
            }
            if ret == sgx_status_t::SGX_SUCCESS {
                let _ = unsafe {sgx_ecc256_close_context(p_ecc_handle)};
            }
            *shared_dhkey = gab_x;
            ret

        }


        pub fn aes128_gcm_decrypt(p_key: &sgx_aes_gcm_128bit_key_t, p_ivcipher: &[u8], p_aad: &[u8], p_data: &mut [u8]) -> sgx_status_t {
            assert_eq!(p_ivcipher.len(), 12+16+p_data.len());

            let p_iv = unsafe{core::slice::from_raw_parts(p_ivcipher.as_ptr(), 12)};
            let p_mac = unsafe{p_ivcipher.as_ptr().offset(12) as *const u8 as *const sgx_aes_gcm_128bit_tag_t};
            let p_cipher = unsafe{core::slice::from_raw_parts(p_ivcipher.as_ptr().offset(12+16), p_data.len())};

            let ret = unsafe{sgx_rijndael128GCM_decrypt(
                p_key, p_cipher.as_ptr(), p_cipher.len() as u32, p_data.as_mut_ptr(),
                p_iv.as_ptr(), p_iv.len() as u32, p_aad.as_ptr(), p_aad.len() as u32, p_mac,
            )};
            ret
        }

        pub fn aes128_gcm_encrypt(p_key: &sgx_aes_gcm_128bit_key_t, p_data: &[u8], p_aad: &[u8], p_out: &mut [u8]) -> sgx_status_t {
            assert_eq!(p_data.len()+12+16, p_out.len());

            let p_iv = unsafe{core::slice::from_raw_parts_mut(p_out.as_mut_ptr(), 12)};
            let p_mac = unsafe{core::slice::from_raw_parts_mut(p_out.as_mut_ptr().offset(12), 16)};
            let p_cipher = unsafe{core::slice::from_raw_parts_mut(p_out.as_mut_ptr().offset(12+16), p_data.len())};

            let ret = unsafe{sgx_read_rand(p_iv.as_mut_ptr(), p_iv.len())};
            if ret != sgx_status_t::SGX_SUCCESS { return ret; }

            let mut mac = sgx_aes_gcm_128bit_tag_t::default();

            let ret = unsafe{sgx_rijndael128GCM_encrypt(
                p_key, p_data.as_ptr(), p_data.len() as u32, p_cipher.as_mut_ptr(),
                p_iv.as_ptr(), p_iv.len() as u32, p_aad.as_ptr(), p_aad.len() as u32, &mut mac,
            )};
            if ret == sgx_status_t::SGX_SUCCESS { p_mac.copy_from_slice(&mac); }
            ret
        }
    }

    pub mod ephemeral_key {
        use advanca_crypto_ctypes::CSgxEphemeralKey;
        use sgx_types::*;
        use core::mem::size_of;

        pub fn verify(ephemeral: &CSgxEphemeralKey, pubkey: &sgx_ec256_public_t) -> bool {
            let mut ecc_handle:sgx_ecc_state_handle_t = 0 as sgx_ecc_state_handle_t;
            let p_data = &ephemeral.pubkey as *const sgx_ec256_public_t as *const u8;
            let data_size = size_of::<sgx_ec256_public_t>() as u32;
            let mut signature = ephemeral.signature;
            let mut result:u8 = 0;

            let _ = unsafe {sgx_ecc256_open_context(&mut ecc_handle)};
            let _ = unsafe {sgx_ecdsa_verify(p_data, data_size, pubkey, &mut signature, &mut result, ecc_handle)};
            let _ = unsafe {sgx_ecc256_close_context(ecc_handle)};

            match sgx_generic_ecresult_t::from_repr(result as u32).unwrap() {
                sgx_generic_ecresult_t::SGX_EC_VALID             => true,
                sgx_generic_ecresult_t::SGX_EC_INVALID_SIGNATURE => false,
                _ => panic!("sgx_ecdsa_verify: {} -- Unexpected value!", result)
            }
        }
    }
}

pub mod secp256r1_signature {
    #[cfg(feature = "sgx_support")]
    pub use sgx_utils::*;
    #[cfg(feature = "ring_support")]
    pub use ring_utils::*;

    #[cfg(feature = "std_env")]
    use advanca_crypto_types::*;

    #[cfg(feature = "std_env")]
    pub fn to_bytes(signature: &Secp256r1Signature) -> [u8;64] {
        let mut bytes = [0_u8;64];
        bytes[..32].copy_from_slice(&signature.x);
        bytes[32..].copy_from_slice(&signature.y);
        bytes
    }

    #[cfg(feature = "sgx_support")]
    pub mod sgx_utils {
        use core::mem::{transmute};
        use advanca_crypto_types::Secp256r1Signature;
        use sgx_types::*;
        pub fn to_sgx_ec256_signature(signature: &Secp256r1Signature) -> sgx_ec256_signature_t {
            sgx_ec256_signature_t {
                x: unsafe{transmute::<[u8;32],[u32;8]>(signature.x)},
                y: unsafe{transmute::<[u8;32],[u32;8]>(signature.y)},
            }
        }

        pub fn from_sgx_ec256_signature(sig: sgx_ec256_signature_t) -> Secp256r1Signature {
            Secp256r1Signature {
                x: unsafe{transmute::<[u32;8],[u8;32]>(sig.x)},
                y: unsafe{transmute::<[u32;8],[u8;32]>(sig.y)},
            }
        }
    }

    #[cfg(feature = "ring_support")]
    pub mod ring_utils {
        use advanca_crypto_types::Secp256r1Signature;
        use ring::signature::Signature;

        pub fn from_ring_signature(ring_sig: &Signature) -> Secp256r1Signature {
            let ring_sig_buf = ring_sig.as_ref();
            assert_eq!(ring_sig_buf.len(), 64);

            let mut x: [u8;32] = [0;32];
            let mut y: [u8;32] = [0;32];
            x.copy_from_slice(&ring_sig_buf[..32]);
            y.copy_from_slice(&ring_sig_buf[32..]);
            x.reverse();
            y.reverse();
            Secp256r1Signature {
                x: x,
                y: y,
            }
        }

        pub fn to_ring_signature_bytes(adv_sig: &Secp256r1Signature) -> [u8;64] {
            let mut temp_buf: [u8;64] = [0;64];
            temp_buf[..32].copy_from_slice(&adv_sig.x);
            temp_buf[32..].copy_from_slice(&adv_sig.y);
            temp_buf[..32].reverse();
            temp_buf[32..].reverse();
            temp_buf
        }
    }
}

pub mod secp256r1_public {
    #[cfg(feature = "sgx_support")]
    pub use sgx_utils::*;
    #[cfg(feature = "ring_support")]
    pub use ring_utils::*;

    #[cfg(feature = "std_env")]
    use advanca_crypto_types::*;

    #[cfg(feature = "sgx_support")]
    pub mod sgx_utils {
        use advanca_crypto_types::Secp256r1PublicKey;
        use sgx_types::*;

        pub fn to_sgx_ec256_public(pubkey: &Secp256r1PublicKey) -> sgx_ec256_public_t {
            sgx_ec256_public_t {
                gx: pubkey.gx,
                gy: pubkey.gy,
            }
        }

        pub fn from_sgx_ec256_public(key: &sgx_ec256_public_t) -> Secp256r1PublicKey {
            Secp256r1PublicKey {
                gx: key.gx,
                gy: key.gy,
            }
        }
    }

    #[cfg(feature = "std_env")]
    pub fn to_bytes(pubkey: &Secp256r1PublicKey) -> [u8;64] {
        let mut bytes = [0_u8;64];
        bytes[..32].copy_from_slice(&pubkey.gx);
        bytes[32..].copy_from_slice(&pubkey.gy);
        bytes
    }

    #[cfg(feature = "ring_support")]
    mod ring_utils {
        use advanca_crypto_types::*;
        use ring::{agreement, signature};
        use ring::agreement::ECDH_P256;
        use ring::signature::{ECDSA_P256_SHA256_FIXED};

        pub fn to_ring_agreementkey(pubkey: &Secp256r1PublicKey) -> agreement::UnparsedPublicKey<Vec<u8>> {
            let mut buf = vec![0_u8; 65];
            let mut gx_be = pubkey.gx;
            let mut gy_be = pubkey.gy;

            gx_be.reverse();
            gy_be.reverse();

            buf[0] = 4;
            buf[1..33].copy_from_slice(&gx_be);
            buf[33..65].copy_from_slice(&gy_be);
            agreement::UnparsedPublicKey::new(&ECDH_P256, buf)
        }

        pub fn to_ring_signaturekey(pubkey: &Secp256r1PublicKey) -> signature::UnparsedPublicKey<Vec<u8>> {
            let mut buf = vec![0_u8; 65];
            let mut gx_be = pubkey.gx;
            let mut gy_be = pubkey.gy;

            gx_be.reverse();
            gy_be.reverse();

            buf[0] = 4;
            buf[1..33].copy_from_slice(&gx_be);
            buf[33..65].copy_from_slice(&gy_be);
            signature::UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, buf)
        }

        pub fn from_ring_bytes(pubkey_ref: &[u8]) -> Secp256r1PublicKey {
            // the array is made of [4][gx][gy] where gx, gy are 32bytes each
            assert_eq!(65, pubkey_ref.len());

            // we only handle type 4 pubkeys.
            let pubkey_type = pubkey_ref[0];
            assert_eq!(4, pubkey_type);

            let mut result = Secp256r1PublicKey::default();

            // extract gx, gy
            let gx_be = pubkey_ref.get(1..33).unwrap();
            let gy_be = pubkey_ref.get(33..65).unwrap();

            // for ring, gx, gy are in big-endian format
            // for intel, gx, gy are in little-endian format
            result.gx.copy_from_slice(gx_be);
            result.gy.copy_from_slice(gy_be);

            result.gx.reverse();
            result.gy.reverse();

            result
        }

        pub fn from_ring_agreementkey(pubkey: &agreement::PublicKey) -> Secp256r1PublicKey {
            let pubkey_ref = pubkey.as_ref();

            // the array is made of [4][gx][gy] where gx, gy are 32bytes each
            assert_eq!(65, pubkey_ref.len());

            // we only handle type 4 pubkeys.
            let pubkey_type = pubkey_ref[0];
            assert_eq!(4, pubkey_type);

            let mut result = Secp256r1PublicKey::default();

            // extract gx, gy
            let gx_be = pubkey_ref.get(1..33).unwrap();
            let gy_be = pubkey_ref.get(33..65).unwrap();

            // for ring, gx, gy are in big-endian format
            // for intel, gx, gy are in little-endian format
            result.gx.copy_from_slice(gx_be);
            result.gy.copy_from_slice(gy_be);

            result.gx.reverse();
            result.gy.reverse();

            result
        }
    }
}

pub mod sgx_ephemeral_key {
    #[cfg(feature = "sgx_support")]
    pub use sgx_utils::*;

    #[cfg(feature = "sgx_support")]
    pub mod sgx_utils {
        use advanca_crypto_types::EphemeralKey;
        use advanca_crypto_ctypes::CSgxEphemeralKey;
        use crate::secp256r1_public;
        use crate::secp256r1_signature;

        pub fn to_sgx(ephemeral: &EphemeralKey) -> CSgxEphemeralKey {
            CSgxEphemeralKey {
                pubkey: secp256r1_public::to_sgx_ec256_public(&ephemeral.pubkey),
                signature: secp256r1_signature::to_sgx_ec256_signature(&ephemeral.signature),
            }
        }
    }
}

#[cfg(feature = "aes_support")]
pub mod aes_utils {
    use cmac::{Cmac, Mac};
    use aes::Aes128;

    pub fn aes128_cmac_mac(key: &[u8;16], data: &[u8]) -> [u8; 16] {
        let mut cmac = Cmac::<Aes128>::new_varkey(key).unwrap();
        cmac.input(data);
        let temp_result = cmac.result().code();
        let mut result = [0_u8;16];
        result.copy_from_slice(temp_result.as_slice());
        result
    }

    pub fn aes128_cmac_verify(key: &[u8;16], data: &[u8], mac: &[u8;16]) -> bool {
        let mut cmac = Cmac::<Aes128>::new_varkey(key).unwrap();
        cmac.input(data);
        match cmac.verify(mac) {
            Ok(_)  => true,
            Err(_) => false,
        }
    }
}

#[cfg(feature = "aas_support")]
pub mod aas_utils {
    use advanca_crypto_types::{AasRegReport, Secp256r1PublicKey};
    use ring::signature::EcdsaKeyPair;
    use ring::rand::SystemRandom;
    use crate::{secp256r1_signature, secp256r1_public};

    mod aas_reg_report {
        use advanca_crypto_types::AasRegReport;
        use crate::{secp256r1_signature, secp256r1_public};

        pub fn to_bytes(aas_reg_report: &AasRegReport) -> [u8;136] {
            // (8)   - attested_time: u64
            // (64)  - worker_pubkey: Secp256r1PublicKey
            // (64)  - aas_signature: Secp256t1Signature
            // (136) - total size of data
            let mut bytes = [0_u8;136];
            let worker_pubkey_buf = secp256r1_public::to_bytes(&aas_reg_report.worker_pubkey);
            let aas_signature_buf = secp256r1_signature::to_bytes(&aas_reg_report.aas_signature);
            bytes[..8].copy_from_slice(&aas_reg_report.attested_time.to_le_bytes());
            bytes[8..72].copy_from_slice(&worker_pubkey_buf);
            bytes[72..].copy_from_slice(&aas_signature_buf);
            bytes
        }
    }

    pub fn verify_aas_reg_report (reg_report: &AasRegReport, aas_pubkey: &Secp256r1PublicKey) -> bool {
        let aas_pubkey_ring = secp256r1_public::to_ring_signaturekey(&aas_pubkey);
        let aas_report_buf = aas_reg_report::to_bytes(&reg_report);
        let aas_report_sig = secp256r1_signature::to_ring_signature_bytes(&reg_report.aas_signature);
        // we'll verify the signature over attested_time and worker_pubkey
        match aas_pubkey_ring.verify(&aas_report_buf[..72], &aas_report_sig) {
            Ok(_) => true,
            Err(e) => {
                println!("{:?}", e);
                false
            },
        }

    }

    // TODO: Change the signing of the aas reg report to use Secp256r1PrivateKey
    // this is a quick hack... we'll directly use a ring ecdsakeypair here first
    pub fn sign_aas_reg_report (report: AasRegReport, signing_key: &EcdsaKeyPair) -> AasRegReport {
        let rng = SystemRandom::new();
        // create the data buffer...
        // length of the data buffer is 8bytes(time u64) + 64bytes(ec256 public key)
        // content is [<attested_time: 8> || <public_key: 64>]
        let mut data = [0_u8; 72];
        data[..8].copy_from_slice(&report.attested_time.to_le_bytes());
        data[8..].copy_from_slice(&secp256r1_public::to_bytes(&report.worker_pubkey));
        let ring_signature = signing_key.sign(&rng, &data).unwrap();
        let aas_signature = secp256r1_signature::from_ring_signature(&ring_signature);
        AasRegReport {
            attested_time: report.attested_time,
            worker_pubkey: report.worker_pubkey,
            aas_signature: aas_signature,
        }
    }
}

// #[cfg(test)]
// mod tests {
//     use ring::signature::*;
//     use ring::rand::SystemRandom;
//     use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING};
// 
// 
//     #[test]
//     fn ec256_signature_test() {
//         let rng = SystemRandom::new();
//         let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
//         let pkcs8 = pkcs8.as_ref();
//         let keypair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8).unwrap();
//         const MESSAGE: &[u8] = b"hello, world";
//         let sig = keypair.sign(&rng, MESSAGE).unwrap();
//         let sig_bytes = sig.as_ref();
//         println!("len: {:?}", sig_bytes.len());
//         println!("{:?}", sig_bytes);
//         let pubkey = keypair.public_key();
//     }
// }


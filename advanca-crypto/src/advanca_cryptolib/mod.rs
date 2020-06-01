#[cfg(feature = "std_env")]
use sgx_ucrypto as intel_crypto;
#[cfg(feature = "std_env")]
use sgx_ucrypto::sgx_read_rand;

#[cfg(feature = "sgx_enclave")]
use sgx_tcrypto as intel_crypto;
#[cfg(feature = "sgx_enclave")]
use sgx_types::sgx_read_rand;

use advanca_crypto_types::*;
use intel_crypto::*;

use sgx_types::*;

use std::vec::Vec;

use advanca_macros::handle_sgx;

pub fn aes128cmac_mac(p_key: &Aes128Key, p_data: &[u8]) -> Result<Aes128Mac, CryptoError> {
    match rsgx_rijndael128_cmac_slice(&p_key.key, p_data) {
        Ok(mac) => {
            Ok (Aes128Mac {
                mac: mac,
            })
        },
        Err(s)  => {
            Err(CryptoError::SgxError(s.from_key(), format!("{}", s)))
        },
    }
}

pub fn aes128cmac_verify(p_key: &Aes128Key, p_data: &[u8], p_orig_mac: &Aes128Mac) -> Result<bool, CryptoError> {
    let msg_mac = aes128cmac_mac(p_key, p_data)?;
    Ok(msg_mac.mac == p_orig_mac.mac)
}

pub fn aes128gcm_encrypt(p_key: &Aes128Key, p_data: &[u8]) -> Result<Aes128EncryptedMsg, CryptoError> {
    let mut iv = [0_u8; 12];
    let mut mac = [0_u8; 16];
    let mut cipher = vec![0_u8; p_data.len()];

    unsafe{
        handle_sgx!(sgx_read_rand(iv.as_mut_ptr(), iv.len()))?;
    }
    if let Err(s) = rsgx_rijndael128GCM_encrypt(&p_key.key, p_data, &iv, &[], &mut cipher[..], &mut mac) {
        return Err(CryptoError::SgxError(s.from_key(), format!("{}", s)))
    };

    Ok (Aes128EncryptedMsg {
        iv: iv,
        mac: Aes128Mac{mac: mac},
        cipher: cipher,
    })
}

pub fn aes128gcm_decrypt(p_key: &Aes128Key, p_encrypted_msg: &Aes128EncryptedMsg) -> Result<Vec<u8>, CryptoError> {
    let p_iv = &p_encrypted_msg.iv;
    let p_mac = &p_encrypted_msg.mac.mac;
    let p_cipher = &p_encrypted_msg.cipher[..];
    let mut plaintext = vec![0_u8; p_encrypted_msg.cipher.len()];

    if let Err(s) = rsgx_rijndael128GCM_decrypt(&p_key.key, p_cipher, p_iv, &[], p_mac, &mut plaintext[..]) {
        return Err(CryptoError::SgxError(s.from_key(), format!("{}", s)));
    }

    Ok ( plaintext )
}

pub fn secp256r1_gen_keypair() -> Result<(Secp256r1PrivateKey, Secp256r1PublicKey), CryptoError> {
    // generate secp256r1 keypair for communication with worker
    let mut sgx_pubkey = sgx_ec256_public_t::default();
    let mut sgx_prvkey = sgx_ec256_private_t::default();
    let mut ecc_handle: sgx_ecc_state_handle_t = 0 as sgx_ecc_state_handle_t;

    unsafe {
        handle_sgx!(sgx_ecc256_open_context(&mut ecc_handle))?;
        handle_sgx!(sgx_ecc256_create_key_pair(&mut sgx_prvkey, &mut sgx_pubkey, ecc_handle))?;
        handle_sgx!(sgx_ecc256_close_context(ecc_handle))?;
    }
    let prvkey = Secp256r1PrivateKey::from_sgx_ec256_private(&sgx_prvkey);
    let pubkey = Secp256r1PublicKey::from_sgx_ec256_public(&sgx_pubkey);
    Ok((prvkey, pubkey))
}

fn secp256r1_compute_shared_dhkey(prvkey: &Secp256r1PrivateKey, pubkey: &Secp256r1PublicKey) -> Result<[u8;32], CryptoError> {
    let mut sgx_prvkey = prvkey.to_sgx_ec256_private();
    let mut sgx_pubkey = pubkey.to_sgx_ec256_public();
    let mut gab_x = sgx_ec256_dh_shared_t::default();
    let mut ecc_handle: sgx_ecc_state_handle_t = 0 as sgx_ecc_state_handle_t;

    unsafe {
        handle_sgx!(sgx_ecc256_open_context(&mut ecc_handle))?;
        handle_sgx!(sgx_ecc256_compute_shared_dhkey(&mut sgx_prvkey, &mut sgx_pubkey, &mut gab_x, ecc_handle))?;
        handle_sgx!(sgx_ecc256_close_context(ecc_handle))?;
    }
    Ok(gab_x.s)
}

pub fn derive_kdk(prvkey: &Secp256r1PrivateKey, pubkey: &Secp256r1PublicKey) -> Result<Aes128Key, CryptoError> {
    let shared_dhkey = secp256r1_compute_shared_dhkey(prvkey, pubkey)?;
    let key0 = Aes128Key {
        key:[0;16],
    };

    let mac = aes128cmac_mac(&key0, &shared_dhkey)?;
    Ok(Aes128Key {
        key: mac.mac,
    })
}

pub fn secp256r1_sign_msg(prvkey: &Secp256r1PrivateKey, msg: &[u8]) -> Result<Secp256r1SignedMsg, CryptoError> {
    let mut sgx_prvkey = prvkey.to_sgx_ec256_private();
    let mut ecc_handle: sgx_ecc_state_handle_t = 0 as sgx_ecc_state_handle_t;
    let mut signature = sgx_ec256_signature_t::default();

    unsafe {
        handle_sgx!(sgx_ecc256_open_context(&mut ecc_handle))?;
        handle_sgx!(sgx_ecdsa_sign(msg.as_ptr(), msg.len() as u32, &mut sgx_prvkey, &mut signature, ecc_handle))?;
        handle_sgx!(sgx_ecc256_close_context(ecc_handle))?;
    }

    Ok(Secp256r1SignedMsg {
        msg: msg.to_vec(),
        signature: Secp256r1Signature::from_sgx_ec256_signature(signature),
    })
}

pub fn secp256r1_verify_msg(pubkey: &Secp256r1PublicKey, signed_msg: &Secp256r1SignedMsg) -> Result<bool, CryptoError> {
    secp256r1_verify_signature(pubkey, &signed_msg.msg, &signed_msg.signature)
}

pub fn secp256r1_verify_signature(pubkey: &Secp256r1PublicKey, msg: &[u8], signature: &Secp256r1Signature) -> Result<bool, CryptoError> {
    let sgx_pubkey = pubkey.to_sgx_ec256_public();
    let mut sgx_signature = signature.to_sgx_ec256_signature();
    let mut ecc_handle: sgx_ecc_state_handle_t = 0 as sgx_ecc_state_handle_t;
    let mut result = 0;

    unsafe {
        handle_sgx!(sgx_ecc256_open_context(&mut ecc_handle))?;
        handle_sgx!(sgx_ecdsa_verify(msg.as_ptr(), msg.len() as u32, &sgx_pubkey, &mut sgx_signature, &mut result, ecc_handle))?;
        handle_sgx!(sgx_ecc256_close_context(ecc_handle))?;
    }
    let result = sgx_generic_ecresult_t::from_repr(result as u32).unwrap();
    match result {
        sgx_generic_ecresult_t::SGX_EC_VALID             => Ok(true),
        sgx_generic_ecresult_t::SGX_EC_INVALID_SIGNATURE => Ok(false),
        e                                                => panic!("Unexpected ECC Result! {:?} (Refer to sgx_generic_ecresult_t)", e.from_key()),
    }
}

pub fn aas_verify_reg_request(key: &Aes128Key, reg_request: &AasRegRequest) -> Result<bool, CryptoError> {
    let reg_request_bytes = reg_request.to_check_bytes();
    let reg_request_mac = aes128cmac_mac(key, &reg_request_bytes)?;
    Ok(reg_request_mac == reg_request.mac)
}

pub fn aas_verify_reg_report(pubkey: &Secp256r1PublicKey, reg_report: &AasRegReport) -> Result<bool, CryptoError> {
    let reg_report_bytes = reg_report.to_check_bytes();
    secp256r1_verify_signature(pubkey, &reg_report_bytes, &reg_report.aas_signature)
}

pub fn aas_sign_reg_report(prvkey: &Secp256r1PrivateKey, reg_report: AasRegReport) -> Result<AasRegReport, CryptoError> {
    let reg_report_bytes = reg_report.to_check_bytes();
    let signed_msg = secp256r1_sign_msg(prvkey, &reg_report_bytes)?;
    Ok(AasRegReport {
        attested_time: reg_report.attested_time,
        worker_pubkey: reg_report.worker_pubkey,
        aas_signature: signed_msg.signature,
    })
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn encrypt_decrypt() {
        let key = Aes128Key {
            key: [0; 16],
        };
        let data: [u8;6] = [1,2,3,4,5,6];
        let encrypted_msg = aes128gcm_encrypt(&key, &data).unwrap();
        let plaintext = aes128gcm_decrypt(&key, &encrypted_msg).unwrap();
        assert_eq!(plaintext, data);
    }

    #[test]
    fn mac_verify() {
        let key = Aes128Key {
            key: [0; 16],
        };
        let mut data: [u8;6] = [1,2,3,4,5,6];
        let data_mac = aes128cmac_mac(&key, &data).unwrap();
        assert_eq!([194, 158, 14, 143, 248, 152, 4, 193, 94, 54, 74, 95, 115, 111, 30, 101], data_mac.mac);
        assert_eq!(true, aes128cmac_verify(&key, &data, &data_mac).unwrap());
        data[1] = 3;
        assert_eq!(false, aes128cmac_verify(&key, &data, &data_mac).unwrap());
    }

    #[test]
    fn derive_shared_secrets() {
        let (prvkey1, pubkey1) = secp256r1_gen_keypair().unwrap();
        let (prvkey2, pubkey2) = secp256r1_gen_keypair().unwrap();
        let kdk1 = derive_kdk(&prvkey1, &pubkey2).unwrap();
        let kdk2 = derive_kdk(&prvkey2, &pubkey1).unwrap();
        assert_eq!(kdk1, kdk2);
    }

    #[test]
    fn sign_verify() {
        let (prvkey1, pubkey1) = secp256r1_gen_keypair().unwrap();
        let (_prvkey2, pubkey2) = secp256r1_gen_keypair().unwrap();
        let msg = [1,2,3,4,5,6];
        let mut signed_msg = secp256r1_sign_msg(&prvkey1, &msg).unwrap();
        assert_eq!(true, secp256r1_verify_msg(&pubkey1, &signed_msg).unwrap());
        assert_eq!(false, secp256r1_verify_msg(&pubkey2, &signed_msg).unwrap());
        signed_msg.msg[3] = 10;
        assert_eq!(false, secp256r1_verify_msg(&pubkey1, &signed_msg).unwrap());
        assert_eq!(false, secp256r1_verify_msg(&pubkey2, &signed_msg).unwrap());
    }

    #[test]
    fn secp256r1_from_der_test() {
        let aas_prvkey_der_bytes = fs::read("sp_prv.der").unwrap();
        let prvkey = Secp256r1PrivateKey::from_der(&aas_prvkey_der_bytes);
        println!("{:x?}", prvkey);
    }

}



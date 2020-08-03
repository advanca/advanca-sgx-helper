// Copyright (C) 2020 ADVANCA PTE. LTD.
// 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
//     https://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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

use rand::rngs::StdRng;
use rand::SeedableRng;
use schnorrkel;

use advanca_macros::handle_sgx;

const SIGNING_CONTEXT: &[u8] = b"advanca-sign";

pub fn aes128cmac_mac(p_key: &Aes128Key, p_data: &[u8]) -> Result<Aes128Mac, CryptoError> {
    match rsgx_rijndael128_cmac_slice(&p_key.key, p_data) {
        Ok(mac) => Ok(Aes128Mac { mac: mac }),
        Err(s) => Err(CryptoError::SgxError(s.from_key(), format!("{}", s))),
    }
}

pub fn aes128cmac_verify(
    p_key: &Aes128Key,
    p_data: &[u8],
    p_orig_mac: &Aes128Mac,
) -> Result<bool, CryptoError> {
    let msg_mac = aes128cmac_mac(p_key, p_data)?;
    Ok(msg_mac.mac == p_orig_mac.mac)
}

pub fn aes128gcm_encrypt(
    p_key: &Aes128Key,
    p_data: &[u8],
) -> Result<Aes128EncryptedMsg, CryptoError> {
    let mut iv = [0_u8; 12];
    let mut mac = [0_u8; 16];
    let mut cipher = vec![0_u8; p_data.len()];

    unsafe {
        handle_sgx!(sgx_read_rand(iv.as_mut_ptr(), iv.len()))?;
    }
    if let Err(s) =
        rsgx_rijndael128GCM_encrypt(&p_key.key, p_data, &iv, &[], &mut cipher[..], &mut mac)
    {
        return Err(CryptoError::SgxError(s.from_key(), format!("{}", s)));
    };

    Ok(Aes128EncryptedMsg {
        iv: iv,
        mac: Aes128Mac { mac: mac },
        cipher: cipher,
    })
}

pub fn aes128gcm_decrypt(
    p_key: &Aes128Key,
    p_encrypted_msg: &Aes128EncryptedMsg,
) -> Result<Vec<u8>, CryptoError> {
    let p_iv = &p_encrypted_msg.iv;
    let p_mac = &p_encrypted_msg.mac.mac;
    let p_cipher = &p_encrypted_msg.cipher[..];
    let mut plaintext = vec![0_u8; p_encrypted_msg.cipher.len()];

    if let Err(s) =
        rsgx_rijndael128GCM_decrypt(&p_key.key, p_cipher, p_iv, &[], p_mac, &mut plaintext[..])
    {
        return Err(CryptoError::SgxError(s.from_key(), format!("{}", s)));
    }

    Ok(plaintext)
}

#[cfg(feature = "sgx_enclave")]
pub fn enclave_get_sk_key(ra_context: sgx_ra_context_t) -> Result<Aes128Key, CryptoError> {
    let mut key = sgx_key_128bit_t::default();
    unsafe {
        handle_sgx!(sgx_ra_get_keys(
            ra_context,
            sgx_ra_key_type_t::SGX_RA_KEY_SK,
            &mut key
        ))?;
    };
    Ok(Aes128Key { key: key })
}

pub fn secp256r1_gen_keypair() -> Result<(Secp256r1PrivateKey, Secp256r1PublicKey), CryptoError> {
    // generate secp256r1 keypair for communication with worker
    let mut sgx_pubkey = sgx_ec256_public_t::default();
    let mut sgx_prvkey = sgx_ec256_private_t::default();
    let mut ecc_handle: sgx_ecc_state_handle_t = 0 as sgx_ecc_state_handle_t;

    unsafe {
        handle_sgx!(sgx_ecc256_open_context(&mut ecc_handle))?;
        handle_sgx!(sgx_ecc256_create_key_pair(
            &mut sgx_prvkey,
            &mut sgx_pubkey,
            ecc_handle
        ))?;
        handle_sgx!(sgx_ecc256_close_context(ecc_handle))?;
    }
    let prvkey = Secp256r1PrivateKey::from_sgx_ec256_private(&sgx_prvkey);
    let pubkey = Secp256r1PublicKey::from_sgx_ec256_public(&sgx_pubkey);
    Ok((prvkey, pubkey))
}

pub fn secp256r1_compute_shared_dhkey(
    prvkey: &Secp256r1PrivateKey,
    pubkey: &Secp256r1PublicKey,
) -> Result<[u8; 32], CryptoError> {
    let mut sgx_prvkey = prvkey.to_sgx_ec256_private();
    let mut sgx_pubkey = pubkey.to_sgx_ec256_public();
    let mut gab_x = sgx_ec256_dh_shared_t::default();
    let mut ecc_handle: sgx_ecc_state_handle_t = 0 as sgx_ecc_state_handle_t;

    unsafe {
        handle_sgx!(sgx_ecc256_open_context(&mut ecc_handle))?;
        handle_sgx!(sgx_ecc256_compute_shared_dhkey(
            &mut sgx_prvkey,
            &mut sgx_pubkey,
            &mut gab_x,
            ecc_handle
        ))?;
        handle_sgx!(sgx_ecc256_close_context(ecc_handle))?;
    }
    Ok(gab_x.s)
}

pub fn sr25519_gen_keypair() -> Result<(Sr25519PrivateKey, Sr25519PublicKey), CryptoError> {
    let mut seed_bytes = [0_u8; 32];
    unsafe {
        handle_sgx!(sgx_read_rand(seed_bytes.as_mut_ptr(), seed_bytes.len()))?;
    }
    let rng: StdRng = SeedableRng::from_seed(seed_bytes);
    let sr25519_keypair = schnorrkel::Keypair::generate_with(rng);
    let sr25519_pubkey = Sr25519PublicKey::from_schnorrkel_public(&sr25519_keypair.public);
    let sr25519_prvkey = Sr25519PrivateKey::from_schnorrkel_private(&sr25519_keypair.secret);
    Ok((sr25519_prvkey, sr25519_pubkey))
}

pub fn sr25519_sign_msg(
    prvkey: &Sr25519PrivateKey,
    msg: &[u8],
) -> Result<Sr25519SignedMsg, CryptoError> {
    let mut seed_bytes = [0_u8; 32];
    unsafe {
        handle_sgx!(sgx_read_rand(seed_bytes.as_mut_ptr(), seed_bytes.len()))?;
    }
    let rng: StdRng = SeedableRng::from_seed(seed_bytes);
    let secretkey = prvkey.to_schnorrkel_private();
    let context = schnorrkel::signing_context(SIGNING_CONTEXT);
    let signature = secretkey.sign(
        schnorrkel::context::attach_rng(context.bytes(msg), rng),
        &secretkey.to_public(),
    );
    Ok(Sr25519SignedMsg {
        msg: msg.to_vec(),
        signature: Sr25519Signature::from_schnorrkel_signature(&signature),
    })
}

pub fn sr25519_verify_msg(
    pubkey: &Sr25519PublicKey,
    signed_msg: &Sr25519SignedMsg,
) -> Result<bool, CryptoError> {
    sr25519_verify_signature(pubkey, &signed_msg.msg, &signed_msg.signature)
}

pub fn sr25519_verify_signature(
    pubkey: &Sr25519PublicKey,
    msg: &[u8],
    signature: &Sr25519Signature,
) -> Result<bool, CryptoError> {
    let context = schnorrkel::signing_context(SIGNING_CONTEXT);
    let schnorrkel_pubkey = pubkey.to_schnorrkel_public();
    let schnorrkel_signature = signature.to_schnorrkel_signature();
    Ok(schnorrkel_pubkey
        .verify(context.bytes(msg), &schnorrkel_signature)
        .is_ok())
}

pub fn derive_kdk(
    prvkey: &Secp256r1PrivateKey,
    pubkey: &Secp256r1PublicKey,
) -> Result<Aes128Key, CryptoError> {
    let shared_dhkey = secp256r1_compute_shared_dhkey(prvkey, pubkey)?;
    let key0 = Aes128Key { key: [0; 16] };

    let mac = aes128cmac_mac(&key0, &shared_dhkey)?;
    Ok(Aes128Key { key: mac.mac })
}

pub fn secp256r1_sign_msg(
    prvkey: &Secp256r1PrivateKey,
    msg: &[u8],
) -> Result<Secp256r1SignedMsg, CryptoError> {
    let mut sgx_prvkey = prvkey.to_sgx_ec256_private();
    let mut ecc_handle: sgx_ecc_state_handle_t = 0 as sgx_ecc_state_handle_t;
    let mut signature = sgx_ec256_signature_t::default();

    unsafe {
        handle_sgx!(sgx_ecc256_open_context(&mut ecc_handle))?;
        handle_sgx!(sgx_ecdsa_sign(
            msg.as_ptr(),
            msg.len() as u32,
            &mut sgx_prvkey,
            &mut signature,
            ecc_handle
        ))?;
        handle_sgx!(sgx_ecc256_close_context(ecc_handle))?;
    }

    Ok(Secp256r1SignedMsg {
        msg: msg.to_vec(),
        signature: Secp256r1Signature::from_sgx_ec256_signature(signature),
    })
}

pub fn secp256r1_verify_msg(
    pubkey: &Secp256r1PublicKey,
    signed_msg: &Secp256r1SignedMsg,
) -> Result<bool, CryptoError> {
    secp256r1_verify_signature(pubkey, &signed_msg.msg, &signed_msg.signature)
}

pub fn secp256r1_verify_signature(
    pubkey: &Secp256r1PublicKey,
    msg: &[u8],
    signature: &Secp256r1Signature,
) -> Result<bool, CryptoError> {
    let sgx_pubkey = pubkey.to_sgx_ec256_public();
    let mut sgx_signature = signature.to_sgx_ec256_signature();
    let mut ecc_handle: sgx_ecc_state_handle_t = 0 as sgx_ecc_state_handle_t;
    let mut result = 0;

    unsafe {
        handle_sgx!(sgx_ecc256_open_context(&mut ecc_handle))?;
        handle_sgx!(sgx_ecdsa_verify(
            msg.as_ptr(),
            msg.len() as u32,
            &sgx_pubkey,
            &mut sgx_signature,
            &mut result,
            ecc_handle
        ))?;
        handle_sgx!(sgx_ecc256_close_context(ecc_handle))?;
    }
    let result = sgx_generic_ecresult_t::from_repr(result as u32).unwrap();
    match result {
        sgx_generic_ecresult_t::SGX_EC_VALID => Ok(true),
        sgx_generic_ecresult_t::SGX_EC_INVALID_SIGNATURE => Ok(false),
        e => panic!(
            "Unexpected ECC Result! {:?} (Refer to sgx_generic_ecresult_t)",
            e.from_key()
        ),
    }
}

pub fn aas_verify_reg_request(
    key: &Aes128Key,
    reg_request: &AasRegRequest,
) -> Result<bool, CryptoError> {
    let reg_request_bytes = reg_request.to_check_bytes();
    let reg_request_mac = aes128cmac_mac(key, &reg_request_bytes)?;
    Ok(reg_request_mac == reg_request.mac)
}

pub fn aas_verify_reg_report(
    pubkey: &Secp256r1PublicKey,
    reg_report: &AasRegReport,
) -> Result<bool, CryptoError> {
    let reg_report_bytes = reg_report.to_check_bytes();
    secp256r1_verify_signature(pubkey, &reg_report_bytes, &reg_report.aas_signature)
}

pub fn aas_sign_reg_report(
    prvkey: &Secp256r1PrivateKey,
    reg_report: AasRegReport,
) -> Result<AasRegReport, CryptoError> {
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
        let key = Aes128Key { key: [0; 16] };
        let data: [u8; 6] = [1, 2, 3, 4, 5, 6];
        let encrypted_msg = aes128gcm_encrypt(&key, &data).unwrap();
        let plaintext = aes128gcm_decrypt(&key, &encrypted_msg).unwrap();
        assert_eq!(plaintext, data);
    }

    #[test]
    fn mac_verify() {
        let key = Aes128Key { key: [0; 16] };
        let mut data: [u8; 6] = [1, 2, 3, 4, 5, 6];
        let data_mac = aes128cmac_mac(&key, &data).unwrap();
        assert_eq!(
            [194, 158, 14, 143, 248, 152, 4, 193, 94, 54, 74, 95, 115, 111, 30, 101],
            data_mac.mac
        );
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
        let msg = [1, 2, 3, 4, 5, 6];
        let mut signed_msg = secp256r1_sign_msg(&prvkey1, &msg).unwrap();
        assert_eq!(true, secp256r1_verify_msg(&pubkey1, &signed_msg).unwrap());
        assert_eq!(false, secp256r1_verify_msg(&pubkey2, &signed_msg).unwrap());
        signed_msg.msg[3] = 10;
        assert_eq!(false, secp256r1_verify_msg(&pubkey1, &signed_msg).unwrap());
        assert_eq!(false, secp256r1_verify_msg(&pubkey2, &signed_msg).unwrap());
    }

    #[test]
    fn secp256r1_from_der_test() {
        // priv:
        //     00:a6:5f:a6:65:d4:08:e5:4a:c2:61:9f:65:9e:b8:
        //     f0:d0:47:1c:b1:7c:bb:17:66:75:e9:65:56:43:df:
        //     af:ac
        // pub:
        //     04:b1:81:35:ac:6d:71:aa:ec:5a:79:33:73:85:e8:
        //     0c:c3:08:02:9e:15:9d:3e:9f:a5:53:53:bf:46:4e:
        //     ed:c0:84:5f:40:48:8e:f3:99:62:e3:42:79:2e:35:
        //     b4:24:48:e8:75:22:3e:7d:50:96:ee:a7:c8:42:c0:
        //     6d:d0:b7:69:17
        // ASN1 OID: prime256v1
        // NIST CURVE: P-256
        let aas_prvkey_der_bytes = [
            48, 119, 2, 1, 1, 4, 32, 0, 166, 95, 166, 101, 212, 8, 229, 74, 194, 97, 159, 101, 158,
            184, 240, 208, 71, 28, 177, 124, 187, 23, 102, 117, 233, 101, 86, 67, 223, 175, 172,
            160, 10, 6, 8, 42, 134, 72, 206, 61, 3, 1, 7, 161, 68, 3, 66, 0, 4, 177, 129, 53, 172,
            109, 113, 170, 236, 90, 121, 51, 115, 133, 232, 12, 195, 8, 2, 158, 21, 157, 62, 159,
            165, 83, 83, 191, 70, 78, 237, 192, 132, 95, 64, 72, 142, 243, 153, 98, 227, 66, 121,
            46, 53, 180, 36, 72, 232, 117, 34, 62, 125, 80, 150, 238, 167, 200, 66, 192, 109, 208,
            183, 105, 23,
        ];
        let prvkey = Secp256r1PrivateKey::from_der(&aas_prvkey_der_bytes);
        let prvkey_actual = Secp256r1PrivateKey {
            r: [
                172, 175, 223, 67, 86, 101, 233, 117, 102, 23, 187, 124, 177, 28, 71, 208, 240,
                184, 158, 101, 159, 97, 194, 74, 229, 8, 212, 101, 166, 95, 166, 0,
            ],
        };
        assert_eq!(prvkey, prvkey_actual);
    }

    #[test]
    fn sr25519_test() {
        let (sr25519_prvkey, sr25519_pubkey) = sr25519_gen_keypair().unwrap();
        let msg: &[u8] = b"test message";
        let mut signed_msg = sr25519_sign_msg(&sr25519_prvkey, msg).unwrap();
        assert_eq!(signed_msg.msg, msg);
        let is_verified = sr25519_verify_msg(&sr25519_pubkey, &signed_msg).unwrap();
        assert_eq!(true, is_verified);
        signed_msg.msg[0] = 0;
        let is_verified = sr25519_verify_msg(&sr25519_pubkey, &signed_msg).unwrap();
        assert_eq!(false, is_verified);
    }
}

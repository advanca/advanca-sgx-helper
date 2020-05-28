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

pub fn aes128cmac_mac(p_key: &Aes128Key, p_data: &[u8]) -> Result<Aes128Mac, CryptoError> {
    match rsgx_rijndael128_cmac_slice(&p_key.key, p_data) {
        Ok(mac) => {
            Ok (Aes128Mac {
                mac: mac,
            })
        },
        Err(s)  => {
            Err(CryptoError::SgxError(format!("{}", s)))
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

    let s = unsafe {sgx_read_rand(iv.as_mut_ptr(), iv.len())};
    if s != sgx_status_t::SGX_SUCCESS {
        return Err(CryptoError::SgxError(format!("{}", s)));
    };
    if let Err(s) = rsgx_rijndael128GCM_encrypt(&p_key.key, p_data, &iv, &[], &mut cipher[..], &mut mac) {
        return Err(CryptoError::SgxError(format!("{}", s)));
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
        return Err(CryptoError::SgxError(format!("{}", s)));
    }

    Ok ( plaintext )
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt() {
        let key = Aes128Key {
            key: [0; 16],
        };
        let data: [u8;6] = [1,2,3,4,5,6];
        let encrypted_msg = aes128gcm_encrypt(&key, &data).unwrap();
        println!("{:?}", encrypted_msg);
        let plaintext = aes128gcm_decrypt(&key, &encrypted_msg).unwrap();
        println!("{:?}", plaintext);
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
}



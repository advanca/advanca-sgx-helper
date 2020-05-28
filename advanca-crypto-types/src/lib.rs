#![cfg_attr(any(feature = "sgx_enclave"), no_std)]

#[cfg(feature = "sgx_enclave")]
#[macro_use]
extern crate sgx_tstd as std;

#[cfg(feature = "std_env")]
use serde as serde;
#[cfg(feature = "std_env")]
use serde_big_array as serde_big_array;

#[cfg(feature = "sgx_enclave")]
use serde_sgx as serde;
#[cfg(feature = "sgx_enclave")]
use serde_big_array_sgx as serde_big_array;

use serde::{Serialize, Deserialize};
use serde_big_array::big_array;

use std::vec::Vec;

#[cfg(feature = "ring_support")]
use ring::signature::{self, Signature};
#[cfg(feature = "ring_support")]
use ring::agreement;

use sgx_types::*;

use core::mem::transmute;
use core::fmt;
use std::error::Error;

big_array! { BigArray; }

#[cfg_attr(feature = "sgx_enclave", serde(crate = "serde_sgx"))]
#[derive(Debug, Serialize, Deserialize)]
pub enum CryptoError {
    InvalidMac,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            CryptoError::InvalidMac => {
                write!(f, "mac verification failed!")
            },
        }
    }
}

impl Error for CryptoError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

#[cfg_attr(feature = "sgx_enclave", serde(crate = "serde_sgx"))]
#[derive(Serialize, Deserialize, Default)]
pub struct EphemeralKey {
    pub pubkey    : Secp256r1PublicKey,
    pub signature : Secp256r1Signature,
}

#[cfg_attr(feature = "sgx_enclave", serde(crate = "serde_sgx"))]
#[derive(Serialize, Deserialize)]
pub struct Rsa3072Signature {
    #[serde(with = "BigArray")]
    signature: [u8; 384],
}

#[cfg_attr(feature = "sgx_enclave", serde(crate = "serde_sgx"))]
#[derive(Serialize, Deserialize)]
pub struct Rsa3072PublicKey {
    #[serde(with = "BigArray")]
    modulus: [u8; 384],
    exponent: [u8; 4],
}

#[cfg_attr(feature = "sgx_enclave", serde(crate = "serde_sgx"))]
#[derive(Serialize, Deserialize, Default, Debug)]
pub struct Secp256r1PublicKey {
    pub gx: [u8; 32],
    pub gy: [u8; 32],
}

#[cfg_attr(feature = "sgx_enclave", serde(crate = "serde_sgx"))]
#[derive(Serialize, Deserialize, Default, Debug)]
pub struct Secp256r1PrivateKey {
    pub r: [u8; 32],
}

#[cfg_attr(feature = "sgx_enclave", serde(crate = "serde_sgx"))]
#[derive(Serialize, Deserialize, Default, Debug)]
pub struct Secp256r1Signature {
    pub x: [u8; 32],
    pub y: [u8; 32],
}

#[cfg_attr(feature = "sgx_enclave", serde(crate = "serde_sgx"))]
#[derive(Serialize, Deserialize, Default, Debug)]
pub struct Aes128Key {
    pub key: [u8; 16],
}

#[cfg_attr(feature = "sgx_enclave", serde(crate = "serde_sgx"))]
#[derive(Serialize, Deserialize, Default, Debug)]
pub struct Aes128Mac {
    pub mac: [u8; 16],
}

#[cfg_attr(feature = "sgx_enclave", serde(crate = "serde_sgx"))]
#[derive(Serialize, Deserialize, Default, Debug)]
pub struct Aes128EncryptedMsg {
    pub iv: [u8; 16],
    pub mac: Aes128Mac,
    pub cipher: Vec<u8>,

}

#[cfg_attr(feature = "sgx_enclave", serde(crate = "serde_sgx"))]
#[derive(Serialize, Deserialize, Default, Debug)]
pub struct AasRegReport {
    pub attested_time: u64,
    pub worker_pubkey: Secp256r1PublicKey,
    pub aas_signature: Secp256r1Signature,
}

impl Secp256r1PublicKey {
    pub fn from_sgx_ec256_public(key: &sgx_ec256_public_t) -> Secp256r1PublicKey {
        Secp256r1PublicKey {
            gx: key.gx,
            gy: key.gy,
        }
    }

    pub fn to_sgx_ec256_public(pubkey: &Secp256r1PublicKey) -> sgx_ec256_public_t {
        sgx_ec256_public_t {
            gx: pubkey.gx,
            gy: pubkey.gy,
        }
    }
}

impl Secp256r1PrivateKey {
    pub fn from_sgx_ec256_private(key: &sgx_ec256_private_t) -> Secp256r1PrivateKey {
        Secp256r1PrivateKey {
            r: key.r,
        }
    }

    pub fn to_sgx_ec256_private(&self) -> sgx_ec256_private_t {
        sgx_ec256_private_t {
            r: self.r,
        }
    }
}

impl Secp256r1Signature {
    pub fn from_sgx_ec256_signature(sig: sgx_ec256_signature_t) -> Secp256r1Signature {
        Secp256r1Signature {
            x: unsafe{transmute::<[u32;8],[u8;32]>(sig.x)},
            y: unsafe{transmute::<[u32;8],[u8;32]>(sig.y)},
        }
    }

    pub fn to_sgx_ec256_signature(signature: &Secp256r1Signature) -> sgx_ec256_signature_t {
        sgx_ec256_signature_t {
            x: unsafe{transmute::<[u8;32],[u32;8]>(signature.x)},
            y: unsafe{transmute::<[u8;32],[u32;8]>(signature.y)},
        }
    }

    #[cfg(feature = "ring_support")]
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

impl Default for Rsa3072Signature {
    fn default() -> Self {
        Rsa3072Signature {
            signature: [0;384],
        }
    }
}

impl Default for Rsa3072PublicKey {
    fn default() -> Self {
        Rsa3072PublicKey {
            modulus: [0;384],
            exponent: [0; 4],
        }
    }
}

// #[derive(Serialize, Deserialize)]
// #[serde(remote = "sgx_rsa3072_signature_t")]
// struct _SgxRsa3072Signature {
//     #[serde(with = "BigArray")]
//     signature: [u8; 384],
// }
// 
// #[derive(Serialize, Deserialize)]
// #[serde(remote = "sgx_rsa3072_public_key_t")]
// struct _SgxRsa3072PublicKey {
//     #[serde(with = "BigArray")]
//     modulus: [u8; 384],
//     exponent: [u8; 4],
// }

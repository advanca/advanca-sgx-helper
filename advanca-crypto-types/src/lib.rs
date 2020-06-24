// Copyright (C) 2020 ADVANCA PTE. LTD.

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

#![cfg_attr(any(feature = "sgx_enclave"), no_std)]

#[cfg(feature = "sgx_enclave")]
#[macro_use]
extern crate sgx_tstd as std;

#[cfg(feature = "std_env")]
use serde;
#[cfg(feature = "std_env")]
use serde_big_array;

#[cfg(feature = "sgx_enclave")]
use serde_big_array_sgx as serde_big_array;
#[cfg(feature = "sgx_enclave")]
use serde_sgx as serde;

use serde::{Deserialize, Serialize};
use serde_big_array::big_array;

use std::string::String;
use std::vec::Vec;

#[cfg(feature = "openssl_support")]
use openssl::ec::EcKey;

#[cfg(feature = "ring_support")]
use ring::agreement;
#[cfg(feature = "ring_support")]
use ring::signature::{self, Signature};

use sgx_types::*;

use core::fmt;
use core::mem::transmute;
use std::error::Error;

big_array! { BigArray; }

#[cfg_attr(feature = "sgx_enclave", serde(crate = "serde_sgx"))]
#[derive(Debug, Serialize, Deserialize)]
pub enum CryptoError {
    InvalidMac,
    SgxError(u32, String),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CryptoError::InvalidMac => write!(f, "mac verification failed!"),
            CryptoError::SgxError(i, s) => write!(f, "{}: {}", i, s),
        }
    }
}

impl Error for CryptoError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

#[cfg_attr(feature = "sgx_enclave", serde(crate = "serde_sgx"))]
#[derive(
    Serialize, Deserialize, Default, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Copy, Clone,
)]
pub struct EphemeralKey {
    pub pubkey: Secp256r1PublicKey,
    pub signature: Secp256r1Signature,
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
#[derive(
    Serialize, Deserialize, Default, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Copy, Clone,
)]
pub struct Secp256r1PublicKey {
    pub gx: [u8; 32],
    pub gy: [u8; 32],
}

#[cfg_attr(feature = "sgx_enclave", serde(crate = "serde_sgx"))]
#[derive(
    Serialize, Deserialize, Default, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Copy, Clone,
)]
pub struct Secp256r1PrivateKey {
    pub r: [u8; 32],
}

#[cfg_attr(feature = "sgx_enclave", serde(crate = "serde_sgx"))]
#[derive(
    Serialize, Deserialize, Default, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Copy, Clone,
)]
pub struct Secp256r1Signature {
    pub x: [u8; 32],
    pub y: [u8; 32],
}

#[cfg_attr(feature = "sgx_enclave", serde(crate = "serde_sgx"))]
#[derive(
    Serialize, Deserialize, Default, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Copy, Clone,
)]
pub struct Aes128Key {
    pub key: [u8; 16],
}

#[cfg_attr(feature = "sgx_enclave", serde(crate = "serde_sgx"))]
#[derive(
    Serialize, Deserialize, Default, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Copy, Clone,
)]
pub struct Aes128Mac {
    pub mac: [u8; 16],
}

#[cfg_attr(feature = "sgx_enclave", serde(crate = "serde_sgx"))]
#[derive(Serialize, Deserialize, Default, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Clone)]
pub struct Aes128EncryptedMsg {
    pub iv: [u8; 12],
    pub mac: Aes128Mac,
    pub cipher: Vec<u8>,
}

#[cfg_attr(feature = "sgx_enclave", serde(crate = "serde_sgx"))]
#[derive(Serialize, Deserialize, Default, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Clone)]
pub struct Secp256r1SignedMsg {
    pub msg: Vec<u8>,
    pub signature: Secp256r1Signature,
}

#[cfg_attr(feature = "sgx_enclave", serde(crate = "serde_sgx"))]
#[derive(
    Serialize, Deserialize, Default, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Copy, Clone,
)]
pub struct AasRegRequest {
    pub worker_pubkey: Secp256r1PublicKey,
    pub mac: Aes128Mac,
}

#[cfg_attr(feature = "sgx_enclave", serde(crate = "serde_sgx"))]
#[derive(
    Serialize, Deserialize, Default, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Copy, Clone,
)]
pub struct AasRegReport {
    pub attested_time: u64,
    pub worker_pubkey: Secp256r1PublicKey,
    pub aas_signature: Secp256r1Signature,
}

#[cfg_attr(feature = "sgx_enclave", serde(crate = "serde_sgx"))]
#[derive(Serialize, Deserialize, Default, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Clone)]
pub struct AliveEvidence {
    pub magic_str: [u8; 8],
    pub task_id: Vec<u8>,
    pub block_hash: Vec<u8>,
    pub data_in: usize,
    pub data_out: usize,
}

#[cfg_attr(feature = "sgx_enclave", serde(crate = "serde_sgx"))]
#[derive(Serialize, Deserialize, Default, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Clone)]
pub struct AasTimestamp {
    pub timestamp: u64,
    pub data: Vec<u8>,
}

impl AasRegRequest {
    // worker_pubkey - 64
    // mac           - 16
    pub fn to_raw_bytes(&self) -> [u8; 80] {
        let mut bytes = [0_u8; 80];
        bytes[..64].copy_from_slice(&self.worker_pubkey.to_raw_bytes());
        bytes[64..].copy_from_slice(&self.mac.to_raw_bytes());
        bytes
    }

    pub fn to_check_bytes(&self) -> [u8; 64] {
        let mut bytes = [0_u8; 64];
        bytes.copy_from_slice(&self.to_raw_bytes()[..64]);
        bytes
    }
}

impl AasRegReport {
    // attested_time     - 8
    // worker_pubkey     - 64
    // aas_signature     - 64
    pub fn to_raw_bytes(&self) -> [u8; 136] {
        let mut bytes = [0_u8; 136];
        bytes[..8].copy_from_slice(&self.attested_time.to_le_bytes());
        bytes[8..72].copy_from_slice(&self.worker_pubkey.to_raw_bytes());
        bytes[72..].copy_from_slice(&self.aas_signature.to_raw_bytes());
        bytes
    }

    pub fn to_check_bytes(&self) -> [u8; 68] {
        let mut bytes = [0_u8; 68];
        bytes.copy_from_slice(&self.to_raw_bytes()[..68]);
        bytes
    }
}

impl Aes128Key {
    pub fn from_slice(byte_slice: &[u8]) -> Aes128Key {
        let mut buf = [0_u8; 16];
        buf.copy_from_slice(byte_slice);
        Aes128Key { key: buf }
    }

    pub fn to_raw_bytes(&self) -> [u8; 16] {
        self.key
    }
}

impl Aes128Mac {
    pub fn to_raw_bytes(&self) -> [u8; 16] {
        self.mac
    }
}

impl Secp256r1PublicKey {
    pub fn from_sgx_ec256_public(key: &sgx_ec256_public_t) -> Secp256r1PublicKey {
        Secp256r1PublicKey {
            gx: key.gx,
            gy: key.gy,
        }
    }

    pub fn to_sgx_ec256_public(&self) -> sgx_ec256_public_t {
        sgx_ec256_public_t {
            gx: self.gx,
            gy: self.gy,
        }
    }

    pub fn to_raw_bytes(&self) -> [u8; 64] {
        let mut bytes = [0_u8; 64];
        bytes[..32].copy_from_slice(&self.gx);
        bytes[32..].copy_from_slice(&self.gy);
        bytes
    }

    #[cfg(feature = "ring_support")]
    pub fn to_ring_agreement_key(&self) -> agreement::UnparsedPublicKey<Vec<u8>> {
        let buf = self.to_ring_bytes();
        agreement::UnparsedPublicKey::new(&agreement::ECDH_P256, buf.to_vec())
    }

    #[cfg(feature = "ring_support")]
    pub fn to_ring_signature_key(&self) -> signature::UnparsedPublicKey<Vec<u8>> {
        let buf = self.to_ring_bytes();
        signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, buf.to_vec())
    }

    pub fn to_ring_bytes(&self) -> [u8; 65] {
        let mut buf = [0_u8; 65];
        buf[0] = 4;
        buf[1..33].copy_from_slice(&self.gx);
        buf[1..33].reverse();
        buf[33..].copy_from_slice(&self.gy);
        buf[33..].reverse();
        buf
    }
}

impl Secp256r1PrivateKey {
    #[cfg(feature = "openssl_support")]
    pub fn from_der(der_bytes: &[u8]) -> Secp256r1PrivateKey {
        let eckey = EcKey::private_key_from_der(der_bytes).unwrap();
        let mut seed = [0_u8; 32];
        seed.copy_from_slice(eckey.private_key().to_vec().as_slice());
        seed.reverse();

        Secp256r1PrivateKey { r: seed }
    }

    pub fn from_sgx_ec256_private(key: &sgx_ec256_private_t) -> Secp256r1PrivateKey {
        Secp256r1PrivateKey { r: key.r }
    }

    pub fn to_sgx_ec256_private(&self) -> sgx_ec256_private_t {
        sgx_ec256_private_t { r: self.r }
    }

    pub fn to_raw_bytes(&self) -> [u8; 32] {
        let mut bytes = [0_u8; 32];
        bytes[..32].copy_from_slice(&self.r);
        bytes
    }
}

impl Secp256r1Signature {
    pub fn from_sgx_ec256_signature(sig: sgx_ec256_signature_t) -> Secp256r1Signature {
        Secp256r1Signature {
            x: unsafe { transmute::<[u32; 8], [u8; 32]>(sig.x) },
            y: unsafe { transmute::<[u32; 8], [u8; 32]>(sig.y) },
        }
    }

    pub fn to_sgx_ec256_signature(&self) -> sgx_ec256_signature_t {
        sgx_ec256_signature_t {
            x: unsafe { transmute::<[u8; 32], [u32; 8]>(self.x) },
            y: unsafe { transmute::<[u8; 32], [u32; 8]>(self.y) },
        }
    }

    #[cfg(feature = "ring_support")]
    pub fn from_ring_signature(ring_sig: &Signature) -> Secp256r1Signature {
        let ring_sig_buf = ring_sig.as_ref();
        assert_eq!(ring_sig_buf.len(), 64);

        let mut x: [u8; 32] = [0; 32];
        let mut y: [u8; 32] = [0; 32];
        x.copy_from_slice(&ring_sig_buf[..32]);
        y.copy_from_slice(&ring_sig_buf[32..]);
        x.reverse();
        y.reverse();
        Secp256r1Signature { x: x, y: y }
    }

    pub fn to_ring_signature_bytes(&self) -> [u8; 64] {
        let mut temp_buf: [u8; 64] = [0; 64];
        temp_buf[..32].copy_from_slice(&self.x);
        temp_buf[32..].copy_from_slice(&self.y);
        temp_buf[..32].reverse();
        temp_buf[32..].reverse();
        temp_buf
    }

    pub fn to_raw_bytes(&self) -> [u8; 64] {
        let mut bytes = [0_u8; 64];
        bytes[..32].copy_from_slice(&self.x);
        bytes[32..].copy_from_slice(&self.y);
        bytes
    }
}

impl Default for Rsa3072Signature {
    fn default() -> Self {
        Rsa3072Signature {
            signature: [0; 384],
        }
    }
}

impl Default for Rsa3072PublicKey {
    fn default() -> Self {
        Rsa3072PublicKey {
            modulus: [0; 384],
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

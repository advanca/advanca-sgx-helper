#[cfg(feature = "std_env")]
use serde;
#[cfg(feature = "std_env")]
use serde_big_array::big_array;

#[cfg(feature = "sgx_enclave")]
use serde_big_array_sgx::big_array;
#[cfg(feature = "sgx_enclave")]
use serde_sgx as serde;

#[cfg(feature = "substrate")]
use serde_big_array_substrate::big_array;
#[cfg(feature = "substrate")]
use serde_substrate as serde;

use serde::{Deserialize, Serialize};

use schnorrkel::keys::{PublicKey, SecretKey};
use schnorrkel::sign::Signature;

use sp_core::Pair;

use core::fmt;

#[cfg(feature = "substrate")]
use sp_std::prelude::*;

#[cfg(feature = "sgx_enclave")]
use sgx_tstd::prelude::v1::*;

big_array! { BigArray; }

#[cfg_attr(feature = "sgx_enclave", serde(crate = "serde_sgx"))]
#[cfg_attr(feature = "substrate", serde(crate = "serde_substrate"))]
#[derive(
    Serialize, Deserialize, Default, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Copy, Clone,
)]
pub struct Sr25519PrivateKey {
    pub secret: [u8; 32],
    pub nonce: [u8; 32],
}

#[cfg_attr(feature = "sgx_enclave", serde(crate = "serde_sgx"))]
#[cfg_attr(feature = "substrate", serde(crate = "serde_substrate"))]
#[derive(
    Serialize, Deserialize, Default, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Copy, Clone,
)]
pub struct Sr25519PublicKey {
    // compressed Ristretto form byte array
    pub compressed_point: [u8; 32],
}

#[cfg_attr(feature = "sgx_enclave", serde(crate = "serde_sgx"))]
#[cfg_attr(feature = "substrate", serde(crate = "serde_substrate"))]
#[derive(Serialize, Deserialize, Copy, Clone)]
pub struct Sr25519Signature {
    #[serde(with = "BigArray")]
    pub signature_bytes: [u8; 64],
}

#[cfg_attr(feature = "sgx_enclave", serde(crate = "serde_sgx"))]
#[cfg_attr(feature = "substrate", serde(crate = "serde_substrate"))]
#[derive(Serialize, Deserialize, Default, Debug, Clone)]
pub struct Sr25519SignedMsg<T: Serialize> {
    pub msg: T,
    pub signature: Sr25519Signature,
}

impl Sr25519PublicKey {
    pub fn from_schnorrkel_public(key: &PublicKey) -> Sr25519PublicKey {
        Sr25519PublicKey {
            compressed_point: key.to_bytes(),
        }
    }

    pub fn to_schnorrkel_public(&self) -> PublicKey {
        PublicKey::from_bytes(&self.compressed_point).expect("bytes to pubkey ok")
    }

    pub fn to_raw_bytes(&self) -> [u8; 32] {
        let mut bytes = [0_u8; 32];
        bytes[..].copy_from_slice(&self.compressed_point);
        bytes
    }
}

impl Sr25519PrivateKey {
    pub fn from_schnorrkel_private(key: &SecretKey) -> Sr25519PrivateKey {
        let bytes = key.to_bytes();
        let mut secret_bytes = [0_u8; 32];
        let mut nonce_bytes = [0_u8; 32];
        secret_bytes.copy_from_slice(&bytes[..32]);
        nonce_bytes.copy_from_slice(&bytes[32..]);
        Sr25519PrivateKey {
            secret: secret_bytes,
            nonce: nonce_bytes,
        }
    }

    pub fn to_schnorrkel_private(&self) -> SecretKey {
        SecretKey::from_bytes(&self.to_raw_bytes()).expect("secret key bytes ok!")
    }

    pub fn to_raw_bytes(&self) -> [u8; 64] {
        let mut bytes = [0_u8; 64];
        bytes[..32].copy_from_slice(&self.secret);
        bytes[32..].copy_from_slice(&self.nonce);
        bytes
    }
}

impl Sr25519Signature {
    pub fn from_schnorrkel_signature(signature: &Signature) -> Sr25519Signature {
        Sr25519Signature {
            signature_bytes: signature.to_bytes(),
        }
    }

    pub fn to_schnorrkel_signature(&self) -> Signature {
        Signature::from_bytes(&self.signature_bytes).expect("Sr25519Signature bytes ok!")
    }

    pub fn to_raw_bytes(&self) -> [u8; 64] {
        let mut bytes = [0_u8; 64];
        bytes[..].copy_from_slice(&self.signature_bytes);
        bytes
    }
}

impl Default for Sr25519Signature {
    fn default() -> Self {
        Sr25519Signature {
            signature_bytes: [0; 64],
        }
    }
}

impl fmt::Debug for Sr25519Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.signature_bytes[..].fmt(f)
    }
}

impl From<Sr25519PrivateKey> for SecretKey {
    fn from(item: Sr25519PrivateKey) -> Self {
        item.to_schnorrkel_private()
    }
}

impl From<SecretKey> for Sr25519PrivateKey {
    fn from(item: SecretKey) -> Self {
        Sr25519PrivateKey::from_schnorrkel_private(&item)
    }
}

impl From<Sr25519PublicKey> for PublicKey {
    fn from(item: Sr25519PublicKey) -> Self {
        item.to_schnorrkel_public()
    }
}

impl From<PublicKey> for Sr25519PublicKey {
    fn from(item: PublicKey) -> Self {
        Sr25519PublicKey::from_schnorrkel_public(&item)
    }
}

impl From<Sr25519Signature> for Signature {
    fn from(item: Sr25519Signature) -> Self {
        item.to_schnorrkel_signature()
    }
}

impl From<Signature> for Sr25519Signature {
    fn from(item: Signature) -> Self {
        Sr25519Signature::from_schnorrkel_signature(&item)
    }
}

impl From<Sr25519PrivateKey> for sp_core::sr25519::Pair {
    fn from(item: Sr25519PrivateKey) -> Self {
        let secret_key: SecretKey = item.into();
        secret_key.into()
    }
}

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

use serde;
use serde_big_array;

use serde::{Serialize, Deserialize};
use serde_big_array::big_array;

use std::error::Error;
use std::fmt;

big_array! { BigArray; }

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

#[derive(Serialize, Deserialize, Default)]
pub struct EphemeralKey {
    pub pubkey    : Secp256r1PublicKey,
    pub signature : Secp256r1Signature,
}

#[derive(Serialize, Deserialize)]
pub struct Rsa3072Signature {
    #[serde(with = "BigArray")]
    signature: [u8; 384],
}

#[derive(Serialize, Deserialize)]
pub struct Rsa3072PublicKey {
    #[serde(with = "BigArray")]
    modulus: [u8; 384],
    exponent: [u8; 4],
}

#[derive(Serialize, Deserialize, Default, Debug)]
pub struct Secp256r1PublicKey {
    pub gx: [u8; 32],
    pub gy: [u8; 32],
}

#[derive(Serialize, Deserialize, Default, Debug)]
pub struct Secp256r1PrivateKey {
    pub r: [u8; 32],
}

#[derive(Serialize, Deserialize, Default, Debug)]
pub struct Secp256r1Signature {
    pub x: [u8; 32],
    pub y: [u8; 32],
}

#[derive(Serialize, Deserialize, Default, Debug)]
pub struct AasRegReport {
    pub attested_time: u64,
    pub worker_pubkey: Secp256r1PublicKey,
    pub aas_signature: Secp256r1Signature,
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

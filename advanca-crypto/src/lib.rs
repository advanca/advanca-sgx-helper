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

#![cfg_attr(any(feature = "sgx_enclave"), no_std)]

#[cfg(feature = "sgx_enclave")]
#[macro_use]
extern crate sgx_tstd as std;

#[cfg(feature = "untrusted")]
extern crate sgx_ucrypto;

mod aes128;
mod enclave;
mod remote_attestation;
mod secp256k1;
mod secp256r1;
mod sr25519;

pub use aes128::*;
pub use remote_attestation::*;
pub use secp256k1::*;
pub use secp256r1::*;
pub use sr25519::*;

#[cfg(feature = "sgx_enclave")]
pub use enclave::*;

// mod test;
// pub use test::*;

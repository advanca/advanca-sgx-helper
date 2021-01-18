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

#![cfg_attr(any(feature = "sgx_enclave", feature = "substrate"), no_std)]

#[cfg(feature = "sgx_enclave")]
#[macro_use]
extern crate sgx_tstd as std;

mod aes128;
mod sr25519;
mod secp256r1;
mod secp256k1;
mod remote_attestation;
mod error;

pub use aes128::*;
pub use sr25519::*;
pub use secp256r1::*;
pub use secp256k1::*;
pub use remote_attestation::*;
pub use error::*;

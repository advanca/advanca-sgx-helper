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

#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

use sgx_types::*;

#[derive(Default, Copy, Clone)]
#[repr(C)]
pub struct CSgxEphemeralKey {
    pub pubkey: sgx_ec256_public_t,
    pub signature: sgx_ec256_signature_t,
}

#[derive(Default, Copy, Clone)]
#[repr(C)]
pub struct CAasRegRequest {
    pub pubkey: sgx_ec256_public_t,
    pub mac: sgx_cmac_128bit_tag_t,
}

#[derive(Default, Copy, Clone)]
#[repr(C)]
pub struct CAes128GcmMessage {
    pub iv: [u8; 12],
    pub cipher: [u8; 0],
}

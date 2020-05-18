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
    pub iv     : [u8;12],
    pub cipher : [u8;0],
}

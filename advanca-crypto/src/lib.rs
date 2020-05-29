#![cfg_attr(any(feature = "sgx_enclave"), no_std)]

#[cfg(feature = "sgx_enclave")]
#[macro_use]
extern crate sgx_tstd as std;

#[cfg(feature = "untrusted")]
extern crate sgx_ucrypto;

mod advanca_cryptolib;
pub use advanca_cryptolib::*;


//mod advanca_cryptolib_ring;
//
//#[cfg(test)]
//mod tests {
//    use crate::advanca_cryptolib_ring;
//    use crate::advanca_cryptolib;
//
//    use advanca_cryptolib::secp256r1_gen_keypair;
//    use advanca_cryptolib_ring::from_advanca_keypair;
//
//    // use ring::signature::*;
//    // use ring::rand::SystemRandom;
//    // use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING};
//
//    #[test]
//    fn ec256_signature_test() {
//        let (prvkey, pubkey) = secp256r1_gen_keypair().unwrap();
//        let ring_keypair = from_advanca_keypair(&prvkey, &pubkey);
//        println!("{:?}", ring_keypair);
//    }
//}

#![cfg_attr(feature="sgx_enclave", no_std)]

use sgx_types::*;
use advanca_crypto_types::*;

#[macro_export]
macro_rules! handle_sgx {
    ($expr:expr) => {
        {
            let s = $expr;
            if s != sgx_status_t::SGX_SUCCESS {
                Err(CryptoError::SgxError(format!("{}", s)))
            } else {
                Ok(())
            }
        }
    };
}


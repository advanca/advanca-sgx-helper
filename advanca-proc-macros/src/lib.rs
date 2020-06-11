use syn::{self, parse_macro_input};
use syn::Token;
use syn::Type::*;
use quote::quote;
use proc_macro::TokenStream;

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


#[cfg(feature = "std_env")]
use serde;
#[cfg(feature = "sgx_enclave")]
use serde_sgx as serde;
#[cfg(feature = "substrate")]
use serde_substrate as serde;

#[cfg(feature = "substrate")]
use sp_std::prelude::*;

use serde::{Deserialize, Serialize};

use core::fmt;

#[cfg(not(feature = "substrate"))]
use std::error::Error;
#[cfg(not(feature = "substrate"))]
use std::string::String;
// #[cfg(not(feature = "substrate"))]
// use std::vec::Vec;

#[cfg(not(feature = "substrate"))]
#[cfg_attr(feature = "sgx_enclave", serde(crate = "serde_sgx"))]
#[derive(Debug, Serialize, Deserialize)]
pub enum CryptoError {
    InvalidMac,
    SgxError(u32, String),
}

#[cfg(not(feature = "substrate"))]
impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CryptoError::InvalidMac => write!(f, "mac verification failed!"),
            CryptoError::SgxError(i, s) => write!(f, "{}: {}", i, s),
        }
    }
}

#[cfg(not(feature = "substrate"))]
impl Error for CryptoError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

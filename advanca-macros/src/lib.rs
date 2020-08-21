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

#![cfg_attr(feature = "sgx_enclave", no_std)]

// use sgx_types::*;
// use advanca_crypto_types::*;
//
#[macro_export]
macro_rules! handle_sgx {
    ($expr:expr) => {{
        let s = $expr;
        if s != sgx_status_t::SGX_SUCCESS {
            Err(CryptoError::SgxError(s.from_key(), format!("{}", s)))
        } else {
            Ok(())
        }
    }};
}

#[macro_export]
macro_rules! enclave_ret {
    ($expr:expr, $buf:expr, $bufsize:expr) => {{
        let obj = $expr;
        let mut buf_slice = core::slice::from_raw_parts_mut($buf, *$bufsize);
        let serialized_bytes = serde_json::to_vec(&obj).unwrap();
        let serialized_bytes_len = serialized_bytes.len();
        buf_slice[..serialized_bytes_len].copy_from_slice(serialized_bytes.as_slice());
        *$bufsize = serialized_bytes_len;
    }};
}

#[macro_export]
macro_rules! enclave_ret_protobuf {
    ($expr:expr, $buf:expr, $bufsize:expr) => {{
        let obj = $expr;
        let mut buf_slice = core::slice::from_raw_parts_mut($buf, *$bufsize);
        let obj_bytes = obj.write_to_bytes().unwrap();
        buf_slice[..obj_bytes.len()].copy_from_slice(&obj_bytes);
        *$bufsize = obj_bytes.len();
    }};
}

#[macro_export]
macro_rules! enclave_cryptoerr {
    ($expr:expr) => {{
        let s = $expr;
        match s {
            Ok(v) => v,
            Err(CryptoError::SgxError(i, _)) => return sgx_status_t::from_repr(i).unwrap(),
            _ => unreachable!(),
        }
    }};
}

#[macro_export]
macro_rules! handle_ecall {
    ($eid:expr, $func_name:ident ($($args:expr),*)) => {
        {
            let mut ret = sgx_status_t::SGX_SUCCESS;
            let ecall_ret = $func_name($eid, &mut ret, $($args),*);
            if ecall_ret != sgx_status_t::SGX_SUCCESS {
                Err(CryptoError::SgxError(ecall_ret.from_key(), format!("{}", ecall_ret)))
            } else if ret != sgx_status_t::SGX_SUCCESS {
                Err(CryptoError::SgxError(ret.from_key(), format!("{}", ret)))
            } else {
                Ok(())
            }
        }
    }
}

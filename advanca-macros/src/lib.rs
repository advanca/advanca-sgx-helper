#![cfg_attr(feature="sgx_enclave", no_std)]

// use sgx_types::*;
// use advanca_crypto_types::*;
// 
#[macro_export]
macro_rules! handle_sgx {
    ($expr:expr) => {
        {
            let s = $expr;
            if s != sgx_status_t::SGX_SUCCESS {
                Err(CryptoError::SgxError(s.from_key(), format!("{}", s)))
            } else {
                Ok(())
            }
        }
    };
}

#[macro_export]
macro_rules! enclave_ret {
    ($expr:expr, $buf:expr, $bufsize:expr) => {
        {
            let obj = $expr;
            let mut buf_slice = core::slice::from_raw_parts_mut($buf, *$bufsize);
            let writer = SliceWrite::new(&mut buf_slice);
            let mut ser = Serializer::new(writer);
            obj.serialize(&mut ser).unwrap();
            let writer = ser.into_inner();
            *$bufsize = writer.bytes_written();
        }
    }
}

#[macro_export]
macro_rules! enclave_cryptoerr {
    ($expr:expr) => {
        {
            let s = $expr;
            match s {
                Ok(v) => v,
                Err(CryptoError::SgxError(i,_)) => return sgx_status_t::from_repr(i).unwrap(),
                _ => unreachable!(),
            }
        }
    };
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

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

pub mod ias;

// TODO: Maybe we want to change this to no_std
// but it will make the usage pattern more complicated
pub use crate::sgx_ra::*;

mod sgx_ra {
    use core::mem::{size_of, transmute};
    use log::debug;
    use memoffset::offset_of;
    use sgx_types::*;

    use aes::Aes128;
    use cmac::{Cmac, Mac};
    use generic_array::GenericArray;
    use typenum::U16;

    use ring::signature::EcdsaKeyPair;
    use ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING;
    use ring::{agreement, rand};

    use crate::ias;

    use advanca_crypto::*;
    use advanca_crypto_ctypes::CAasRegRequest;
    use advanca_crypto_types::*;

    type KeyType = GenericArray<u8, U16>;

    pub struct SgxQuote {
        pub raw_quote: sgx_quote_t,
        pub signature: Vec<u8>,
    }

    pub struct SgxRaMsg3 {
        pub raw_ra_msg3: sgx_ra_msg3_t,
        pub quote: SgxQuote,
    }

    pub struct SgxReportBody {
        pub raw_sgx_report_body: sgx_report_body_t,
    }

    pub struct RaSession {
        svr_ecdsa_key: EcdsaKeyPair,
        spid: [u8; 16],
        ias_server: ias::IasServer,
        _session_state: SessionState,
        session_key: SessionKeys,
    }

    enum SessionState {
        Init,
        _ProcMsg0,
        _ProcMsg1,
        _ProcMsg3,
    }

    #[derive(Default)]
    struct SessionKeys {
        g_a: sgx_ec256_public_t,
        g_b: sgx_ec256_public_t,
        kdk: sgx_key_128bit_t,
        smk: sgx_key_128bit_t,
        sk: sgx_key_128bit_t,
        mk: sgx_key_128bit_t,
    }

    impl RaSession {
        pub fn get_smk(&self) -> sgx_key_128bit_t {
            self.session_key.smk
        }
    }

    /// Derive SMK, SK, MK, and VK according to
    /// https://software.intel.com/en-us/articles/code-sample-intel-software-guard-extensions-remote-attestation-end-to-end-example
    pub fn derive_secret_keys(kdk: &[u8]) -> (KeyType, KeyType, KeyType, KeyType) {
        let mut mac = Cmac::<Aes128>::new_varkey(kdk).unwrap();
        let smk_data = [0x01, 'S' as u8, 'M' as u8, 'K' as u8, 0x00, 0x80, 0x00];
        mac.input(&smk_data);
        let smk = mac.result_reset().code();

        let sk_data = [0x01, 'S' as u8, 'K' as u8, 0x00, 0x80, 0x00];
        mac.input(&sk_data);
        let sk = mac.result_reset().code();

        let mk_data = [0x01, 'M' as u8, 'K' as u8, 0x00, 0x80, 0x00];
        mac.input(&mk_data);
        let mk = mac.result_reset().code();

        let vk_data = [0x01, 'V' as u8, 'K' as u8, 0x00, 0x80, 0x00];
        mac.input(&vk_data);
        let vk = mac.result_reset().code();

        debug!("smk: {:02x?}", smk);
        debug!("sk : {:02x?}", sk);
        debug!("mk : {:02x?}", mk);
        debug!("vk : {:02x?}", vk);
        (smk, sk, mk, vk)
    }

    pub fn print_sgx_ec256_public_t(key: sgx_ec256_public_t) {
        println!("gx: {:02x?}", key.gx);
        println!("gy: {:02x?}", key.gy);
    }

    pub fn to_sgx_ec256_public_t(pubkey: agreement::PublicKey) -> sgx_ec256_public_t {
        let pubkey_ref = pubkey.as_ref();

        // the array is made of [4][gx][gy] where gx, gy are 32bytes each
        assert_eq!(65, pubkey_ref.len());

        // we only handle type 4 pubkeys.
        let pubkey_type = pubkey_ref[0];
        assert_eq!(4, pubkey_type);

        let mut result = sgx_ec256_public_t::default();

        // extract gx, gy
        let gx_be = pubkey_ref.get(1..33).unwrap();
        let gy_be = pubkey_ref.get(33..65).unwrap();

        // for ring, gx, gy are in big-endian format
        // for intel, gx, gy are in little-endian format
        result.gx.copy_from_slice(gx_be);
        result.gy.copy_from_slice(gy_be);

        result.gx.reverse();
        result.gy.reverse();

        result
    }

    pub fn to_ring_publickey(pubkey: sgx_ec256_public_t) -> agreement::UnparsedPublicKey<Vec<u8>> {
        let mut buf = vec![0_u8; 65];
        let mut gx_be = pubkey.gx;
        let mut gy_be = pubkey.gy;

        gx_be.reverse();
        gy_be.reverse();

        buf[0] = 4;
        buf[1..33].copy_from_slice(&gx_be);
        buf[33..65].copy_from_slice(&gy_be);
        agreement::UnparsedPublicKey::new(&agreement::ECDH_P256, buf)
    }

    pub fn sp_init_ra(
        svr_ecdsa_key_der: &[u8],
        ias_spid: &[u8],
        ias_apikey: &str,
        is_dev: bool,
    ) -> RaSession {
        let keypair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, svr_ecdsa_key_der).unwrap();
        let mut spid = [0; 16];
        spid.copy_from_slice(ias_spid);
        let ias_server = ias::IasServer::new(ias_apikey.trim(), is_dev);
        RaSession {
            svr_ecdsa_key: keypair,
            spid: spid,
            ias_server: ias_server,
            _session_state: SessionState::Init,
            session_key: SessionKeys::default(),
        }
    }

    pub fn sp_proc_ra_msg0(msg0_buf: &[u8]) -> bool {
        if msg0_buf == 0_u32.to_le_bytes() {
            true
        } else {
            false
        }
    }

    pub fn sp_proc_ra_msg1(msg1_slice: &[u8], session: &mut RaSession) -> Vec<u8> {
        let mut p_msg1_buf = [0_u8; size_of::<sgx_ra_msg1_t>()];
        p_msg1_buf.copy_from_slice(msg1_slice);
        let p_msg1: sgx_ra_msg1_t =
            unsafe { transmute::<[u8; size_of::<sgx_ra_msg1_t>()], sgx_ra_msg1_t>(p_msg1_buf) };
        // generate our own ephemeral keys for ecdh agreement
        let rng = rand::SystemRandom::new();
        let prv_key =
            agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rng).unwrap();
        let pub_key = prv_key.compute_public_key().unwrap();
        let pub_key_ref = pub_key.as_ref();
        debug!("own public key:");
        debug!("len of public key: {}", pub_key_ref.len());
        let g_b = to_sgx_ec256_public_t(pub_key);
        let g_a = p_msg1.g_a;
        session.session_key.g_a = g_a;
        session.session_key.g_b = g_b;
        //print_sgx_ec256_public_t(g_b);
        let g_a_ringpubkey = to_ring_publickey(p_msg1.g_a);
        let kdk = agreement::agree_ephemeral(
            prv_key,
            &g_a_ringpubkey,
            ring::error::Unspecified,
            |gab_x| {
                // agree_ephemeral outputs gab_x in big-endian format
                // sgx dev ref 2.9.1 states in page 374 that aes-cmac(key0, le(gab_x))
                let mut gab_x_le = [0_u8; 32];
                gab_x_le.copy_from_slice(gab_x);
                gab_x_le.reverse();
                let mut mac = Cmac::<Aes128>::new_varkey(&[0_u8; 16]).unwrap();
                mac.input(&gab_x_le);
                let result = mac.result();
                Ok(result.code())
            },
        )
        .unwrap();
        debug!("kdk: {:02x?}", kdk);
        let (smk, sk, mk, _vk) = derive_secret_keys(&kdk);
        session.session_key.kdk.copy_from_slice(&kdk);
        session.session_key.smk.copy_from_slice(&smk);
        session.session_key.sk.copy_from_slice(&sk);
        session.session_key.mk.copy_from_slice(&mk);

        // get sign_gb_ga
        let mut gb_ga: [u8; 128] = [0; 128];
        let gb_bytes =
            unsafe { transmute::<sgx_ec256_public_t, [u8; size_of::<sgx_ec256_public_t>()]>(g_b) };
        let ga_bytes =
            unsafe { transmute::<sgx_ec256_public_t, [u8; size_of::<sgx_ec256_public_t>()]>(g_a) };
        gb_ga[..64].copy_from_slice(&gb_bytes);
        gb_ga[64..].copy_from_slice(&ga_bytes);

        debug!("{:02x?}", &gb_ga[..32]);
        debug!("{:02x?}", &gb_ga[32..64]);
        debug!("{:02x?}", &gb_ga[64..96]);
        debug!("{:02x?}", &gb_ga[96..128]);

        let keypair = &session.svr_ecdsa_key;
        let sign_gb_ga = keypair.sign(&rng, &gb_ga).unwrap();

        let mut sig_x = [0_u8; 32];
        let mut sig_y = [0_u8; 32];

        // signature is of r || s where r, s are big-endian bigints
        // copy r to x
        sig_x.copy_from_slice(sign_gb_ga.as_ref().get(..32).unwrap());
        // copy s to y
        sig_y.copy_from_slice(sign_gb_ga.as_ref().get(32..).unwrap());

        // covert them to little-endian
        sig_x.reverse();
        sig_y.reverse();

        // convert to u32 array from u8 array
        let sig_x_u32 = unsafe { transmute::<[u8; 32], [u32; 8]>(sig_x) };
        let sig_y_u32 = unsafe { transmute::<[u8; 32], [u32; 8]>(sig_y) };

        let mut p_msg2 = sgx_ra_msg2_t::default();
        p_msg2.g_b = g_b;
        p_msg2.spid.id = session.spid;
        p_msg2.quote_type = 1_u16;
        p_msg2.kdf_id = 1_u16;
        p_msg2.sign_gb_ga.x.copy_from_slice(&sig_x_u32);
        p_msg2.sign_gb_ga.y.copy_from_slice(&sig_y_u32);

        // the mac is an aes-128 cmac over the p_msg2 structure from g_b till sign_gb_ga
        // using smk as the key
        //
        // g_b: sgx_ec256_public_t
        // spid: sgx_spid_t
        // quote_type: uint16_t
        // kdf_id: uint16_t
        // sign_gb_ga: sgx_ec256_signature_t
        // (remove) mac: sgx_mac_t
        // (remove) sig_rl_size: uint32_t
        // sig_rl: [uint8_t; 0]
        //
        let p_msg2_slice_size =
            size_of::<sgx_ra_msg2_t>() - (size_of::<sgx_mac_t>() + size_of::<uint32_t>());
        let p_msg2_bytes_slice = unsafe {
            core::slice::from_raw_parts(
                &p_msg2 as *const sgx_ra_msg2_t as *const u8,
                p_msg2_slice_size,
            )
        };
        let mut mac = Cmac::<Aes128>::new_varkey(&session.session_key.smk).unwrap();
        mac.input(p_msg2_bytes_slice);
        let result = mac.result().code();
        p_msg2.mac.copy_from_slice(&result);

        let sigrl = session.ias_server.get_sigrl(&p_msg1.gid);
        p_msg2.sig_rl_size = sigrl.len() as u32;

        // create the buffer for the full msg2 object
        let full_msg2_size = size_of::<sgx_ra_msg2_t>() + p_msg2.sig_rl_size as usize;
        let mut msg2_buf = vec![0; full_msg2_size];
        let msg2_slice = unsafe {
            core::slice::from_raw_parts(
                &p_msg2 as *const sgx_ra_msg2_t as *const u8,
                size_of::<sgx_ra_msg2_t>(),
            )
        };
        msg2_buf[..size_of::<sgx_ra_msg2_t>()].copy_from_slice(msg2_slice);
        msg2_buf[size_of::<sgx_ra_msg2_t>()..].copy_from_slice(sigrl.as_slice());
        msg2_buf
    }

    pub fn sp_proc_ra_msg3(msg3_slice: &[u8], session: &mut RaSession) -> ias::IasReportResponse {
        let msg3 = SgxRaMsg3::from_slice(msg3_slice).unwrap();
        // verify sgx_ra_msg3_t using derived smk as described in Intel's manual.
        msg3.verify(session.session_key.smk);
        let avr = session.ias_server.verify_quote(msg3.quote).unwrap();
        avr
    }

    pub fn sp_proc_aas_reg_request(
        reg_request: &CAasRegRequest,
        session: &RaSession,
    ) -> Result<AasRegReport, CryptoError> {
        let worker_mac_sgx = reg_request.mac;
        let p_data = &reg_request.pubkey as *const sgx_ec256_public_t as *const u8;
        let data_slice =
            unsafe { core::slice::from_raw_parts(p_data, size_of::<sgx_ec256_public_t>()) };

        let sk = session.session_key.sk;
        if aes_utils::aes128_cmac_verify(&sk, &data_slice, &worker_mac_sgx) {
            let mut result = AasRegReport::default();
            result.attested_time = std::time::SystemTime::now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            result.worker_pubkey = secp256r1_public::from_sgx_ec256_public(&reg_request.pubkey);
            let result = aas_utils::sign_aas_reg_report(result, &session.svr_ecdsa_key);
            Ok(result)
        } else {
            Err(CryptoError::InvalidMac)
        }
    }

    impl SgxRaMsg3 {
        pub fn verify(&self, smk: sgx_key_128bit_t) -> bool {
            let msg3_bytes = self.as_bytes();
            let msg3_content = msg3_bytes.get(size_of::<sgx_mac_t>()..).unwrap();
            let mut mac = Cmac::<Aes128>::new_varkey(&smk).unwrap();
            mac.input(msg3_content);
            match mac.verify(&self.raw_ra_msg3.mac) {
                Ok(()) => true,
                _ => false,
            }
        }

        pub fn from_slice(msg3_bytes: &[u8]) -> Option<SgxRaMsg3> {
            // We take in a vector of bytes representing the entire msg3.
            // As long as we work within the size of the vec, we're safe.

            // Ensure that the length of vec is at least sgx_ra_msg3_t + sgx_quote_t
            let quote_size = msg3_bytes.len() - size_of::<sgx_ra_msg3_t>();
            if quote_size < size_of::<sgx_quote_t>() {
                return None;
            }

            // TODO: Do some sanity check on the structure of sgx_ra_msg3_t
            // sanity_check(msg3);

            // Create a buffer for safety and copy quote object into it
            let mut quote_bytes: Vec<u8> = vec![0; quote_size];
            let msg3_bytes_ptr = msg3_bytes.as_ptr();
            let quote_bytes_ptr =
                unsafe { msg3_bytes_ptr.offset(size_of::<sgx_ra_msg3_t>() as isize) };
            let quote_slice = unsafe { core::slice::from_raw_parts(quote_bytes_ptr, quote_size) };
            quote_bytes.copy_from_slice(quote_slice);

            // Try to instantiate SgxQuote object
            if let Some(quote) = SgxQuote::from_bytes(quote_bytes) {
                let msg3 = SgxRaMsg3 {
                    raw_ra_msg3: unsafe { *(msg3_bytes_ptr as *const sgx_ra_msg3_t) },
                    quote: quote,
                };
                Some(msg3)
            } else {
                None
            }
        }

        pub fn as_bytes(&self) -> Vec<u8> {
            let msg3_size = size_of::<sgx_ra_msg3_t>() + self.quote.as_bytes().len();
            let mut msg3_bytes = vec![0_u8; msg3_size];
            let msg3_bytes_ptr = (&self.raw_ra_msg3 as *const sgx_ra_msg3_t) as *const u8;
            let msg3_bytes_slice =
                unsafe { core::slice::from_raw_parts(msg3_bytes_ptr, size_of::<sgx_ra_msg3_t>()) };
            msg3_bytes[..size_of::<sgx_ra_msg3_t>()].copy_from_slice(msg3_bytes_slice);
            msg3_bytes[size_of::<sgx_ra_msg3_t>()..]
                .copy_from_slice(self.quote.as_bytes().as_slice());
            msg3_bytes
        }
    }

    impl SgxQuote {
        pub fn get_report_body(&self) -> sgx_report_body_t {
            self.raw_quote.report_body
        }

        pub fn get_mr_enclave(&self) -> [u8; 32] {
            self.raw_quote.report_body.mr_enclave.m
        }

        pub fn get_mr_signer(&self) -> [u8; 32] {
            self.raw_quote.report_body.mr_signer.m
        }

        pub fn get_attributes(&self) -> sgx_attributes_t {
            self.raw_quote.report_body.attributes
        }

        pub fn get_isv_prod_id(&self) -> sgx_prod_id_t {
            self.raw_quote.report_body.isv_prod_id
        }

        pub fn get_isv_svn(&self) -> sgx_isv_svn_t {
            self.raw_quote.report_body.isv_svn
        }

        pub fn is_enclave_debug(&self) -> bool {
            self.raw_quote.report_body.attributes.flags & SGX_FLAGS_DEBUG != 0
        }

        pub fn is_enclave_init(&self) -> bool {
            self.raw_quote.report_body.attributes.flags & SGX_FLAGS_INITTED != 0
        }

        pub fn from_isv_bytes(quote_bytes: Vec<u8>) -> Option<SgxQuote> {
            // Check that quote_bytes is sgx_quote_t up till report_body
            if offset_of!(sgx_quote_t, signature_len) != quote_bytes.len() {
                return None;
            }
            let mut raw_quote_buf = [0_u8; size_of::<sgx_quote_t>()];
            raw_quote_buf[..offset_of!(sgx_quote_t, signature_len)].copy_from_slice(&quote_bytes);
            let quote = SgxQuote {
                raw_quote: unsafe {
                    transmute::<[u8; size_of::<sgx_quote_t>()], sgx_quote_t>(raw_quote_buf)
                },
                signature: Vec::new(),
            };
            Some(quote)
        }

        pub fn from_bytes(quote_bytes: Vec<u8>) -> Option<SgxQuote> {
            // Check that quote_bytes is at least sgx_quote_t large
            let actual_sig_size: i32 = quote_bytes.len() as i32 - size_of::<sgx_quote_t>() as i32;
            if actual_sig_size < 0 {
                return None;
            }

            let raw_quote = unsafe { *(quote_bytes.as_ptr() as *const sgx_quote_t) };
            if actual_sig_size as usize != raw_quote.signature_len as usize {
                return None;
            }

            let mut signature: Vec<u8> = vec![0; raw_quote.signature_len as usize];
            signature.copy_from_slice(&quote_bytes[size_of::<sgx_quote_t>()..]);

            let quote = SgxQuote {
                raw_quote: raw_quote,
                signature: signature,
            };
            Some(quote)
        }

        pub fn as_bytes(&self) -> Vec<u8> {
            let quote_size = size_of::<sgx_quote_t>() + self.signature.len();
            let mut quote_bytes = vec![0_u8; quote_size];
            let quote_bytes_ptr = (&self.raw_quote as *const sgx_quote_t) as *const u8;
            let quote_bytes_slice =
                unsafe { core::slice::from_raw_parts(quote_bytes_ptr, size_of::<sgx_quote_t>()) };
            quote_bytes[..size_of::<sgx_quote_t>()].copy_from_slice(quote_bytes_slice);
            quote_bytes[size_of::<sgx_quote_t>()..].copy_from_slice(self.signature.as_slice());
            quote_bytes
        }
    }
}

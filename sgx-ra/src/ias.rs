use serde::{Serialize, Deserialize};
use serde_json;
use reqwest;
use base64;
use base16;

use rand::{thread_rng, Rng};
use rand::distributions::Alphanumeric;

use strum_macros::{Display, EnumString};
use std::str::FromStr;

use std::error::Error;

use crate::sgx_ra::SgxQuote;


pub struct IasServer {
    api_key: String,
    base_url: &'static str,
}

impl IasServer {
    pub fn new(apikey: &str, is_dev: bool) -> IasServer {
        let base_url = if is_dev {
            "https://api.trustedservices.intel.com/sgx/dev"
        } else {
            "https://api.trustedservices.intel.com/sgx"
        };
        IasServer {
            api_key: String::from(apikey),
            base_url: base_url,
        }
    }

    pub fn verify_quote (&self, quote: SgxQuote) -> Result<IasReportResponse, Box<dyn Error>> {
        let quote_bytes = quote.as_bytes();

        // get a random nonce
        let random_nonce: String = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(32)
            .collect();

        let report_request = IasReportRequest {
            isv_enclave_quote: base64::encode(quote_bytes),
            nonce: Some(random_nonce),
        };
        let report_request_json = serde_json::to_string(&report_request).unwrap();


        let api_url = format!("{}/attestation/v4/report", self.base_url);
        let client = reqwest::blocking::Client::new();
        let res = client.post(&api_url)
            .header("Content-Type", "application/json")
            .header("Ocp-Apim-Subscription-Key", self.api_key.as_str())
            .body(report_request_json)
            .send()?;
        let avr_json = res.text()?;
        let avr: IasReportResponse = serde_json::from_str(&avr_json)?;
        Ok(avr)
    }

    pub fn get_sigrl (&self, gid: &[u8;4]) -> Vec<u8> {
        let mut gid_be = [0_u8;4];
        gid_be.copy_from_slice(gid);
        gid_be.reverse();
        let gid_base16 = base16::encode_lower(&gid_be);
        let api_url = format!("{}/attestation/v4/sigrl/{}", self.base_url, gid_base16);
        let client = reqwest::blocking::Client::new();
        let res = client.get(&api_url)
            .header("Ocp-Apim-Subscription-Key", self.api_key.as_str())
            .send().unwrap();
        let sigrl_base64 = res.text().unwrap();
        base64::decode(sigrl_base64).unwrap()
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct IasReportRequest {
    pub isv_enclave_quote: String,
    pub nonce: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct IasReportResponse {
    pub id                          : String,
    pub timestamp                   : String,
    pub version                     : u32,
    pub isv_enclave_quote_status    : String,
    pub isv_enclave_quote_body      : String,
    pub revocation_reason           : Option<String>,
    pub pse_manifest_status         : Option<String>,
    pub pse_manifest_hash           : Option<String>,
    pub platform_info_blob          : Option<String>,
    pub nonce                       : Option<String>,
    pub epid_pseudonym              : Option<String>,
    #[serde(rename(serialize    = "advisoryURL"))]
    #[serde(rename(deserialize  = "advisoryURL"))]
    pub advisory_url                : Option<String>,
    #[serde(rename(serialize    = "advisoryIDs"))]
    #[serde(rename(deserialize  = "advisoryIDs"))]
    pub advisory_ids                : Option<Vec<String>>,
}

impl IasReportResponse {
    pub fn get_isv_enclave_quote_body(&self) -> SgxQuote {
        let isv_enclave_quote_body = base64::decode(&self.isv_enclave_quote_body).unwrap();
        // size of sgx_quote_t is 436 bytes, 
        // isv_enclave_quote_body don't have signature and signature len
        SgxQuote::from_isv_bytes(isv_enclave_quote_body).unwrap()
    }

    pub fn get_isv_enclave_quote_status(&self) -> String {
        self.isv_enclave_quote_status.to_owned()
    }

    pub fn is_enclave_secure(&self, allow_conditional: bool) -> bool {
        use EnclaveQuoteStatus::*;

        let isv_enclave_quote_status = EnclaveQuoteStatus::from_str(&self.isv_enclave_quote_status).unwrap();
        let is_secure = match isv_enclave_quote_status {
            Ok                                => true,
            SignatureInvalid                  => false,
            GroupRevoked                      => false,
            SignatureRevoked                  => false,
            KeyRevoked                        => false,
            SigrlVersionMismatch              => false,
            // the following items are conditionally "secure"
            GroupOutOfDate                    => allow_conditional,
            ConfigurationNeeded               => allow_conditional,
            SwHardeningNeeded                 => allow_conditional,
            ConfigurationAndSwHardeningNeeded => allow_conditional,
        };
        is_secure
    }
}

#[derive(Display, EnumString)]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
enum EnclaveQuoteStatus {
    Ok,
    SignatureInvalid,
    GroupRevoked,
    SignatureRevoked,
    KeyRevoked,
    SigrlVersionMismatch,
    GroupOutOfDate,
    ConfigurationNeeded,
    SwHardeningNeeded,
    ConfigurationAndSwHardeningNeeded,
}



#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}

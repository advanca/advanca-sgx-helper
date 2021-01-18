#[cfg(feature = "std_env")]
use sgx_ucrypto::sgx_read_rand;

#[cfg(feature = "sgx_enclave")]
use sgx_types::sgx_read_rand;

use advanca_types::*;

use sgx_types::*;

use rand::rngs::StdRng;
use rand::SeedableRng;
use schnorrkel;

use advanca_macros::handle_sgx;

const SIGNING_CONTEXT: &[u8] = b"substrate";

pub fn sr25519_gen_keypair() -> Result<(Sr25519PrivateKey, Sr25519PublicKey), CryptoError> {
    let mut seed_bytes = [0_u8; 32];
    unsafe {
        handle_sgx!(sgx_read_rand(seed_bytes.as_mut_ptr(), seed_bytes.len()))?;
    }
    let rng: StdRng = SeedableRng::from_seed(seed_bytes);
    let sr25519_keypair = schnorrkel::Keypair::generate_with(rng);
    let sr25519_pubkey = Sr25519PublicKey::from_schnorrkel_public(&sr25519_keypair.public);
    let sr25519_prvkey = Sr25519PrivateKey::from_schnorrkel_private(&sr25519_keypair.secret);
    Ok((sr25519_prvkey, sr25519_pubkey))
}

pub fn sr25519_sign_msg(
    prvkey: &Sr25519PrivateKey,
    msg: &[u8],
) -> Result<Sr25519SignedMsg, CryptoError> {
    let mut seed_bytes = [0_u8; 32];
    unsafe {
        handle_sgx!(sgx_read_rand(seed_bytes.as_mut_ptr(), seed_bytes.len()))?;
    }
    let rng: StdRng = SeedableRng::from_seed(seed_bytes);
    let secretkey = prvkey.to_schnorrkel_private();
    let context = schnorrkel::signing_context(SIGNING_CONTEXT);
    let signature = secretkey.sign(
        schnorrkel::context::attach_rng(context.bytes(msg), rng),
        &secretkey.to_public(),
    );
    Ok(Sr25519SignedMsg {
        msg: msg.to_vec(),
        signature: Sr25519Signature::from_schnorrkel_signature(&signature),
    })
}

pub fn sr25519_verify_msg(
    pubkey: &Sr25519PublicKey,
    signed_msg: &Sr25519SignedMsg,
) -> Result<bool, CryptoError> {
    sr25519_verify_signature(pubkey, &signed_msg.msg, &signed_msg.signature)
}

pub fn sr25519_verify_signature(
    pubkey: &Sr25519PublicKey,
    msg: &[u8],
    signature: &Sr25519Signature,
) -> Result<bool, CryptoError> {
    let context = schnorrkel::signing_context(SIGNING_CONTEXT);
    let schnorrkel_pubkey = pubkey.to_schnorrkel_public();
    let schnorrkel_signature = signature.to_schnorrkel_signature();
    Ok(schnorrkel_pubkey
        .verify(context.bytes(msg), &schnorrkel_signature)
        .is_ok())
}


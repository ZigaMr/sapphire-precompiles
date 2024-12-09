use ethabi::{ParamType, Token};
use rand::Rng;
use hex;
use std::{env, process};
use oasis_runtime_sdk::{
    core::common::crypto::mrae::deoxysii::{DeoxysII, KEY_SIZE, NONCE_SIZE},
    crypto::signature::{self, SignatureType},
};
use hmac::{Hmac, Mac};
use sha2::{Sha512_256, digest::KeyInit};

const WORD: usize = 32;

fn decode_deoxysii_args(input: &[u8]) -> Result<([u8; KEY_SIZE], [u8; NONCE_SIZE], Vec<u8>, Vec<u8>), String> {
    let call_args = ethabi::decode(
        &[
            ParamType::FixedBytes(32), // key
            ParamType::FixedBytes(32), // nonce
            ParamType::Bytes,          // plain or ciphertext
            ParamType::Bytes,          // associated data
        ],
        input,
    ).map_err(|e| e.to_string())?;

    let ad = call_args[3].clone().into_bytes().unwrap();
    let text = call_args[2].clone().into_bytes().unwrap();
    let nonce_bytes = call_args[1].clone().into_fixed_bytes().unwrap();
    let key_bytes = call_args[0].clone().into_fixed_bytes().unwrap();

    let mut nonce = [0u8; NONCE_SIZE];
    nonce.copy_from_slice(&nonce_bytes[..NONCE_SIZE]);
    let mut key = [0u8; KEY_SIZE];
    key.copy_from_slice(&key_bytes[..KEY_SIZE]);

    Ok((key, nonce, text, ad))
}

fn handle_random_bytes(input: &[u8]) -> Result<Vec<u8>, String> {
    let call_args = ethabi::decode(
        &[ParamType::Uint(256), ParamType::Bytes],
        input,
    ).map_err(|e| e.to_string())?;

    let pers_str = call_args[1].clone().into_bytes().unwrap();
    let num_bytes: u64 = call_args[0].clone().into_uint().unwrap().try_into().unwrap_or(u64::MAX);

    let mut rng = rand::thread_rng();
    let mut result = Vec::with_capacity(num_bytes as usize);
    for _ in 0..num_bytes {
        result.push(rng.gen());
    }

    Ok(result)
}

fn handle_x25519_derive(input: &[u8]) -> Result<Vec<u8>, String> {
    if input.len() != 2 * WORD {
        return Err("input length must be 64 bytes".into());
    }

    let mut public = [0u8; WORD];
    let mut private = [0u8; WORD];
    
    public.copy_from_slice(&input[0..WORD]);
    private.copy_from_slice(&input[WORD..]);

    let public = x25519_dalek::PublicKey::from(public);
    let private = x25519_dalek::StaticSecret::from(private);

    let mut kdf = <Hmac<Sha512_256> as Mac>::new_from_slice(b"MRAE_Box_Deoxys-II-256-128")
        .map_err(|e| e.to_string())?;
    kdf.update(private.diffie_hellman(&public).as_bytes());

    let mut derived_key = [0u8; KEY_SIZE];
    let digest = kdf.finalize();
    derived_key.copy_from_slice(&digest.into_bytes()[..KEY_SIZE]);

    Ok(derived_key.to_vec())
}

fn handle_curve25519_compute_public(input: &[u8]) -> Result<Vec<u8>, String> {
    if input.len() != WORD {
        return Err("input length must be 32 bytes".into());
    }

    let private = <&[u8; WORD]>::try_from(input).unwrap();
    let secret = x25519_dalek::StaticSecret::from(*private);
    Ok(x25519_dalek::PublicKey::from(&secret).as_bytes().to_vec())
}

fn handle_deoxysii_seal(input: &[u8]) -> Result<Vec<u8>, String> {
    let (key, nonce, text, ad) = decode_deoxysii_args(input)?;
    let deoxysii = DeoxysII::new(&key);
    Ok(deoxysii.seal(&nonce, text, ad))
}

fn handle_deoxysii_open(input: &[u8]) -> Result<Vec<u8>, String> {
    let (key, nonce, ciphertext, ad) = decode_deoxysii_args(input)?;
    let deoxysii = DeoxysII::new(&key);
    deoxysii.open(&nonce, ciphertext, ad).map_err(|_| "decryption failed".into())
}

fn handle_keypair_generate(input: &[u8]) -> Result<Vec<u8>, String> {
    let call_args = ethabi::decode(
        &[
            ParamType::Uint(256), // method
            ParamType::Bytes,     // seed
        ],
        input,
    ).map_err(|e| e.to_string())?;

    let seed = call_args[1].clone().into_bytes().unwrap();
    let method: u8 = call_args[0]
        .clone()
        .into_uint()
        .unwrap()
        .try_into()
        .map_err(|_| "method identifier out of bounds")?;

    let sig_type: SignatureType = method
        .try_into()
        .map_err(|_| "unknown signature type")?;

    let signer = signature::MemorySigner::new_from_seed(sig_type, &seed)
        .map_err(|e| format!("error creating signer: {}", e))?;
    
    let public = signer.public_key().as_bytes().to_vec();
    let private = signer.to_bytes();

    Ok(ethabi::encode(&[Token::Bytes(public), Token::Bytes(private)]))
}

fn handle_sign(input: &[u8]) -> Result<Vec<u8>, String> {
    let call_args = ethabi::decode(
        &[
            ParamType::Uint(256), // signature type
            ParamType::Bytes,     // private key
            ParamType::Bytes,     // context
            ParamType::Bytes,     // message
        ],
        input,
    ).map_err(|e| e.to_string())?;

    let message = call_args[3].clone().into_bytes().unwrap();
    let context = call_args[2].clone().into_bytes().unwrap();
    let pk = call_args[1].clone().into_bytes().unwrap();
    let method: u8 = call_args[0]
        .clone()
        .into_uint()
        .unwrap()
        .try_into()
        .map_err(|_| "signature type identifier out of bounds")?;

    let sig_type: SignatureType = method
        .try_into()
        .map_err(|_| "unknown signature type")?;

    let signer = signature::MemorySigner::from_bytes(sig_type, &pk)
        .map_err(|e| format!("error creating signer: {}", e))?;

    let result = signer.sign_by_type(sig_type, &context, &message)
        .map_err(|e| format!("error signing message: {}", e))?;

    Ok(result.into())
}

fn handle_verify(input: &[u8]) -> Result<Vec<u8>, String> {
    let call_args = ethabi::decode(
        &[
            ParamType::Uint(256), // signature type
            ParamType::Bytes,     // public key
            ParamType::Bytes,     // context
            ParamType::Bytes,     // message
            ParamType::Bytes,     // signature
        ],
        input,
    ).map_err(|e| e.to_string())?;

    let signature = call_args[4].clone().into_bytes().unwrap();
    let message = call_args[3].clone().into_bytes().unwrap();
    let context = call_args[2].clone().into_bytes().unwrap();
    let pk = call_args[1].clone().into_bytes().unwrap();
    let method: u8 = call_args[0]
        .clone()
        .into_uint()
        .unwrap()
        .try_into()
        .map_err(|_| "signature type identifier out of bounds")?;

    let sig_type: SignatureType = method
        .try_into()
        .map_err(|_| "unknown signature type")?;

    let signature: signature::Signature = signature.into();
    let public_key = signature::PublicKey::from_bytes(sig_type, &pk)
        .map_err(|_| "error reading public key")?;

    let result = public_key.verify_by_type(sig_type, &context, &message, &signature);
    Ok(ethabi::encode(&[Token::Bool(result.is_ok())]))
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <hex-encoded input>", args[0]);
        process::exit(1);
    }

    let input_hex = args[1].trim_start_matches("0x");
    
    let input = hex::decode(input_hex).unwrap_or_else(|e| {
        eprintln!("Failed to decode hex input: {}", e);
        process::exit(1);
    });

    let binary_name = args[0].clone();
    let result = match binary_name.split('/').last().unwrap_or(&binary_name) {
        "random_bytes" => handle_random_bytes(&input),
        "x25519_derive" => handle_x25519_derive(&input),
        "curve25519_compute_public" => handle_curve25519_compute_public(&input),
        "deoxysii_seal" => handle_deoxysii_seal(&input),
        "deoxysii_open" => handle_deoxysii_open(&input),
        "keypair_generate" => handle_keypair_generate(&input),
        "sign" => handle_sign(&input),
        "verify" => handle_verify(&input),
        _ => Err("Unknown precompile".into()),
    };

    match result {
        Ok(output) => {
            print!("{}", hex::encode(output));
            process::exit(0);
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            process::exit(1);
        }
    }
}
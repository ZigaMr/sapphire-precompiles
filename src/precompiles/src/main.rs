use hmac::{Hmac, Mac};
use std::env;
use x25519_dalek::{PublicKey, StaticSecret};
use sha2::{Sha256, Sha384, Sha512, Sha512_256, Digest};
use sha3::Keccak256;
use ethabi::{ParamType, Token};
use deoxysii::{DeoxysII, KEY_SIZE, NONCE_SIZE, TAG_SIZE};

// const KEY_SIZE: usize = 32;
// const NONCE_SIZE: usize = 32;
const RNG_MAX_BYTES: u64 = 1024;
const WORD: usize = 32;


fn handle_random_bytes() {
    // Get hex encoded input from args
    let raw_input = env::args().nth(1).expect("Missing input hex");

    // Check if the input has the "0x" prefix and remove it if present
    let input = if raw_input.starts_with("0x") {
        hex::decode(&raw_input[2..]).expect("Invalid hex input")
    } else {
        hex::decode(raw_input).expect("Invalid hex input")
    };

    // Decode input parameters: (uint256 num_bytes, bytes personalization)
    let call_args = ethabi::decode(
        &[ParamType::Uint(256), ParamType::Bytes],
        &input
    ).expect("Failed to decode input");

    // Extract parameters
    let pers_str = call_args[1].clone().into_bytes().unwrap();
    let num_bytes_big = call_args[0].clone().into_uint().unwrap();
    let num_bytes = std::cmp::min(num_bytes_big.as_u64(), RNG_MAX_BYTES);

    // Generate random bytes
    let mut kdf = Hmac::<Sha512_256>::new_from_slice(
        format!("{:?}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()).as_bytes()
    ).expect("HMAC init failed");
    kdf.update(&pers_str);
    
    let digest = kdf.finalize();
    let output = &digest.into_bytes()[..num_bytes as usize];

    // Print hex-encoded result
    print!("{}", hex::encode(output));
}

fn handle_x25519_derive() {
    // Get hex encoded input from args
    let raw_input = env::args().nth(1).expect("Missing input hex");
    
    // Check if the input has the "0x" prefix and remove it if present
    let input = if raw_input.starts_with("0x") {
        hex::decode(&raw_input[2..]).expect("Invalid hex input")
    } else {
        hex::decode(raw_input).expect("Invalid hex input")
    };

    // Input should be exactly two 32-byte values concatenated (public key || private key)
    if input.len() != 2 * WORD {
        eprintln!("input length must be 64 bytes");
        std::process::exit(1);
    }

    // Split input into public and private keys
    let mut public = [0u8; WORD];
    let mut private = [0u8; WORD];
    public.copy_from_slice(&input[0..WORD]);
    private.copy_from_slice(&input[WORD..]);

    // Convert to x25519 types
    let public = PublicKey::from(public);
    let private = StaticSecret::from(private);

    // Create KDF with MRAE_Box_Deoxys-II-256-128 as context
    let mut kdf = Hmac::<Sha512_256>::new_from_slice(b"MRAE_Box_Deoxys-II-256-128")
        .expect("HMAC initialization failed");
    
    // Perform Diffie-Hellman and update KDF
    kdf.update(private.diffie_hellman(&public).as_bytes());

    // Derive final key
    let mut derived_key = [0u8; 32]; // KEY_SIZE
    let digest = kdf.finalize();
    derived_key.copy_from_slice(&digest.into_bytes()[..32]);

    // Print hex-encoded result without newline
    print!("{}", hex::encode(derived_key));
}

fn handle_deoxysii_seal() {
    let raw_input = env::args().nth(1).expect("Missing input hex");
    let input = if raw_input.starts_with("0x") {
        hex::decode(&raw_input[2..]).expect("Invalid hex input")
    } else {
        hex::decode(raw_input).expect("Invalid hex input")
    };

    let (key, nonce, plaintext, ad) = decode_deoxysii_args(&input)
        .expect("Failed to decode deoxysii arguments");

    // Create a new Deoxys-II instance with our key
    // Deoxys-II-256-128 uses a 32-byte key
    let deoxysii = DeoxysII::new(&key);

    // The seal operation will:
    // 1. Encrypt the plaintext
    // 2. Compute an authentication tag over the ciphertext and associated data
    // 3. Return the concatenation of ciphertext and tag
    let ciphertext = deoxysii.seal(&nonce, plaintext, ad);

    // Output the hex-encoded ciphertext + tag
    print!("{}", hex::encode(ciphertext));
}

fn handle_deoxysii_open() {
    let raw_input = env::args().nth(1).expect("Missing input hex");
    let input = if raw_input.starts_with("0x") {
        hex::decode(&raw_input[2..]).expect("Invalid hex input")
    } else {
        hex::decode(raw_input).expect("Invalid hex input")
    };

    // We use the same decoding function as seal, since the parameter format is identical
    let (key, nonce, ciphertext, ad) = decode_deoxysii_args(&input)
        .expect("Failed to decode deoxysii arguments");

    // Create the Deoxys-II instance with our key
    let deoxysii = DeoxysII::new(&key);

    // The SDK makes an explicit copy of the ciphertext before passing it to open
    let ciphertext = ciphertext.to_vec();

    // Match the error handling pattern from the SDK:
    // - On success: return the decrypted data
    // - On failure: exit with status code 1 (matching the Revert behavior)
    match deoxysii.open(&nonce, ciphertext, ad) {
        Ok(decrypted) => print!("{}", hex::encode(decrypted)),
        Err(_) => std::process::exit(1)
    }
}

fn handle_curve25519_compute_public() {
    let raw_input = env::args().nth(1).expect("Missing input hex");
    let input = if raw_input.starts_with("0x") {
        hex::decode(&raw_input[2..]).expect("Invalid hex input")
    } else {
        hex::decode(raw_input).expect("Invalid hex input")
    };

    if input.len() != WORD {
        eprintln!("input length must be 32 bytes");
        std::process::exit(1);
    }

    let private = <&[u8; WORD]>::try_from(&input[..]).unwrap();
    let secret = StaticSecret::from(*private);
    
    print!("{}", hex::encode(PublicKey::from(&secret).as_bytes()));
}

fn decode_deoxysii_args(input: &[u8]) -> Result<([u8; KEY_SIZE], [u8; NONCE_SIZE], Vec<u8>, Vec<u8>), String> {
    let mut call_args = ethabi::decode(
        &[
            ParamType::FixedBytes(32), // key
            ParamType::FixedBytes(32), // nonce
            ParamType::Bytes,          // plain or ciphertext
            ParamType::Bytes,          // associated data
        ],
        input,
    ).map_err(|e| e.to_string())?;
    
    // Extract in reverse order to match SDK implementation
    let ad = call_args.pop().unwrap().into_bytes().unwrap();
    let text = call_args.pop().unwrap().into_bytes().unwrap();
    let nonce_bytes = call_args.pop().unwrap().into_fixed_bytes().unwrap();
    let key_bytes = call_args.pop().unwrap().into_fixed_bytes().unwrap();

    let mut nonce = [0u8; NONCE_SIZE];
    nonce.copy_from_slice(&nonce_bytes[..NONCE_SIZE]);
    let mut key = [0u8; KEY_SIZE];
    key.copy_from_slice(&key_bytes);

    Ok((key, nonce, text, ad))
}

fn handle_keypair_generate() {
    let raw_input = env::args().nth(1).expect("Missing input hex");
    let input = if raw_input.starts_with("0x") {
        hex::decode(&raw_input[2..]).expect("Invalid hex input")
    } else {
        hex::decode(raw_input).expect("Invalid hex input")
    };

    let call_args = ethabi::decode(
        &[
            ParamType::Uint(256), // signature type
            ParamType::Bytes,     // seed
        ],
        &input,
    ).expect("Failed to decode input");

    let sig_type = call_args[0].clone().into_uint().unwrap().as_u64();
    let seed = call_args[1].clone().into_bytes().unwrap();

    // TODO: For now return dummy keypair
    let result = ethabi::encode(&[
        Token::Bytes(vec![1u8; 32]), // public key
        Token::Bytes(vec![2u8; 32]), // private key
    ]);

    print!("{}", hex::encode(result));
}

fn handle_sign() {
    let raw_input = env::args().nth(1).expect("Missing input hex");
    let input = if raw_input.starts_with("0x") {
        hex::decode(&raw_input[2..]).expect("Invalid hex input")
    } else {
        hex::decode(raw_input).expect("Invalid hex input")
    };

    let call_args = ethabi::decode(
        &[
            ParamType::Uint(256), // signature type
            ParamType::Bytes,     // private key
            ParamType::Bytes,     // context/hash
            ParamType::Bytes,     // message
        ],
        &input,
    ).expect("Failed to decode input");

    let sig_type = call_args[0].clone().into_uint().unwrap().as_u64();
    let private_key = call_args[1].clone().into_bytes().unwrap();
    let context = call_args[2].clone().into_bytes().unwrap();
    let message = call_args[3].clone().into_bytes().unwrap();

    // TODO: For now return dummy signature
    print!("{}", hex::encode(vec![3u8; 64]));
}

fn handle_verify() {
    let raw_input = env::args().nth(1).expect("Missing input hex");
    let input = if raw_input.starts_with("0x") {
        hex::decode(&raw_input[2..]).expect("Invalid hex input")
    } else {
        hex::decode(raw_input).expect("Invalid hex input")
    };

    let call_args = ethabi::decode(
        &[
            ParamType::Uint(256), // signature type
            ParamType::Bytes,     // public key
            ParamType::Bytes,     // context/hash
            ParamType::Bytes,     // message
            ParamType::Bytes,     // signature
        ],
        &input,
    ).expect("Failed to decode input");

    let sig_type = call_args[0].clone().into_uint().unwrap().as_u64();
    let public_key = call_args[1].clone().into_bytes().unwrap();
    let context = call_args[2].clone().into_bytes().unwrap();
    let message = call_args[3].clone().into_bytes().unwrap();
    let signature = call_args[4].clone().into_bytes().unwrap();

    // TODO: Here implement actual signature verification
    // For now return always true
    print!("{}", hex::encode(&ethabi::encode(&[Token::Bool(true)])));
}

fn main() {
    let exe_path = env::current_exe().unwrap();
    let binary_name = exe_path
        .file_name()
        .unwrap()
        .to_str()
        .unwrap();

    match binary_name {
        "random_bytes" => handle_random_bytes(),
        "x25519_derive" => handle_x25519_derive(),
        "curve25519_compute_public" => handle_curve25519_compute_public(),
        "deoxysii_seal" => handle_deoxysii_seal(),
        "deoxysii_open" => handle_deoxysii_open(),
        "keypair_generate" => handle_keypair_generate(),
        "sign" => handle_sign(),
        "verify" => handle_verify(),
        _ => eprintln!("Unknown binary")
    }
}
// fn main() {
//     // Create binding for current_exe() result to extend its lifetime
//     let exe_path = env::current_exe().unwrap();
//     let binary_name = exe_path
//         .file_name()
//         .unwrap()
//         .to_str()
//         .unwrap();
//     // println!("Debug: binary_name = '{}'", binary_name);  // Add this line

//     // let mut input = String::new();
//     // std::io::stdin().read_line(&mut input).unwrap();
//     // let input = hex::decode(input.trim()).unwrap();

//     match binary_name {
//         "random_bytes" => handle_random_bytes(),
//         "x25519_derive" => handle_x25519_derive(),
//         _ => eprintln!("Unknown binary")
//     }
// }
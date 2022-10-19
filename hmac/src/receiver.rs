use std::{fs::File, io::Read};

use hmac::{
    aes, blake3::Blake3, digest::DigestTrait, hash::FibMulCombineHash, hmac, rsa, SenderStruct,
    HMAC_KEY,
};

fn main() {
    let mut file = File::open("sender.json").unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();
    let sender_params: SenderStruct = serde_json::from_str(&contents).unwrap();

    println!("1) Get AES Key by Rsa decryption");

    let aes_priv_key = rsa::decrypt_private(&rsa::decrypt_public(&sender_params.rsa_enc_aes_key));

    let hmac_blake3 = hmac(
        HMAC_KEY,
        &sender_params.aes_encrypted_message,
        &Blake3::default(),
    );
    let hmac_custom_hash = hmac(
        HMAC_KEY,
        &sender_params.aes_encrypted_message,
        &FibMulCombineHash::default(),
    );

    println!("2) Verify AES encrypted message with hmac to check for integrity");
    assert_eq!(&hmac_blake3.as_bytes(), &sender_params.hmac_blake3);
    assert_eq!(
        &hmac_custom_hash.as_bytes(),
        &sender_params.hmac_custom_hash
    );

    println!("    --- Verified Successfully----");

    println!("3) Get the original message by AES Decryption");

    let message = aes::decrypt(&sender_params.aes_encrypted_message, &aes_priv_key);
    println!("MESSAGE: {}", String::from_utf8(message).unwrap());
}

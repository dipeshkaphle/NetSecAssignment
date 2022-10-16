use std::{env, fs::File, io::Write};

use hmac::{aes, blake3::Blake3, hash::FibMulCombineHash, hmac, rsa, AES_KEY, HMAC_KEY, digest::DigestTrait, SenderStruct};
fn main() {
    if env::args().len() == 1 {
        eprintln!("Please provide the message as argument");
    } else {
        let message = env::args().nth(1).unwrap();
        // let message = aes
        println!("We have the message to send from the sender");
        println!("MESSAGE: {}", message);

        let priv_key = rsa::encrypt(AES_KEY);
        println!("1) We'll encrypt the AES KEY using RSA to get non repudiation");

        let enc_message = aes::encrypt(message.as_bytes(), AES_KEY);
        println!("2) We'll encrypt the message using AES to get confidentiality");

        let hmac_on_enc_message_blake3 = hmac(HMAC_KEY, &enc_message, &Blake3::default());
        let hmac_on_enc_message_fib_combine =
            hmac(HMAC_KEY, &enc_message, &FibMulCombineHash::default());
        println!("3) We'll use hmac to show message integrity. HMAC, we're using two variants");
        println!("     i)  One variant uses Blake3 algorithm for hashing");
        println!(
            "     ii) 2nd variant uses custom hashing algorithm which outputs 128 bit digest. "
        );


        println!("--------------------------------------------------------------------");
        println!("----------------------------OUTPUT----------------------------------");
        println!("--------------------------------------------------------------------\n");
        println!("ENCRYPTED AES_KEY: {:?}\n", priv_key);
        println!("ENCRYPTED MESSAGE WITH AES: {:?}\n", enc_message);
        println!("HMAC on ENCRYPTED MESSAGE(Blake3): {:?}\n", hmac_on_enc_message_blake3.as_bytes());
        println!("HMAC on ENCRYPTED MESSAGE(Custom Hash): {:?}\n", hmac_on_enc_message_fib_combine.as_bytes());


        let sender_params = SenderStruct{
            rsa_enc_aes_key: priv_key,
            aes_encrypted_message: enc_message,
            hmac_blake3: hmac_on_enc_message_blake3.as_bytes().to_vec(),
            hmac_custom_hash: hmac_on_enc_message_fib_combine.as_bytes().to_vec()
        };

        let mut f= File::create("sender.json").unwrap();
        let _  = f.write_all(serde_json::to_string(&sender_params).unwrap().as_bytes());
    }
}

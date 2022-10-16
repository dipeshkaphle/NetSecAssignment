use hmac::{blake3::Blake3, digest::DigestTrait, hash::FibMulCombineHash, hmac};

fn main() {
    let message = "Hi Brother!!";
    let key = "key";
    let hmac_res = hmac(
        key.as_bytes(),
        message.as_bytes(),
        &FibMulCombineHash::default(),
    );
    println!(
        "As Bytes: {:?}\nAs hex: {:?}",
        hmac_res.as_bytes(),
        hmac_res.as_hex()
    );

    let hmac_res = hmac(key.as_bytes(), message.as_bytes(), &Blake3::default());
    println!(
        "As Bytes: {:?}\nAs hex: {:?}",
        hmac_res.as_bytes(),
        hmac_res.as_hex()
    );
}

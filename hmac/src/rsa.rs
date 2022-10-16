use std::fs::read;

use openssl::rsa::{Padding, Rsa};

pub fn encrypt(input: &[u8]) -> Vec<u8> {
    let pub_key = Rsa::public_key_from_pem(&read("public.pem").unwrap()).unwrap();
    let mut out_buf = vec![0; pub_key.size() as usize];
    let sz = pub_key
        .public_encrypt(input, &mut out_buf, Padding::PKCS1)
        .unwrap();
    out_buf[..sz].to_owned()
}

pub fn decrypt(cipher: &[u8]) -> Vec<u8> {
    let priv_key = Rsa::private_key_from_pem(&read("private.pem").unwrap()).unwrap();
    let mut buf = vec![0; priv_key.size() as usize];
    let msg_size = priv_key
        .private_decrypt(cipher, &mut buf, Padding::PKCS1)
        .unwrap();
    (&buf)[..msg_size].to_vec()
}

#[cfg(test)]
mod tests {
    use super::{decrypt, encrypt};

    #[test]
    fn test() {
        let data = vec![1, 2, 3, 4].repeat(10);
        let enc_data = encrypt(&data);
        let dec_data = decrypt(&enc_data);
        assert_eq!(data, dec_data);
    }
}

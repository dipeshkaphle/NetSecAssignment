use std::fs::read;

use openssl::rsa::{Padding, Rsa};

pub fn encrypt_private(input: &[u8]) -> Vec<u8> {
    let priv_key = Rsa::private_key_from_pem(&read("private2.pem").unwrap()).unwrap();
    println!("{}", priv_key.size());
    let mut out_buf = vec![0; priv_key.size() as usize];
    let sz = priv_key
        .private_encrypt(input, &mut out_buf, Padding::PKCS1)
        .unwrap();
    out_buf[..sz].to_owned()
}
pub fn decrypt_public(input: &[u8]) -> Vec<u8> {
    let pub_key = Rsa::public_key_from_pem(&read("public2.pem").unwrap()).unwrap();
    let mut out_buf = vec![0; pub_key.size() as usize];
    let sz = pub_key
        .public_decrypt(input, &mut out_buf, Padding::PKCS1)
        .unwrap();
    out_buf[..sz].to_owned()
}

pub fn encrypt_public(input: &[u8]) -> Vec<u8> {
    let pub_key = Rsa::public_key_from_pem(&read("public.pem").unwrap()).unwrap();
    let mut out_buf = vec![0; pub_key.size() as usize];
    let sz = pub_key
        .public_encrypt(input, &mut out_buf, Padding::PKCS1)
        .unwrap();
    out_buf[..sz].to_owned()
}

pub fn decrypt_private(cipher: &[u8]) -> Vec<u8> {
    let priv_key = Rsa::private_key_from_pem(&read("private.pem").unwrap()).unwrap();
    let mut buf = vec![0; priv_key.size() as usize];
    let msg_size = priv_key
        .private_decrypt(cipher, &mut buf, Padding::PKCS1)
        .unwrap();
    (&buf)[..msg_size].to_vec()
}

#[cfg(test)]
mod tests {
    use crate::rsa::{decrypt_public, encrypt_private};

    use super::{decrypt_private, encrypt_public};
    #[test]
    fn test2() {
        let data = vec![1, 2, 3, 4].repeat(10);
        let enc_data = encrypt_private(&data);
        let dec_data = decrypt_public(&enc_data);
        assert_eq!(data, dec_data);
    }

    #[test]
    fn test1() {
        let data = vec![1, 2, 3, 4].repeat(10);
        let enc_data = encrypt_public(&data);
        let dec_data = decrypt_private(&enc_data);
        assert_eq!(data, dec_data);
    }
}

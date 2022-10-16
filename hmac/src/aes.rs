use openssl::symm::{self, Cipher};

pub fn encrypt(inp: &[u8], key: &[u8]) -> Vec<u8> {
    let cipher = Cipher::aes_128_cbc();

    symm::encrypt(cipher, key, None, inp).unwrap()
}

pub fn decrypt(cipher_text: &[u8], key: &[u8]) -> Vec<u8> {
    let cipher = Cipher::aes_128_cbc();
    symm::decrypt(cipher, key, None, cipher_text).unwrap()
}

#[cfg(test)]
mod tests {
    use crate::AES_KEY;

    use super::{decrypt, encrypt};

    #[test]
    fn correctness() {
        let data = vec![1, 2, 3, 4].repeat(1000);
        let enc = encrypt(&data, AES_KEY);
        let dec = decrypt(&enc, AES_KEY);
        assert_eq!(data, dec);
    }
}

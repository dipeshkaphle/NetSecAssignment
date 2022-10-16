use std::{mem::size_of, ops::Mul};

use crate::{
    digest::{DigestTrait, DigestType},
    CryptHash,
};

#[derive(Default)]
pub struct Blake3 {}

impl CryptHash<[u8; 32]> for Blake3 {
    fn hash(&self, s: &[u8]) -> DigestType<[u8; 32]> {
        let hash = blake3::hash(s);
        DigestType::new(hash.as_bytes().to_owned())
    }
}

impl DigestTrait for DigestType<[u8; 32]> {
    fn as_hex(&self) -> String {
        self.val
            .iter()
            .map(|x| format!("{:02x}", x))
            .collect::<Vec<String>>()
            .join("")
    }

    fn as_bytes(&self) -> Vec<u8> {
        self.val.to_vec()
    }

    fn size_in_bits(&self) -> usize {
        size_of::<[u8; 32]>().mul(8)
    }
}

use std::mem::size_of;

use digest::{DigestTrait, DigestType};
use serde::{Deserialize, Serialize};

pub mod aes;
pub mod blake3;
pub mod digest;
pub mod hash;
pub mod rsa;

pub const AES_KEY: &[u8] = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F";
pub const HMAC_KEY: &[u8] = b"\x29\x31\x11\xaa\x22\x33\x44\x92\xff\xef\x0f";

pub trait CryptHash<T> {
    fn hash(&self, s: &[u8]) -> DigestType<T>;
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SenderStruct {
    pub rsa_enc_aes_key: Vec<u8>,
    pub aes_encrypted_message: Vec<u8>,
    pub hmac_blake3: Vec<u8>,
    pub hmac_custom_hash: Vec<u8>,
}

pub fn hmac<T, H: CryptHash<T>>(key: &[u8], message: &[u8], hasher: &H) -> DigestType<T>
where
    DigestType<T>: DigestTrait,
{
    let block_size = size_of::<T>();
    let block_sized_key = compute_block_sized_key(key, hasher, block_size);
    let o_key_pad = block_sized_key
        .iter()
        .zip(vec![0x5c; block_size].iter())
        .map(|(x, y)| x ^ y)
        .collect::<Vec<u8>>();
    let i_key_pad = block_sized_key
        .iter()
        .zip(vec![0x36; block_size].iter())
        .map(|(x, y)| x ^ y)
        .collect::<Vec<u8>>();
    hasher.hash(
        &[
            o_key_pad,
            hasher.hash(&[&i_key_pad, message].concat()).as_bytes(),
        ]
        .concat(),
    )
}

fn compute_block_sized_key<T, H: CryptHash<T>>(key: &[u8], hasher: &H, block_size: usize) -> Vec<u8>
where
    DigestType<T>: DigestTrait,
{
    let mut k = key.to_owned();
    if k.len() > block_size {
        k = hasher.hash(&k).as_bytes();
    }
    if k.len() < block_size {
        let rem = block_size - key.len();
        k = [k, vec![0; rem]].concat();
    }
    k
}

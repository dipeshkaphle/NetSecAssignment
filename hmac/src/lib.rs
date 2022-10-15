use std::mem::size_of;

use digest::{DigestTrait, DigestType};

pub mod blake3;
pub mod digest;
pub mod hash;

pub trait CryptHash<T> {
    fn hash(&self, s: &[u8]) -> DigestType<T>;
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

#[cfg(test)]
mod tests {

    use crate::{digest::DigestTrait, hash::FibMulCombineHash, hmac};

    #[test]
    fn check() {
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
    }
}

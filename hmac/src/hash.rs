use crate::{digest::DigestType, CryptHash};
use rayon::prelude::*;

// #[derive(Default)]
// pub struct FibAddHash {}

// impl CryptHash for FibAddHash {
// fn hash(&self, s: &[u8]) -> u128 {
// let mut h: u128 = 0;
// let mut fib: u64 = 1;
// let mut prev: u64 = 1;
// s.iter().for_each(|x: &u8| {
// h = h.wrapping_add((*x as u128).wrapping_mul(fib as _));
// let p = fib;
// fib = fib.wrapping_add(prev);
// prev = p;
// });
// h
// }
// }

/* Multiplicative Fibonacci hashing
(Knuth, TAOCP vol 3, section 6.4, page 518).
HASH_FACTOR is (sqrt(5) - 1) / 2 * 2^wordsize. */
// https://asecuritysite.com/hash/smh_fib
const HASH_FACTOR: u128 = 210306068529402873165736369884012333108;
#[derive(Default)]
pub struct FibMulCombineHash {}

impl FibMulCombineHash {
    fn combine(seed: u128, h: u128) -> u128 {
        let mut seed = seed;
        // seed ^= h + 0x9e3779b9 + (seed << 6) + (seed >> 2);
        seed ^= h
            .wrapping_add(0x9e3779b9)
            .wrapping_add(seed.wrapping_shl(6))
            .wrapping_add(seed.wrapping_shr(2));
        seed
    }
}

impl CryptHash<u128> for FibMulCombineHash {
    fn hash(&self, s: &[u8]) -> DigestType<u128> {
        let mut v: Vec<u128> = s
            .par_iter()
            // .chars()
            .map(|x| ((*x as u128).wrapping_mul(HASH_FACTOR)))
            .collect();
        let chunk_size = 2;
        while v.len() >= 2 {
            let w: Vec<u128> = v
                .par_chunks(chunk_size)
                // .chunks(chunk_size)
                .map(|w| {
                    if w.len() == chunk_size {
                        FibMulCombineHash::combine(w[0], w[1])
                    } else {
                        w[0]
                    }
                })
                .collect();
            v = w;
        }
        if v.is_empty() {
            DigestType::new(0)
        } else {
            DigestType::new(v.last().unwrap().to_owned())
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        digest::{DigestTrait, DigestType},
        hash::FibMulCombineHash,
        CryptHash,
    };

    // use super::FibAddHash;

    // #[test]
    // fn fib_add_hash() {
    // let fh = FibAddHash::default();
    // let aa_h = fh.hash("a".as_bytes());
    // println!("{}", aa_h);
    // let ab_h = fh.hash("ab".as_bytes());
    // println!("{}", ab_h);
    // }
    #[test]
    fn fib_mul_combine_hash() {
        let fh = FibMulCombineHash::default();
        let s1 = "abc".repeat(2000000);
        let s2 = "abd".repeat(2000000);
        let h1 = fh.hash(s1.as_bytes());
        let h2 = fh.hash(s2.as_bytes());
        let h1_hex = h1.as_hex();
        let h2_hex = h2.as_hex();
        assert_eq!(
            h1,
            DigestType::new(u128::from_str_radix(h1_hex.as_str(), 16).unwrap())
        );
        assert_eq!(
            h2,
            DigestType::new(u128::from_str_radix(h2_hex.as_str(), 16).unwrap())
        );
        println!("{}\n{}\n", h1_hex, h2_hex);
    }

    #[test]
    fn avalanche_fib_mul_combine() {
        let fh = FibMulCombineHash::default();
        let s1 = "abcd";
        let s2 = "abbd";

        let mismatches = |x: &[u8], y: &[u8]| -> usize {
            x.iter()
                .zip(y.iter())
                .map(|(x, y)| usize::from(x != y))
                .sum()
        };

        println!(
            "Mismatches in hash: {}",
            mismatches(
                fh.hash(s1.as_bytes()).as_hex().as_bytes(),
                fh.hash(s2.as_bytes()).as_hex().as_bytes()
            )
        );
        println!(
            "Mismatches in keys: {}",
            mismatches(s1.as_bytes(), s2.as_bytes())
        );
        assert_ne!(
            mismatches(s1.as_bytes(), s2.as_bytes()),
            mismatches(
                fh.hash(s1.as_bytes()).as_hex().as_bytes(),
                fh.hash(s2.as_bytes()).as_hex().as_bytes()
            )
        )
    }

    #[test]
    fn fib_mul_combine_hash_deterministic() {
        let fh = FibMulCombineHash::default();
        let s = "abcd";
        let v = [s; 10000];
        let hash = fh.hash(s.as_bytes());
        assert!(v
            .into_iter()
            .map(|x| fh.hash(x.as_bytes()))
            .all(|x| x == hash));
    }
}

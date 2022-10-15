use std::{mem::size_of, ops::Mul};

#[derive(Debug, PartialEq, Eq)]
pub struct DigestType<T> {
    val: T,
}

impl<T> DigestType<T> {
    pub fn new(v: T) -> Self {
        DigestType { val: v }
    }
}

pub trait DigestTrait {
    fn as_hex(&self) -> String;
    fn as_bytes(&self) -> Vec<u8>;
    fn size(&self) -> usize;
}

impl DigestTrait for DigestType<u128> {
    fn as_hex(&self) -> String {
        format!("{:032x}", self.val)
    }

    fn as_bytes(&self) -> Vec<u8> {
        self.val.to_be_bytes().into_iter().collect()
    }

    fn size(&self) -> usize {
        size_of::<u128>().mul(8)
    }
}

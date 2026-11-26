use std::fmt;

use zeroize::Zeroize;

pub struct SecretBytes {
    bytes: Box<[u8]>,
}

impl SecretBytes {
    pub fn zeroed(len: usize) -> Self {
        Self {
            bytes: vec![0u8; len].into_boxed_slice(),
        }
    }

    pub fn take_from(source: &mut [u8]) -> Self {
        let secret = Self { 
            bytes: Box::from(&source[..]),
        };
        source.zeroize();
        secret
    }
}
use std::fmt;

use zeroize::Zeroize;

pub struct SecretBytes {
    bytes: Box<[u8]>,
}

impl SecretBytes {
    /// # Arguments
    /// * `len (usize = size of pointers, e.g. 32 or 64 bits` - length of an entry.
    /// # Returns
    /// SecretBytes Object with "bytes" member, where all entries are 0-bytes
    /// # Does
    /// boxes the zeroed bytes, such that no copy is left behind when cleaning memory (would make attackers beable to read out old memory and get the data)
    pub fn zeroed(len: usize) -> Self {
        Self {
            bytes: vec![0u8; len].into_boxed_slice(),
        }
    }

    /// # Arguments
    /// * `source` - mutatable unsigned 8bit integer array.
    /// # Returns
    /// SecretBytes Object.
    /// # Does
    /// Copies data from a source in secret, zeroes it and then deletes the source
    pub fn take_from(source: &mut [u8]) -> Self {
        let secret = Self {
            bytes: Box::from(&source[..]),
        };
        source.zeroize();
        secret
    }

    /// # Arguments
    /// * `&self` - reads object and does not mutate it
    /// # Returns
    /// loaned reading sight on bytes (pointer + length), no copy
    pub fn expose_secret(&self) -> &[u8] {
        &self.bytes
    }

    /// # Arguments
    /// * `&mut self` - mutatable object
    /// # Returns
    /// loaned sight with writing rights
    pub fn expose_secret_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }

    /// # Arguments
    /// * `&self` - reads object and does not mutate it
    /// # Returns
    /// length of box
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// # Arguments
    /// * `&self` - reads object and does not mutate it
    /// # Returns
    /// true if the object is empty
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl Drop for SecretBytes {
    /// # Arguments
    /// * `&mut self` - mutatable object
    /// # Returns
    /// -
    /// # Does
    /// gets called when object gets destroyed, zeroes the entries such that no data gets left behind visible
    fn drop(&mut self) {
        // zeroize guarantees the compiler can't remove this wipe as a 'dead store', even though the memory is freed right after
        self.bytes.zeroize();
    }
}

impl fmt::Debug for SecretBytes {
    /// # Arguments
    /// * `&self` - mutatable object
    /// * `f` - mutatable formatter target
    /// # Returns
    /// formatting result
    /// # Does
    /// writes the secretbytes to output, but redacted
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBytes([REDACTED; {} bytes])", self.bytes.len())
    }
}

use aead::{Aead, KeyInit};
use chacha20::{ChaCha8Rng, rand_core::{RngCore, SeedableRng}};
use stack_sanitizer::*;
use std::collections::{BTreeMap, HashMap, HashSet};
use hkdf::Hkdf;
use sha3::Sha3_512;

/// The HKDFs of a given epoch.
struct EpochCrypto {
    symmetric_key_hkdf: Hkdf<Sha3_512>,
    ecdsa_key_hkdf: Hkdf<Sha3_512>,
    ecdh_key_hkdf: Hkdf<Sha3_512>,
    access_count: u64,
}

impl EpochCrypto {
    pub fn new(rng: &mut ChaCha8Rng, epoch: u64) -> Self {
        let mut symmetric_kdf_key = [0u8; 64];
        let mut ecdsa_kdf_key = [0u8; 64];
        let mut ecdh_kdf_key = [0u8; 64];
        let mut discard = [0u8; 32];

        let epoch_low_word = epoch as u32;
        let epoch_high_word = (epoch >> 32) as u32;
        rng.set_block_pos([u32::MAX, epoch_low_word]);
        rng.set_stream([epoch_high_word, 0]);
        rng.fill_bytes(&mut discard);

        for key in [symmetric_kdf_key, ecdsa_kdf_key, ecdh_kdf_key].iter_mut() {
            rng.fill_bytes(key);
        }
        Self {
            symmetric_key_hkdf: Hkdf::<Sha3_512>::from_prk(&symmetric_kdf_key).expect("Key should be valid"),
            ecdsa_key_hkdf: Hkdf::<Sha3_512>::from_prk(&ecdsa_kdf_key).expect("Key should be valid"),
            ecdh_key_hkdf: Hkdf::<Sha3_512>::from_prk(&ecdh_kdf_key).expect("Key should be valid"),
            access_count: 1,
        }
    }
}

struct ZeroizingCache {
    cache: HashMap<u64, EpochCrypto>,
    access_counts: BTreeMap<u64, HashSet<u64>>,
}

impl ZeroizingCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            cache: HashMap::with_capacity(capacity),
            access_counts: BTreeMap::new(),
        }
    }
    fn remove_least_used(&mut self) -> Option<EpochCrypto> {
        let (&min_freq, keys) = self.access_counts.iter_mut().next()?;
        let key = keys.iter().next()?;

        if let Some(entry) = self.cache.remove(key) {
            drop(entry);
        }
        keys.remove(key);
        if keys.is_empty() {
            self.access_counts.remove(&min_freq);
        }
        None
    }
    pub fn access(&mut self, rng: &mut ChaCha8Rng, epoch: u64) -> &EpochCrypto {
        if let Some(v) = self.cache.get_mut(&epoch) {
            self.access_counts.get_mut(&v.access_count).expect("exists").remove(&epoch);
            self.access_counts.entry(v.access_count + 1).or_default().insert(epoch);
            v.access_count += 1;
            v
        } else {
            if self.cache.len() == self.cache.capacity() {
                self.remove_least_used();
            }
            self.cache.insert(epoch, EpochCrypto::new(rng, epoch));
            self.access_counts.entry(1).or_default().insert(epoch);
            self.cache.get_mut(&epoch).expect("We just added this")
        }
    }
}

pub struct CryptoOperator {
    stack: ZeroizingHeapStack,
    rng: Box<ChaCha8Rng>,
    cache: ZeroizingCache,
}

impl CryptoOperator {
    pub fn new(key: &[u8]) -> Self {
        let mut stack = ZeroizingHeapStack::new(4);
        let rng = unsafe {
            switch_stacks(&mut stack, || {
                let hkdf: Hkdf<Sha3_512> = Hkdf::from_prk(key).expect("Main KDF key was not long enough");
                let mut seed = [0u8; 32];
                hkdf.expand(b"main rng", &mut seed);
                Box::new(ChaCha8Rng::from_seed(seed))
            })
        };

        Self {
            stack,
            rng,
            cache: ZeroizingCache::new(16),
        }
    }

    /// If you want to use this hierarchy of HKDFs and CSPRNGs for key 
    /// management, it might be better to perform the entire cryptographic 
    /// operation on the separate stack rather than just generating a single key. 
    /// In other words, use the key on the separate stack and perform an individual 
    /// but larger operation, such as encryption/decryption, signature, or a 
    /// key agreement.
    pub fn encrypt_data<A: Aead + KeyInit>(&mut self, epoch: u64, key_id: &[u8], data: &mut [u8], nonce: &[u8; 12]) {
        unsafe {
            switch_stacks(&mut self.stack, || {
                let mut key = [0u8; 32];
                let epoch_crypto = self.cache.access(&mut self.rng, epoch);
                epoch_crypto.symmetric_key_hkdf.expand_multi_info(&[b"symmetric key", &epoch.to_le_bytes(), key_id], key.as_mut_slice());
                let mut cipher = A::new(&key.into());
                cipher.encrypt(&Default::default(), data.into());

            })
        }
    }
}
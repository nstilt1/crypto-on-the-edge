use private_key_generator_docs::{BinaryId, CryptoKeyGenerator, VersioningConfig, KeyGenerator, typenum::consts::{U48, U5}};
use hkdf::hmac::{Hmac, KeyInit};
use rand_chacha::ChaCha8Rng;
use rand::rngs::OsRng;
use sha2::Sha256;

type TestId = BinaryId<
    U48, // IdLength: okay
    U5,  // MacLength: okay
    3,   // MAX_PREFIX_LEN: okay
    32,  // VERSION_BITS: okay
    56,  // TIMESTAMP_BITS: okay
    27    // TIMESTAMP_PRECISION_REDUCTION: okay
>;
type InvalidVersionLifetimeConfig = VersioningConfig<
    3, // EPOCH can be any time between 0 and now
    600, // VERSION LIFETIME must be at 600 seconds
    false, 
    4
>;

fn main() {
    type K = KeyGenerator<Hmac<Sha256>, InvalidVersionLifetimeConfig, ChaCha8Rng, Sha256>;

    let mut k = K::new(&[48u8; 32], b"ff", Hmac::<Sha256>::new_from_slice(&[42u8; 32]).unwrap(), &mut [3u8; 32]);
    let _id = k.generate_keyless_id::<TestId>(&[], &[], None, None, &mut OsRng);
}
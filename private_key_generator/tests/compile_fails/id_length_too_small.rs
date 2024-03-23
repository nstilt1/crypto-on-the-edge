use private_key_generator_docs::{BinaryId, CryptoKeyGenerator, VersioningConfig, KeyGenerator, typenum::consts::{U19, U5}};
use hkdf::hmac::{Hmac, KeyInit};
use rand_chacha::ChaCha8Rng;
use rand::rngs::OsRng;
use sha2::Sha256;

type TestId = BinaryId<
    U19, // IdLength: too small. The other parameters would require this to be at least 20 bytes. Breakdown:
    U5,  // MacLength:                      5 bytes
    3,   // MAX_PREFIX_LEN:                 3 bytes
    32,  // VERSION_BITS:                           + 32 bits + constant 2 bits
    56,  // TIMESTAMP_BITS:                         + 56 bits
    8    // TIMESTAMP_PRECISION_REDUCTION:
>;  //                           20 bytes = 8 bytes + 11 bytes + round up 1 byte

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
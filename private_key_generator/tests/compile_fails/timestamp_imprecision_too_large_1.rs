use private_key_generator::prelude::*;
use hkdf::hmac::{Hmac, KeyInit};
use rand_chacha::ChaCha8Rng;
use rand::rngs::OsRng;
use sha2::Sha256;

type TestId = BinaryId<
    U48, // IdLength: okay. Total length sums up to exactly 19 bytes...
         // BUT... there is no room for pseudorandom bytes, other than the prefix
    U5,  // MacLength: okay
    5,   // MAX_PREFIX_LEN: okay
    use_timestamps::Sometimes
>;

type InvalidTimestampPrecisionLossConfig = VersioningConfig<
    0,              // EPOCH
    1_000_000_000,  // VERSION_LIFETIME
    32,             // VERSION_BITS
    24,             // TIMESTAMP_BITS
    28,              // TIMESTAMP_PRECISION_LOSS
    1_000_000_000,  // MAX_KEY_EXPIRATION_TIME
    800             // BREAKING_POINT_YEARS
>;

fn main() {
    type K = KeyGenerator<Hmac<Sha256>, InvalidTimestampPrecisionLossConfig, ChaCha8Rng, Sha256>;

    let mut k = K::new(&[48u8; 32], b"ff", Hmac::<Sha256>::new_from_slice(&[42u8; 32]).unwrap(), &mut [3u8; 32]);
    let _id = k.generate_keyless_id::<TestId>(&[], &[], None, None, &mut OsRng);
}
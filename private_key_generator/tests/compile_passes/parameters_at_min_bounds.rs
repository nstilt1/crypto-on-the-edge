use private_key_generator::prelude::*;
use hkdf::hmac::{Hmac, KeyInit};
use rand_chacha::ChaCha8Rng;
use rand::rngs::OsRng;
use sha2::Sha256;

type TestId = BinaryId<
    U3, // IdLength: okay
    U1,  // MacLength: okay
    0,   // MAX_PREFIX_LEN: okay
    use_timestamps::Sometimes
>;

// type V = VersioningConfig<
//     0,              // EPOCH
//     600,  // VERSION_LIFETIME
//     0,             // VERSION_BITS
//     0,             // TIMESTAMP_BITS
//     0,              // TIMESTAMP_PRECISION_LOSS
//     0,  // MAX_KEY_EXPIRATION_TIME
//     0             // BREAKING_POINT_YEARS
// >;

fn main() {
    type V  = StaticVersionConfig<0, 0, 0>;
    type K = KeyGenerator<Hmac<Sha256>, V, ChaCha8Rng, Sha256>;

    let mut k = K::new(&[48u8; 32], b"ff", Hmac::<Sha256>::new_from_slice(&[42u8; 32]).unwrap(), &mut [3u8; 32]);
    let _id = k.generate_keyless_id::<TestId>(&[], &[], None, None, &mut OsRng);
}
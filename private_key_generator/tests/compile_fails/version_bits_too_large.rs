use private_key_generator::prelude::*;
use hkdf::hmac::Hmac;
use rand_chacha::ChaCha8Rng;
use rand::rngs::OsRng;
use sha2::Sha256;

type TestId = BinaryId<
    U48, // IdLength: okay
    U5,  // MacLength: okay
    5,   // MAX_PREFIX_LEN: okay
    use_timestamps::Sometimes
>;

type InvalidVersionBitsConfig = VersioningConfig<
    0,              // EPOCH
    1_000_000_000,  // VERSION_LIFETIME
    33,             // VERSION_BITS
    56,             // TIMESTAMP_BITS
    4,              // TIMESTAMP_PRECISION_LOSS is too high because TIMESTAMP_BITS + TIMESTAMP_PRECISION_LOSS is above 64
    1_000_000_000,  // MAX_KEY_EXPIRATION_TIME
>;

fn main() {
    type K = KeyGenerator<Hmac<Sha256>, InvalidVersionBitsConfig, ChaCha8Rng, Sha256>;

    let mut k = K::new(&[48u8; 32], b"ff");
    let _id = k.generate_keyless_id::<TestId>(&[], &[], None, None, &mut OsRng);
}
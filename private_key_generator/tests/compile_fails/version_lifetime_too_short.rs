use private_key_generator::prelude::*;
use hkdf::hmac::Hmac;
use private_key_generator::prelude::ChaCha8Rng;
use sha2::Sha256;

type TestId = BinaryId<
    U48, // IdLength: okay
    U5,  // MacLength: okay
    5,   // MAX_PREFIX_LEN: okay
    use_timestamps::Sometimes
>;

type InvalidVersionLifetimeConfig = VersioningConfig<
    0,              // EPOCH
    599,            // VERSION_LIFETIME
    32,             // VERSION_BITS
    56,             // TIMESTAMP_BITS
    5,              // TIMESTAMP_PRECISION_LOSS is too high because TIMESTAMP_BITS + TIMESTAMP_PRECISION_LOSS is above 64
    1_000_000_000,  // MAX_KEY_EXPIRATION_TIME
>;

fn main() {
    // this test should not compile because the VERSION_LIFETIME is too short. When the VERSION_LIFETIME is too short, the KeyGenerator will run through the total amount of versions way too quickly. Thus, it is limited to 2 weeks.
    type K = KeyGenerator<Hmac<Sha256>, InvalidVersionLifetimeConfig, ChaCha8Rng, Sha256>;

    let mut _k = K::new(&[48u8; 32], b"ff");
}
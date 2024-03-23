use private_key_generator_docs::{BinaryId, CryptoKeyGenerator, VersioningConfig, KeyGenerator, typenum::consts::{U48, U5}};
use hkdf::hmac::{Hmac, KeyInit};
use rand_chacha::ChaCha8Rng;
use sha2::Sha256;

type TestId = BinaryId<U48, U5, 3, 3, 24, 8>;
type InvalidVersionLifetimeConfig = VersioningConfig<
    3, // EPOCH can be any time between 0 and now
    599, // VERSION LIFETIME must be at least 600 seconds
    false, 
    4
>;

fn main() {
    // this test should not compile because the VERSION_LIFETIME is too short. When the VERSION_LIFETIME is too short, the KeyGenerator will run through the total amount of versions way too quickly. Thus, it is limited to 2 weeks.
    type K = KeyGenerator<Hmac<Sha256>, InvalidVersionLifetimeConfig, ChaCha8Rng, Sha256>;

    let mut _k = K::new(&[48u8; 32], b"ff", Hmac::<Sha256>::new_from_slice(&[42u8; 32]).unwrap(), &mut [3u8; 32]);
}
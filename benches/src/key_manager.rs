use chacha20poly1305::ChaCha20Poly1305;
use criterion::{Criterion, BenchmarkId, criterion_group, criterion_main};
type Benchmarker = Criterion;
use http_private_key_manager::{prelude::{KeyGenerator, *}, private_key_generator::{hkdf::hmac::Hmac, timestamp_policies}};


type BigId = BinaryId<U48, U8, 6, timestamp_policies::use_timestamps::Sometimes>;
type MediumId = BinaryId<U24, U8, 6, timestamp_policies::use_timestamps::Sometimes>;
type SmallId = BinaryId<U10, U3, 0, use_timestamps::Never>;

type Versioning = AnnualVersionConfig<14, 8, 18>;
use p384::NistP384;
use sha2::Sha256;

type KeyGen = KeyGenerator<
    Hmac<sha3::Sha3_512>,
    Versioning,
    ChaCha8Rng,
    sha3::Sha3_512
>;

pub type EcdsaAlg = NistP384;
type EcdhAlg = NistP384;
type EcdhDigest = sha2::Sha384;
pub type EcdsaDigest = sha2::Sha384;

pub type KeyManager = HttpPrivateKeyManager<
    KeyGen, // key generator
    EcdhAlg, // ecdh algo
    EcdhDigest, 
    EcdsaAlg, 
    EcdsaDigest,
    BigId, 
    BigId,
    BigId, 
    ChaCha8Rng
>;

fn init_key_manager() -> KeyManager {
    let result = KeyManager::from_key_generator(
        KeyGen::new(&[0u8; 64], b"bench"),
        Alphabet::new("asdfghjklqwertyuiopzxcvbnm1234567890ASDFGHJKLQWERTYUIOPZXCVBNM/-").unwrap()
    );
    result
}

fn bench(c: &mut Benchmarker) {
    let mut group = c.benchmark_group("init");
    group.bench_function(BenchmarkId::new("init", 1), |b| {
        b.iter(||init_key_manager());
    });
    let mut group = c.benchmark_group("decrypt");
    group.bench_function(BenchmarkId::new("decrypt", 1), |b| {
        let mut key_manager = init_key_manager();
        b.iter(|| {
            key_manager.decrypt_and_hash_request::<ChaCha20Poly1305, Sha256, _>(request, request_bytes, false)
        });
    });
    let mut group = c.benchmark_group("generate_id");
    let mut group = c.benchmark_group("encrypt");
}

criterion_group!(benches, bench);
criterion_main!(benches);
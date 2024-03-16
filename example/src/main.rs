use key_manager::{private_key_generator::{self, CryptoKeyGenerator}, HttpPrivateKeyManager};
use private_key_generator::{BinaryId, KeyGenerator};
use base64::{alphabet::Alphabet, engine::{general_purpose::NO_PAD, GeneralPurpose}};
use secrecy::Secret;
use sha2::digest::consts::{U39, U48, U6};

mod client_side;

const ID_VERSION: u8 = 1;

type ClientId = BinaryId<U39, U6, 6, 0, ID_VERSION, 6, 1710599105>;
type KeyId = BinaryId<U48, U6, 0, 0, ID_VERSION, 6, 1710599105>;

type ExampleKeyGenerator = KeyGenerator<Sha384>;

type ExampleKeyManager = HttpPrivateKeyManager<ExampleKeyGenerator, NistP384, Sha384, NistP384, ClientId, KeyId, StdRng>;

/// Initializes a key manager.
/// 
/// TODO: finish initializing key manager
fn initialize_key_manager() -> ExampleKeyManager {
    // you could use a custom alphabet here
    let base64_alphabet = Alphabet::new("ASDFGHJKLZXCVBNMQWERTYUIOP1234567890asdfghjklqwertyuiopzxcvbnm-_").unwrap();
    
    let mut secret_key: Secret<[u8; 48]> = Secret::new([42u8; 48]);

    let key_manager = ExampleKeyManager::from_key_generator(ExampleKeyGenerator::new(secret_key.as_slice(), b"my arbitrary application ID"), base64_alphabet, NO_PAD);
}

/// Generates a handshake request.
/// 
/// TODO: Add payload and finish this function
fn begin_handshake() -> Request {
    let mut key_manager = initialize_key_manager();
    
    // generate ecdh and ecdsa pubkeys and key IDs for the client to use for the first request
    
    // have the client send a request
    client_side::send_request(ecdh_key_id.as_ref(), &ecdh_pubkey, ecdsa_key_id.as_ref(), &ecdsa_pubkey);
}

fn main() {
    let mut key_manager = initialize_key_manager();

    let mut request = receive_request();

    let decrypted_payload = key_manager.decrypt_and_hash_request::<HandshakeRequestPayload>(request, true)?;

    // create a response payload

    // encrypt and sign response payload

    // receive the next request from the client
    let decrypted_payload = key_manager.decrypt_and_hash_request::<OtherPayload>(request_payload, false)?;
}

//! This library handles the generation of private keys, has capabilities for
//! expiring private keys, and eliminates the need to store private keys.
//!
//! <div class="warning">
//! Security notice: This is not a replacement for a Hardware Security Module,
//! and this crate has not been independently audited or reviewed. </div>
//!
//! [KeyGenerator](crate::KeyGenerator) is essentially a wrapper around an
//! HMAC-based Key Derivation function ([HKDF](hkdf::Hkdf)) with some utility
//! functions, along with a [BinaryId](crate::BinaryId) struct. The ID contains
//! an HMAC for determining probable[^note] authenticity of a user-supplied ID.
//! The ID could be an identifier for an ECDH key, an ECDSA key, or a client's
//! ID. The ID can also be encoded with an expiration timestamp and a version.
//!
//! [^note] [BinaryId](crate::BinaryId) contains an `HmacLen` parameter, which
//! determines the ID's HMAC's bits of security when validating IDs.
//!
//! Falsely validated IDs should not be critical to the security of your
//! application. The validation is primarily for preventing unnecessary database
//! read operations or other processing just to find out that a supplied ID was
//! invalid. If a "client ID" was falsely validated, you probably won't find the
//! ID in your database. If an ECDH Key ID was falsely validated, you will not
//! be able to decrypt the message, or they will not be able to decrypt the
//! message you send to them. If an ECDSA Key was falsely validated, then an
//! arbitrary signature might be created, and the attacker should not be able to
//! obtain any information from it.
//!
//! # Example
//! Before we can begin to use our generated private keys, we need to distribute
//! the public keys and key IDs. You can distribute the keys several different
//! ways:
//! 1. If you aren't concerned about timing attacks, you could create a REST API
//!    method that returns a public key and a key ID.
//! 2. You could also create a static webpage that you periodically update with
//!    your latest public keys and key IDs.
//! 3. If you are only using these keys with your own network of machines, you
//!    could theoretically use the same HMAC key and application ID to generate
//!    compatible private and public keys without needing to distribute or store
//!    public keys.
//! ```
//! use p256::NistP256;
//! use sha2::Sha256;
//! use private_key_generator::{
//!     Id, typenum::consts::{U48, U4}, KeyGenerator
//! };
//! use zeroize::Zeroize;
//!
//! // an EPOCH reference point for encoding timestamps with only 3 bytes
//! const EPOCH: u64 = 1709349508;
//! type EccKeyIdV1 = Id<
//!     U48,   // binary encoded ID length
//!     U4,    // binary encoded HMAC length
//!     6,     // max prefix length; use multiple of 3 for Base64 representation
//!     0,     // Info byte offset
//!     1,     // version number
//!     5,     // number of bits used to represent the version number
//!     EPOCH
//! >;
//!
//! /// You can make a private function for initializing a key generator, and
//! /// you could use the `prk` output with `from_prk` instead of `new` or `extract` to save a small amount of time.
//! fn initialize_key_generator() -> KeyGenerator {
//!    KeyGenerator::<Sha256>::new(&[42u8; 64], b"arbitrary application ID");
//! }
//!
//! // a function that generates some P-384 public keys and IDs with an expiration timestamp. You will need to distribute them as suggested above
//! fn generate_pubkeys() {
//!     let key_generator = initialize_key_generator();
//!     let expiration_date = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + 60 * 60 * 24 * 365;
//!     let (id, pubkey) = key_generator.generate_ecdsa_key_and_id::<NistP256, EccKeyIdV1>(&[], Some(expiration_date), None, &mut OsRng);
//!     let (ecdh_key_id, pubkey) = key_generator.generate_ecdh_pubkey_and_id::<NistP256, EccKeyIdV1>(&[], Some(expiration_date), None, &mut OsRng);
//! }
//!
//! // a function that makes or uses private keys generated from IDs
//! fn use_key_ids() {
//!     let key_generator = initialize_key_generator();
//!     let client_id: &[u8];
//!     let client_provided_ecdh_key_id: &[u8];
//!     let client_pubkey: &[u8];
//!     let encrypted_data: &[u8];
//!     if let Ok(id) = key_generator.validate_ecdh_key_id::<EccKeyIdV1>(client_provided_ecdh_key_id, None) {
//!         let pubkey = PublicKey::<NistP384>::from_sec1_bytes(client_pubkey).unwrap();
//!         let shared_secret = key_generator.ecdh_using_key_id::<NistP256>(id, None, pubkey);
//!     }
//!     
//!     let client_provided_ecdsa_key_id: &[u8];
//!     if let Ok(id) = key_generator.validate_ecdsa_key_id::<NistP256>(client_provided_ecdsa_key_id, None) {
//!         let private_key = key_generator.generate_ecdsa_key_from_id::<NistP256>(id, None);
//!     }
//! }
//! ```
//! Stuff for the ID
//! has a generic argument that determines the length of the `HMAC` within the
//! ID itself. The longer the HMAC, the less likely a forged ID will make it
//! through. The `HMAC` does not need to be very long. If a forged Client ID
//! made it through this validation, then you shouldn't be able to find it in
//! your database. If a forged ECDH Key ID made it through, then shouldn't be
//! able to decrypt their message. If a forged ECDSA Key ID made it through,
//! then the attacker will receive a signature from an arbitrary private ECDSA
//! key, and since signatures are designed to be public, this should not reveal
//! any information about the private key generation.

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

#[cfg(feature = "std")]
extern crate std;

pub use ecdsa;
pub use hkdf::hmac::digest::typenum;
pub use hkdf::hmac::digest::Digest;

pub use elliptic_curve;
pub use hkdf;

mod id;
mod key_generator;

mod error;
mod traits;
mod utils;

pub use error::InvalidId;
pub use id::BinaryId;
pub use key_generator::{KeyGenerator, SimpleKeyGenerator};
pub use traits::{CryptoKeyGenerator, EncodedId};

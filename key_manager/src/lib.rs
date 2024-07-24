//! A library that semi-implements a crypto system that is capable of creating
//! encrypted responses to encrypted requests using ECDH and ECDSA.

use private_key_generator::EncodedId;
#[cfg(feature = "zeroize")]
use private_key_generator::Zeroize;

pub use private_key_generator;
pub mod utils;

pub mod error;
mod macros;
pub mod prelude;

pub mod generated;

#[cfg(feature = "server_client_ecdh_ecdsa_mode")]
pub mod server_client_ecdh_ecdsa_mode;

pub use error::ProtocolError;

/// An ID wrapper containing both the BinaryId and the base64 encoded ID.
pub struct Id<IdType: EncodedId> {
    /// The binary-encoded ID
    pub binary_id: IdType,
    /// The base64-encoded ID or hex-encoded ID
    pub encoded_id: String,
    associated_data: Vec<u8>,
}

impl<I: EncodedId> Id<I> {
    /// Creates a new Id instance of a Binary Id, encoded Id, and an
    /// associated_data Option
    pub fn new(binary_id: &I, encoded_id: String, associated_data: Option<&[u8]>) -> Self {
        Self {
            binary_id: binary_id.clone(),
            encoded_id,
            associated_data: associated_data.unwrap_or(&[]).to_owned(),
        }
    }

    /// Creates a new Id instance of a Binary Id, encoded Id, and an
    /// associated_data Vec
    pub fn new_from_vec(binary_id: &I, encoded_id: String, associated_data: Vec<u8>) -> Self {
        Self {
            binary_id: binary_id.clone(),
            encoded_id,
            associated_data,
        }
    }
}

#[cfg(feature = "zeroize")]
impl<I: EncodedId> Zeroize for Id<I> {
    fn zeroize(&mut self) {
        self.binary_id.as_mut().zeroize();
        self.encoded_id.zeroize()
    }
}

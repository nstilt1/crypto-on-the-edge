use aead::Error as AeadError;
use base64::DecodeError as B64DecodeError;
use private_key_generator::ecdsa::signature::Error as SigningError;
use private_key_generator::{elliptic_curve::Error as EcError, error::IdCreationError, InvalidId};
use prost::DecodeError;

/// An error arising from our protocol.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    /// We were unable to decode the request from Protobuf encoding
    InvalidProtobufMessage(DecodeError),
    InvalidId(InvalidId),
    InvalidPublicKey,
    AeadError,
    /// `encrypt_and_sign` was called without calling `decrypt_and_hash` first
    NoRequestToRespondTo,
    Base64DecodeError(B64DecodeError),
    ClientIdNotSet,
    CanOnlyRegenerateIdDuringHandshake,
    InvalidRequest(String),
    IdCreationError(IdCreationError),
    /// This should only happen if the hash function size is incorrect
    SigningError,
}

impl From<DecodeError> for ProtocolError {
    fn from(value: DecodeError) -> Self {
        Self::InvalidProtobufMessage(value)
    }
}

impl From<InvalidId> for ProtocolError {
    fn from(value: InvalidId) -> Self {
        Self::InvalidId(value)
    }
}

impl From<EcError> for ProtocolError {
    fn from(_: EcError) -> Self {
        Self::InvalidPublicKey
    }
}

impl From<AeadError> for ProtocolError {
    fn from(_: AeadError) -> Self {
        Self::AeadError
    }
}

impl From<IdCreationError> for ProtocolError {
    fn from(value: IdCreationError) -> Self {
        Self::IdCreationError(value)
    }
}

impl From<B64DecodeError> for ProtocolError {
    fn from(value: B64DecodeError) -> Self {
        Self::Base64DecodeError(value)
    }
}

impl From<SigningError> for ProtocolError {
    fn from(_value: SigningError) -> Self {
        Self::SigningError
    }
}

impl core::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        #[cfg(not(debug_assertions))]
        let msg = match self {
            Self::InvalidId(v) => v.to_string(),
            Self::InvalidPublicKey => "Your public key was invalid".into(),
            Self::InvalidProtobufMessage(v) => v.to_string(),
            Self::Base64DecodeError(v) => v.to_string(),
            Self::ClientIdNotSet => "You must successfully call 'decrypt_and_hash_request()' \
                                     prior to calling this function"
                .into(),
            Self::SigningError => "There was a signature error. Perhaps the digest size didn't \
                                   match the signing key"
                .into(),
            Self::InvalidRequest(v) => format!("Invalid request: {}", v),
            _ => "".to_string(),
        };
        #[cfg(debug_assertions)]
        let msg = match self {
            Self::InvalidId(v) => v.to_string(),
            Self::InvalidPublicKey => "Your public key was invalid".into(),
            Self::InvalidProtobufMessage(v) => v.to_string(),
            Self::Base64DecodeError(v) => v.to_string(),
            Self::ClientIdNotSet => "You must successfully call 'decrypt_and_hash_request()' \
                                     prior to calling this function"
                .into(),
            Self::SigningError => "There was a signature error. Perhaps the digest size didn't \
                                   match the signing key"
                .into(),
            Self::InvalidRequest(v) => format!("Invalid request: {}", v),
            Self::AeadError => "There was an AEAD error".into(),
            _ => "".to_string(),
        };
        f.write_str(&msg)
    }
}

impl std::error::Error for ProtocolError {}

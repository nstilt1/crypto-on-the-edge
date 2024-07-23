/// Some information that is necessary to decrypt the request
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DecryptInfo {
    /// the ecdh key used for decrypting the request
    #[prost(bytes = "vec", tag = "1")]
    pub server_ecdh_key_id: ::prost::alloc::vec::Vec<u8>,
    /// the `info` string for use in an HKDF for decrypting the request
    #[prost(bytes = "vec", tag = "3")]
    pub ecdh_info: ::prost::alloc::vec::Vec<u8>,
    /// the `salt` string for use in an HKDF for decrypting the request
    #[prost(bytes = "vec", tag = "4")]
    pub ecdh_salt: ::prost::alloc::vec::Vec<u8>,
    /// the client's ecdh pubkey for decrypting the request. This can
    /// be PEM encoded or DER encoded
    #[prost(oneof = "decrypt_info::ClientEcdhPubkey", tags = "5, 6")]
    pub client_ecdh_pubkey: ::core::option::Option<decrypt_info::ClientEcdhPubkey>,
}
/// Nested message and enum types in `DecryptInfo`.
pub mod decrypt_info {
    /// the client's ecdh pubkey for decrypting the request. This can
    /// be PEM encoded or DER encoded
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum ClientEcdhPubkey {
        #[prost(string, tag = "5")]
        Pem(::prost::alloc::string::String),
        #[prost(bytes, tag = "6")]
        Der(::prost::alloc::vec::Vec<u8>),
    }
}
/// An API request to the Service.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Request {
    /// this value allows the client to decide which symmetric encryption
    /// algorithm will be used for the request and response. The server may
    /// reject the request if the value here is unacceptable.
    #[prost(string, tag = "1")]
    pub symmetric_algorithm: ::prost::alloc::string::String,
    /// the client's ID, or their desired prefix for their ID based on whether
    /// this is the initial handshake or not
    #[prost(string, tag = "2")]
    pub client_id: ::prost::alloc::string::String,
    /// Encrypted payload with the nonce prefixed to the encrypted data
    #[prost(bytes = "vec", tag = "3")]
    pub data: ::prost::alloc::vec::Vec<u8>,
    /// Information to decrypt the request
    #[prost(message, optional, tag = "4")]
    pub decryption_info: ::core::option::Option<DecryptInfo>,
    /// The ECDSA key ID that the server will use to sign its response
    #[prost(bytes = "vec", tag = "5")]
    pub server_ecdsa_key_id: ::prost::alloc::vec::Vec<u8>,
    /// the timestamp, in seconds since UNIX_EPOCH
    #[prost(uint64, tag = "6")]
    pub timestamp: u64,
}

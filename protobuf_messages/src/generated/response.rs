/// Some ecdh key information
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EcdhKey {
    #[prost(bytes = "vec", tag = "1")]
    pub ecdh_key_id: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub ecdh_public_key: ::prost::alloc::vec::Vec<u8>,
    #[prost(string, tag = "3")]
    pub ecdh_public_key_pem: ::prost::alloc::string::String,
}
/// An API response from the service.
///
/// To decrypt `data`, you will need to use the same ECDH private key
/// and ECDH public key that was used to encrypt the `data` field of
/// the request.
///
/// There will be a signature stored in the `Signature` header, which is
/// computed from a hash of this encoded structure.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Response {
    /// Encrypted payload with the nonce prefixed to the encrypted data
    #[prost(bytes = "vec", tag = "2")]
    pub data: ::prost::alloc::vec::Vec<u8>,
    /// The protobuf-encoded key information for the client to use for their next
    /// request
    #[prost(message, optional, tag = "5")]
    pub next_ecdh_key: ::core::option::Option<EcdhKey>,
    /// the timestamp, in seconds since UNIX_EPOCH
    #[prost(uint64, tag = "6")]
    pub timestamp: u64,
}

//! Some macros.

/// Conditionally puts out debugging messages based on the "logging" feature.
#[macro_export]
macro_rules! error_log {
    ($($arg:tt)*) => {{
        #[cfg(feature = "logging")]
        tracing::error!($($arg)*);
    }};
}

#[macro_export]
macro_rules! debug_log {
    ($str:expr) => {
        #[cfg(feature = "logging")]
        tracing::debug!($str)
    };
}

/// Defines a `handle_crypto` function that selects a symmetric encryption
/// algorithm at runtime for decrypting the request and encrypting the response.
///
/// # Arguments
///
/// * `request_type` - the Protobuf payload that the request is meant to have,
///   and it is the first argument type that `process_request` needs to have.
/// * `response_type` - the Protobuf payload that the response is meant to have,
///   and it is the output type that `process_request` needs to have.
/// * `error_type` - the error type returned by the `handle_crypto` function.
///   This error type needs to be able to convert the `prost::DecodeError` into
///   itself, as well as this crate's errors.
/// * `hash_function` - the hash function that will be used for signing and
///   verifying the request and response
/// * `signature_type` - the signature type that will be returned by the
///   `handle_crypto` function, such as `p384::ecdsa::Signature`.
/// * `(symmetric_alg_name, symmetric_alg)` - the lowercase symmetric encryption
///   algorithm names and their associated types
///
/// # Example
///
/// ```ignore
/// impl_handle_crypto!(
///     CreateLicenseRequest, // the protobuf message request data
///     CreateLicenseResponse,// the output of `process_request`
///     ApiError,             // the error type of handle_crypto
///     sha2::Sha384,          // the ECDSA digest type
///     p384::ecdsa::Signature,
///     ("chacha20poly1305", ChaCha20Poly1305), // The symmetric ciphers
///     ("aes-128-gcm", Aes128Gcm),             // that you choose to allow
///     ("aes-256-gcm", Aes256Gcm)              // for processing requests
/// );
///
/// async fn process_request<D: Digest + FixedOutput>(
///     key_manager: &mut KeyManager,
///     request: &mut CreateLicenseRequest,
///     hasher: D,
///     signature: Vec<u8>
/// ) -> Result<CreateLicenseResponse, ApiError> {
///     
/// ```
#[macro_export]
macro_rules! impl_handle_crypto {
    ($request_type:ty, $response_type:ty, $error_type:ty, $hash_function:ty, $signature_type:ty, $(($symmetric_alg_name:expr, $symmetric_alg:ty)),*) => {
        /// This function uses a match statement to select a symmetric encryption algorithm, then it:
        ///
        /// * decodes the request to a `Request` with length delimiting
        /// * decrypts the payload within the Request
        /// * sends the decrypted request and hash to `process_request`
        /// * Takes the output of `process_request` and encrypts it, returning the protobuf-encoded `Response` and binary signature.
        async fn handle_crypto(
            key_manager: &mut KeyManager,
            request_bytes: &[u8],
            is_handshake: bool,
            signature: Vec<u8>
        ) -> Result<($crate::Response, $signature_type), ApiError> {
            let mut request = $crate::Request::decode_length_delimited(request_bytes)?;
            let chosen_symmetric_algorithm = request.symmetric_algorithm.to_lowercase();
            match chosen_symmetric_algorithm.as_str() {
                $(
                    $symmetric_alg_name => {
                        let (mut decrypted, hasher) = key_manager.decrypt_and_hash_request::<$symmetric_alg, $hash_function, $request_type>(&mut request, request_bytes, is_handshake)?;
                        let mut output = process_request(key_manager, &mut decrypted, hasher, signature).await?;
                        let (response, signature) = key_manager.encrypt_and_sign_response::<$symmetric_alg, $response_type>(&mut output)?;
                        Ok((response, signature))
                    }
                )*
                _ => return Err($crate::error::ProtocolError::InvalidRequest("Invalid symmetric encryption algorithm".into()).into())
            }
        }
    };
}

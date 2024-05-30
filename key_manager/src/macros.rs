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

/// Processes a request with a symmetric algorithm chosen by the client from a
/// list of algorithms.
///
/// This could be done with a hash algorithm as well as an elliptic curve, but
/// that would take a bit more code. The easiest thing to do might be to make
/// different versions of the same function using generic parameters.
///
/// # Arguments
///
/// * `key_manager` - the HttpPrivateKeyManager
/// * `func_to_call` - the function that will be called to process the inner
///   content. It needs to take the following parameters and needs to output a
///   `DecryptedOutput`:
///   * `&mut HttpPrivateKeyManager`
///   * `DecryptedOutput` ($request)
///   * `$hasher`
/// * `request` - the request Protobuf Message
/// * `request_bytes` - the bytes of the Protobuf Request, used for hashing
/// * `decrypted_inner_request_type` - the inner request that `$func_to_call` is
///   expecting as input
/// * `response` - the response type
/// * `hasher` - the hash function to use for verifying the signature
/// * `signature` - the signature on the request (possibly in the header) that
///   will need to be validated in `func_to_call`
/// * `chosen_symmetric_alg` - the user's chosen symmetric encryption algorithm.
///   `ChaCha20Poly1305` is faster on `aarch64`
/// * `is_handshake` - whether or not this request is supposed to be an initial
///   handshake
/// * `(name, alg)` - a series of tuples of (str, ty) where the str is the
///   string representation of the symmetric algorithm name, and the type is the
///   AEAD type corresponding to the name
#[macro_export]
macro_rules! process_request_with_symmetric_algorithm {
    (
        $key_manager:expr,
        $func_to_call:ident,
        $request:expr,
        $request_bytes:expr,
        $decrypted_inner_request_type:ty,
        $response:ty,
        $hasher:ty,
        $signature:expr,
        $chosen_symmetric_alg:expr,
        $is_handshake:expr,
        $(($name:expr, $alg:ty)),*) => { {
            match $chosen_symmetric_alg {
                $(
                    $name => {
                        let (mut decrypted, hasher) = $key_manager.decrypt_and_hash_request::<$alg, $hasher, $decrypted_inner_request_type>($request, $request_bytes, $is_handshake)?;
                        $crate::debug_log!("Sending output to function within macro");
                        let mut output = $func_to_call($key_manager, &mut decrypted, hasher, $signature).await?;

                        $key_manager.encrypt_and_sign_response::<$alg, $response>(&mut output)?
                    },
                )*
                _ => return Err($crate::error::ProtocolError::InvalidRequest("Invalid symmetric encryption algorithm".into()))?
            }
        }
    };
}

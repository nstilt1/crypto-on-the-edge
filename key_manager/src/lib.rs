//! A library that semi-implements a crypto system that is capable of creating
//! encrypted responses to encrypted requests using ECDH and ECDSA.

use core::marker::PhantomData;
use private_key_generator::{
    ecdsa::{hazmat::DigestPrimitive, signature::Signer, EcdsaCurve, Signature, SignatureSize},
    elliptic_curve::{
        array::ArraySize,
        ops::Invert,
        point::PointCompression,
        sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint},
        subtle::CtOption,
        zeroize::{Zeroize, ZeroizeOnDrop},
        AffinePoint, CurveArithmetic, FieldBytesSize, JwkParameters, PublicKey, Scalar,
    },
    hkdf::hmac::digest::{core_api::BlockSizeUser, Output as HashOutput},
    typenum::Unsigned,
    CryptoKeyGenerator, Digest, EncodedId,
};
use std::time::{SystemTime, UNIX_EPOCH};

use aead::{Aead, AeadCore, AeadInPlace, KeyInit};

use rand_core::{CryptoRngCore, SeedableRng};

use core::cmp::min;

use base64::{
    alphabet::Alphabet,
    engine::{GeneralPurpose, GeneralPurposeConfig},
    Engine,
};
use prost::Message;

pub use private_key_generator;

mod error;
mod request;
mod response;

pub use error::ProtocolError;
pub use request::*;
pub use response::*;

/// Short-hand for making a new key manager from a key generator
macro_rules! new_key_manager {
    ($key_gen:expr, $b64:expr) => {
        Self {
            key_generator: $key_gen,
            symmetric_key: Vec::new(),
            nonce: Vec::new(),
            rng: FastRng::from_entropy(),
            client_id: CId::default(),
            ecdsa_key_id: KId::default(),
            is_handshake: false,
            _ecdh: PhantomData,
            _ecdh_kdf: PhantomData,
            _ecdsa: PhantomData,
            b64_engine: $b64,
        }
    };
}

/// A private key manager.
///
/// This struct is capable of decrypting and then responding with encrypted HTTP
/// API requests. It is possible to cache this data structure and reuse it for
/// multiple requests, but it is also possible to spin up an instance of this
/// data structure in a split second with a serverless API. If you don't trust
/// the machine your code is running on, you might want to ensure that this data
/// structure does not persist longer than is necessary.
///
/// # Generic Arguments
///
/// * `KeyGen` - the `CryptoKeyGenerator` type that you will use
/// * `Ecdh` - the ECDH curve you want to use
/// * `EcdhKdfDigest` - The digest to use in an HKDF during ECDH
/// * `Ecdsa` - the ECDSA curve you want to use
/// * `ClientId` - the ID type for your clients
/// * `KeyId` - the ID type for your keys
///
/// # Examples
/// ```rust
/// ```
pub struct HttpPrivateKeyManager<KeyGen, Ecdh, EcdhKdfDigest, Ecdsa, ClientId, KeyId, FastRng>
where
    KeyGen: CryptoKeyGenerator,
    Ecdh: CurveArithmetic + JwkParameters + PointCompression,
    FieldBytesSize<Ecdh>: ModulusSize,
    AffinePoint<Ecdh>: FromEncodedPoint<Ecdh> + ToEncodedPoint<Ecdh>,
    EcdhKdfDigest: BlockSizeUser + Clone + Digest,
    Ecdsa: EcdsaCurve + CurveArithmetic + JwkParameters + DigestPrimitive,
    Scalar<Ecdsa>: Invert<Output = CtOption<Scalar<Ecdsa>>>,
    SignatureSize<Ecdsa>: ArraySize,
    ClientId: EncodedId,
    KeyId: EncodedId,
    FastRng: CryptoRngCore + SeedableRng,
{
    /// the key generator. You may use this directly if you need to.
    pub key_generator: KeyGen,
    // the symmetric key that will be reused once when encrypting the response
    symmetric_key: Vec<u8>,
    // the nonce that was used with the request
    nonce: Vec<u8>,
    // the rng we will used for generating IDs. It does not need to be super secure, and it does
    // not need to be zeroized since IDs could be public facing
    pub rng: FastRng,
    client_id: ClientId,
    // the current ecdsa key ID for this request
    ecdsa_key_id: KeyId,
    // determines whether the current instance is dealing with a handshake
    is_handshake: bool,
    _ecdh: PhantomData<Ecdh>,
    _ecdh_kdf: PhantomData<EcdhKdfDigest>,
    _ecdsa: PhantomData<Ecdsa>,
    /// the base64 engine this struct uses
    pub b64_engine: GeneralPurpose,
}

impl<KeyGen, Ecdh, EcdhKdf, Ecdsa, CId, KId, FastRng>
    HttpPrivateKeyManager<KeyGen, Ecdh, EcdhKdf, Ecdsa, CId, KId, FastRng>
where
    KeyGen: CryptoKeyGenerator,
    Ecdh: CurveArithmetic + JwkParameters + PointCompression,
    FieldBytesSize<Ecdh>: ModulusSize,
    AffinePoint<Ecdh>: FromEncodedPoint<Ecdh> + ToEncodedPoint<Ecdh>,
    EcdhKdf: BlockSizeUser + Clone + Digest,
    Ecdsa: EcdsaCurve + CurveArithmetic + JwkParameters + DigestPrimitive,
    Scalar<Ecdsa>: Invert<Output = CtOption<Scalar<Ecdsa>>>,
    SignatureSize<Ecdsa>: ArraySize,
    CId: EncodedId,
    KId: EncodedId,
    FastRng: CryptoRngCore + SeedableRng,
{
    /// Initializes this structure using your Key Generator.
    ///
    /// # Arguments
    ///
    /// * `key_generator` - an instance of a `CryptoKeyGenerator`
    /// * `base64_alphabet` - your chosen Base64 alphabet
    /// * `base64_config` - the Base64 configuration you want to use. `NO_PAD`
    ///   is recommended
    pub fn from_key_generator(
        key_generator: KeyGen,
        base64_alphabet: Alphabet,
        base64_config: GeneralPurposeConfig,
    ) -> Self {
        // TODO: update this once there are new Base64 engines available with SIMD
        new_key_manager!(
            key_generator,
            GeneralPurpose::new(&base64_alphabet, base64_config)
        )
    }

    /// Generates ECDH public keys and IDs in bulk using the struct's RNG.
    ///
    /// Unfortunately, this is not much more efficient than just generating them
    /// yourself.
    ///
    /// # Arguments
    ///
    /// * `count` - the amount of public keys you want to generate
    /// * `expiration` - the expiration time of these new keys
    pub fn generate_ecdh_pubkeys_and_ids(
        &mut self,
        count: usize,
        expiration: Option<u64>,
    ) -> Vec<(KId, PublicKey<Ecdh>)> {
        let mut output: Vec<(KId, PublicKey<Ecdh>)> = Vec::with_capacity(count);

        for _ in 0..count {
            output.push(self.key_generator.generate_ecdh_pubkey_and_id::<Ecdh, KId>(
                &[],
                expiration,
                None,
                &mut self.rng,
            ));
        }

        output
    }

    /// Decrypts and hashes a request.
    ///
    /// Use the hash to verify the signature.
    ///
    /// # Generic Arguments
    ///
    /// * `Aead` - the AEAD used to decrypt the request
    /// * `Hasher` - the Hash function used to hash the request
    /// * `DecryptedOutput` - the Protocol Buffer message that the request
    ///   should contain
    ///
    /// # Arguments
    ///
    /// * `request_payload` - the binary representation of the request's body
    /// * `is_handshake` - set this to true if your API method solely handles
    ///   handshakes. If true, this will generate a new client ID for the user,
    ///   which you can fetch with `get_client_id()` and you can regenerate it
    ///   with `regenerate_client_id()` if the ID has a collision with an
    ///   existing ID in your database
    pub fn decrypt_and_hash_request<Aead, Hasher, DecryptedOutput>(
        &mut self,
        request_payload: &[u8],
        is_handshake: bool,
    ) -> Result<(DecryptedOutput, HashOutput<Hasher>), ProtocolError>
    where
        Aead: AeadCore + KeyInit + AeadInPlace,
        Hasher: Digest,
        DecryptedOutput: Message + ZeroizeOnDrop + Default,
    {
        self.is_handshake = is_handshake;
        let mut request = Request::decode(request_payload)?;

        // reject a request if the ClientID is longer than 2 times our ID length. If it
        // was originally encoded in base64, it wouldn't be much larger than 133% of the
        // length
        if request.client_id.len() > CId::IdLen::USIZE << 1 {
            return Err(ProtocolError::InvalidRequest);
        }

        let decrypt_info = request.decryption_info.unwrap();

        // generate a new client ID if this is the first handshake; otherwise, update
        // self to contain the client ID
        if is_handshake {
            // truncate the user-supplied prefix to reduce the amount of data we have to
            // decode. This will be truncated again by the key_generator
            let truncated_prefix_len: usize =
                min(request.client_id.len(), CId::MAX_PREFIX_LEN << 1);

            let mut truncated_prefix: Vec<u8> = Vec::with_capacity(truncated_prefix_len);

            let prefix = if truncated_prefix_len > 0 {
                // decode prefix to binary
                let decoded_len = self
                    .b64_engine
                    .decode_slice(
                        &request.client_id[..truncated_prefix_len],
                        &mut truncated_prefix,
                    )
                    .expect("a base64 decode output has a length less than or equal to the input");

                // fill the remaining space with random bits instead of 0s. Base64 uses 6 bits
                // per Base64 character, leaving any unused space as 0s. Changing these 0s to
                // random bits will not change the client's chosen prefix
                let unused_bits = (truncated_prefix_len * 6) & 0b0111;

                if unused_bits > 0 {
                    truncated_prefix[decoded_len - 1] |=
                        self.rng.next_u32() as u8 & ((1 << unused_bits) - 1);
                }

                &truncated_prefix.as_slice()[..decoded_len]
            } else {
                &[]
            };

            self.client_id = self.key_generator.generate_keyless_id(
                prefix,
                b"client ID",
                None,
                None,
                &mut self.rng,
            );
        } else {
            // validate the client's ID
            self.client_id = self.key_generator.validate_keyless_id(
                request.client_id.as_bytes(),
                b"client ID",
                None,
            )?
        }

        // validate signing key ID. If we wanted to... we could associate the signing
        // key with a client. Not entirely sure how useful it would be, but it doesn't
        // cost anything to include the client's ID here during validation
        self.ecdsa_key_id = self.key_generator.validate_ecdsa_key_id::<Ecdsa, KId>(
            request.server_ecdsa_key_id.as_slice(),
            Some(self.client_id.as_ref()),
        )?;

        let associated_data = request.client_id.as_bytes();

        let ecdh_key_id = self
            .key_generator
            .validate_ecdh_key_id::<KId>(&decrypt_info.server_ecdh_key_id, Some(associated_data))?;

        let client_public_key =
            PublicKey::<Ecdh>::from_sec1_bytes(&decrypt_info.client_ecdh_pubkey)?;

        let shared_secret = self.key_generator.ecdh_using_key_id(
            &ecdh_key_id,
            Some(associated_data),
            client_public_key,
        );

        let kdf = shared_secret.extract::<EcdhKdf>(Some(&decrypt_info.ecdh_salt));

        if self.symmetric_key.capacity() < Aead::KeySize::USIZE {
            self.symmetric_key = Vec::with_capacity(Aead::KeySize::USIZE);
        }

        kdf.expand(&decrypt_info.ecdh_info, &mut self.symmetric_key)
            .expect("Key size should be smaller than 256 bytes");

        self.nonce = request.data[..Aead::NonceSize::USIZE].to_vec();

        let key = aead::Key::<Aead>::from_slice(&self.symmetric_key);

        let decryptor = Aead::new(key);

        decryptor.decrypt_in_place_detached(
            self.nonce.as_slice().try_into().unwrap(),
            associated_data,
            &mut request.data[Aead::NonceSize::USIZE..],
            &aead::Tag::<Aead>::default(),
        )?;

        let mut hasher = Hasher::new();
        hasher.update(request_payload);
        let hash = hasher.finalize();

        let output = Ok((
            DecryptedOutput::decode(&request.data[Aead::NonceSize::USIZE..])?,
            hash,
        ));

        request.data.zeroize();

        output
    }

    /// Encrypts and signs a response.
    ///
    /// Pass in the AEAD you wish to encrypt the request with, and this will
    /// return `(EncryptedPayload, Hash, Signature)`
    ///
    /// # Generic Parameters
    ///
    /// * `Aead_` - the AEAD you wish to encrypt the response with. Ideally this
    ///   will be the same one used to decrypt the response.
    /// * `Hasher` - the hash function you wish to use prior to signing the
    ///   response.
    ///
    /// # Parameters
    ///
    /// * `response` - the Protocol Buffer message that you wish to encrypt.
    ///   Ensure that it zeroizes on drop and implements ZeroizeOnDrop
    ///
    /// # Panics
    /// This panics when `encrypt_and_sign_response()` is called prior to
    /// calling `decrypt_and_hash_request()` for a given KeyManager struct.
    pub fn encrypt_and_sign_response<Aead_, Hasher, InputData>(
        &mut self,
        response: &mut InputData,
    ) -> Result<(Response, HashOutput<Hasher>, Signature<Ecdsa>), ProtocolError>
    where
        Aead_: AeadCore + KeyInit + Aead,
        Hasher: Digest,
        InputData: Message + ZeroizeOnDrop,
    {
        if !self.has_decrypted_request() {
            return Err(ProtocolError::NoRequestToRespondTo);
        }

        let key = aead::Key::<Aead_>::from_slice(&self.symmetric_key);

        let mut plaintext = response.encode_to_vec();

        // the server will be skipping a random nonce generation in favor of simply
        // using a different nonce. Because the client should pick different nonces for
        // each request, and this will suffice given that the client should be picking a
        // different ephemeral key, and they will be receiving a new ECDH key as part of
        // this response
        for (i, n) in self.nonce.iter_mut().enumerate() {
            *n = n.wrapping_add(i as u8);
        }

        let encryptor = Aead_::new(key);
        let mut encrypted = encryptor.encrypt(
            &self.nonce.as_slice().try_into().unwrap(),
            plaintext.as_slice(),
        )?;

        plaintext.zeroize();

        encrypted.splice(0..0, self.nonce.drain(..));

        self.symmetric_key.zeroize();

        let (key_id, pubkey) = self.key_generator.generate_ecdh_pubkey_and_id::<Ecdh, KId>(
            &[],
            None,
            Some(self.client_id.as_ref()),
            &mut self.rng,
        );

        let next_key = EcdhKey {
            ecdh_key_id: key_id.as_ref().to_vec(),
            ecdh_public_key: pubkey.to_sec1_bytes().as_ref().to_vec(),
        };

        let resp = Response {
            data: encrypted,
            next_ecdh_key: Some(next_key),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        let mut hasher = Hasher::new();
        hasher.update(resp.encode_to_vec().as_slice());
        let hash = hasher.finalize();

        let signer = self.key_generator.generate_ecdsa_key_from_id::<Ecdsa, KId>(
            &self.ecdsa_key_id,
            Some(self.client_id.as_ref()),
        );

        let signature = signer.sign(&hash);

        // reset state to prepare for the next request, if there is one
        self.is_handshake = false;
        self.ecdsa_key_id = KId::default();
        self.client_id = CId::default();
        Ok((resp, hash, signature))
    }

    /// A simple function that determines whether we have decrypted a request
    /// yet. This is mainly used to prevent misuse.
    #[inline]
    fn has_decrypted_request(&self) -> bool {
        self.symmetric_key.len().eq(&0)
    }

    /// Returns the client's ID in its Binary Encoding.
    ///
    /// It might be preferable to hash this function's output prior to storing
    /// it in your database. If there is a collision, you can regenerate the ID
    /// using `regenerate_client_id()`.
    ///
    /// # Errors
    /// This returns an error if you haven't already called
    /// `decrypt_and_hash_request()`
    pub fn get_client_id_slice(&self) -> Result<&[u8], ProtocolError> {
        if !self.has_decrypted_request() {
            return Err(ProtocolError::ClientIdNotSet);
        }
        Ok(self.client_id.as_ref())
    }

    /// Regenerates the client's ID.
    ///
    /// This might be useful if there was a collision with the first generated
    /// ID. The probability of this should be extremely small; the probability
    /// is determined by the ID's `IdLen`, `HmacLen`, and `MAX_PREFIX_LEN`. This
    /// is intended to be called during the first handshake, before the
    /// response.
    ///
    /// # Errors
    /// This returns an error if you haven't already called
    /// `decrypt_and_hash_request()` during this session.
    ///
    /// It will also return an error if you call this function and the current
    /// request is not during a handshake. The client's ID probably shouldn't
    /// need to change once their ID has already been established.
    pub fn regenerate_client_id(&mut self) -> Result<&[u8], ProtocolError> {
        if !self.has_decrypted_request() {
            return Err(ProtocolError::ClientIdNotSet);
        }
        if !self.is_handshake {
            return Err(ProtocolError::CanOnlyRegenerateIdDuringHandshake);
        }
        // we will keep the original prefix bytes for simplicity, regardless of whether
        // the client's desired prefix had a length shorter than the maximum length
        let prefix = self.client_id.as_ref()[..CId::MAX_PREFIX_LEN].to_vec();
        self.client_id = self.key_generator.generate_keyless_id(
            prefix.as_slice(),
            b"client ID",
            None,
            None,
            &mut self.rng,
        );
        Ok(self.client_id.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decryption_and_decoding() {}

    #[test]
    fn zeroize_vec_mechanics() {
        let mut vec: Vec<u8> = Vec::new();
        assert_eq!(vec.capacity(), 0);

        vec = Vec::with_capacity(32);

        for i in 0..32 {
            vec.push(i);
        }

        assert_eq!(vec.capacity(), 32);

        vec.zeroize();

        assert_eq!(vec.capacity(), 32);

        assert_eq!(vec.len(), 0);
    }
}

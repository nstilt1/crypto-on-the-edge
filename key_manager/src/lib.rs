//! A library that semi-implements a crypto system that is capable of creating
//! encrypted responses to encrypted requests using ECDH and ECDSA.

use core::marker::PhantomData;
use private_key_generator::{
    ecdsa::{
        hazmat::DigestPrimitive, signature::DigestSigner, EcdsaCurve, Signature, SignatureSize,
        SigningKey,
    },
    elliptic_curve::{
        array::ArraySize,
        ops::Invert,
        pkcs8::AssociatedOid,
        point::PointCompression,
        sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint},
        subtle::CtOption,
        AffinePoint, CurveArithmetic, FieldBytesSize, JwkParameters, PublicKey, Scalar,
    },
    error::IdCreationError,
    hkdf::hmac::digest::core_api::BlockSizeUser,
    typenum::Unsigned,
    CryptoKeyGenerator, Digest, EncodedId,
};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(feature = "zeroize")]
use private_key_generator::Zeroize;

use aead::{Aead, AeadCore, AeadInPlace, KeyInit};

use rand_core::{CryptoRng, SeedableRng};

use base64::{
    alphabet::Alphabet,
    engine::{self, GeneralPurpose},
    Engine,
};
use prost::Message;

pub use private_key_generator;
pub mod utils;
use utils::{b64_len_to_binary_len, padding_trail, StringSanitization};

pub mod error;
mod macros;
pub mod prelude;
mod request;
mod response;

pub use error::ProtocolError;
pub use request::*;
pub use response::*;

/// Short-hand for making a new key manager from a key generator
macro_rules! new_key_manager {
    ($key_gen:expr, $b64:expr, $b64_alphabet:expr) => {
        Self {
            key_generator: $key_gen,
            symmetric_key: Vec::new(),
            nonce: Vec::new(),
            rng: FastRng::from_entropy(),
            client_id: CId::default(),
            ecdsa_key_id: EcdsaKId::default(),
            is_handshake: false,
            _ecdh: PhantomData,
            _ecdh_key_id: PhantomData,
            _ecdh_kdf: PhantomData,
            _ecdsa: PhantomData,
            _ecdsa_digest: PhantomData,
            b64_engine: $b64,
            base64_alphabet: $b64_alphabet,
        }
    };
}

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
/// * `EcdhKeyId` - the ID type for your ECDH keys
/// * `EcdsaKeyId` - the ID type for your ECDSA Keys
/// * `FastRng` - any RNG that impls `CrytpoRngCore` and `SeedableRng`
///
/// # Examples
/// ```rust
/// ```
pub struct HttpPrivateKeyManager<
    KeyGen,
    Ecdh,
    EcdhKdfDigest,
    Ecdsa,
    EcdsaDigest,
    ClientId,
    EcdhKeyId,
    EcdsaKeyId,
    FastRng,
> where
    KeyGen: CryptoKeyGenerator,
    Ecdh: CurveArithmetic + JwkParameters + PointCompression + AssociatedOid,
    FieldBytesSize<Ecdh>: ModulusSize,
    AffinePoint<Ecdh>: FromEncodedPoint<Ecdh> + ToEncodedPoint<Ecdh>,
    EcdhKdfDigest: BlockSizeUser + Clone + Digest,
    Ecdsa: EcdsaCurve + CurveArithmetic + JwkParameters,
    EcdsaDigest: Digest,
    Scalar<Ecdsa>: Invert<Output = CtOption<Scalar<Ecdsa>>>,
    SignatureSize<Ecdsa>: ArraySize,
    ClientId: EncodedId,
    EcdhKeyId: EncodedId,
    EcdsaKeyId: EncodedId,
    FastRng: CryptoRng + SeedableRng,
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
    ecdsa_key_id: EcdsaKeyId,
    // determines whether the current instance is dealing with a handshake
    is_handshake: bool,
    _ecdh: PhantomData<Ecdh>,
    _ecdh_key_id: PhantomData<EcdhKeyId>,
    _ecdh_kdf: PhantomData<EcdhKdfDigest>,
    _ecdsa: PhantomData<Ecdsa>,
    _ecdsa_digest: PhantomData<EcdsaDigest>,
    /// the base64 engine this struct uses
    pub b64_engine: GeneralPurpose,
    base64_alphabet: Alphabet,
}

impl<KeyGen, Ecdh, EcdhKdf, Ecdsa, EcdsaDigest, CId, EcdhKId, EcdsaKId, FastRng>
    HttpPrivateKeyManager<
        KeyGen,
        Ecdh,
        EcdhKdf,
        Ecdsa,
        EcdsaDigest,
        CId,
        EcdhKId,
        EcdsaKId,
        FastRng,
    >
where
    KeyGen: CryptoKeyGenerator,
    Ecdh: CurveArithmetic + JwkParameters + PointCompression + AssociatedOid,
    FieldBytesSize<Ecdh>: ModulusSize,
    AffinePoint<Ecdh>: FromEncodedPoint<Ecdh> + ToEncodedPoint<Ecdh>,
    EcdhKdf: BlockSizeUser + Clone + Digest,
    Ecdsa: EcdsaCurve + CurveArithmetic + JwkParameters + DigestPrimitive,
    EcdsaDigest: Digest,
    Scalar<Ecdsa>: Invert<Output = CtOption<Scalar<Ecdsa>>>,
    SignatureSize<Ecdsa>: ArraySize,
    CId: EncodedId,
    EcdhKId: EncodedId,
    EcdsaKId: EncodedId,
    FastRng: CryptoRng + SeedableRng,
{
    /// Initializes this structure using your Key Generator.
    ///
    /// # Arguments
    ///
    /// * `key_generator` - an instance of a `CryptoKeyGenerator`
    /// * `base64_alphabet` - your chosen Base64 alphabet
    /// * `base64_config` - the Base64 configuration you want to use. `NO_PAD`
    ///   is recommended
    #[inline]
    pub fn from_key_generator(key_generator: KeyGen, base64_alphabet: Alphabet) -> Self {
        // base64 config for no padding
        let config = engine::GeneralPurposeConfig::new()
            .with_decode_allow_trailing_bits(true)
            .with_encode_padding(false)
            .with_decode_padding_mode(engine::DecodePaddingMode::Indifferent);
        new_key_manager!(
            key_generator,
            engine::GeneralPurpose::new(&base64_alphabet, config),
            base64_alphabet
        )
    }

    /// Decodes and truncates an ID prefix.
    ///
    /// Returns (decoded, truncate_len)
    #[inline]
    fn decode_and_truncate_prefix<IdType: EncodedId>(&self, prefix: &str) -> (Vec<u8>, usize) {
        // trimming length to MAX_PREFIX_LEN * 2 in case there are any invalid
        // characters in the user's chosen prefix I know that I could trim after
        // sanitizing, but I don't want to call sanitize_str() on an arbitrarily large
        // string
        let mut sanitized_prefix = prefix
            .trim_length(IdType::MAX_PREFIX_LEN << 1)
            .sanitize_str(self.base64_alphabet.as_str());
        let original_len = sanitized_prefix.len();

        sanitized_prefix = padding_trail(&sanitized_prefix);

        let mut decoded = vec![0u8; b64_len_to_binary_len(sanitized_prefix.len())];
        self.b64_engine
            .decode_slice(sanitized_prefix, &mut decoded)
            .expect(
                "We have sanitized and padded the prefix, as well as ensured that the length is \
                 correct.",
            );

        (decoded, b64_len_to_binary_len(original_len))
    }

    /// Generates a keyless id with an optional prefix, associated data, and
    /// expiration.
    ///
    /// The difference between `KeyManager::generate_keyless_id` and
    /// `key_generator::generate keyless_id` is that this method encodes the ID
    /// in base64 with the chosen alphabet.
    ///
    /// # Arguments
    ///
    /// - `IdType` - the ID type you wish to create.
    /// - `prefix` - a potentially user-supplied prefix, which will be sanitized
    ///   in this function
    /// - `id_type` - an arbitrary ID type that must be supplied when verifying
    ///   the ID
    /// - `expiration` - the expiration date for the ID. This function can
    ///   return an error if the specified ID type always or never uses an
    ///   expiration
    /// - `associated_data` - any associated data you wish to bind this ID to
    ///
    /// # Errors
    ///
    /// Returns an error if the expiration date is too far ahead, or if the
    /// expiration Option is incompatible with the `IdType`'s `TimestampPolicy`.
    #[inline]
    pub fn generate_keyless_id<IdType: EncodedId>(
        &mut self,
        prefix: &str,
        id_type: &[u8],
        expiration: Option<u64>,
        associated_data: Option<&[u8]>,
    ) -> Result<Id<IdType>, IdCreationError> {
        let (decoded_prefix, truncate_len) = self.decode_and_truncate_prefix::<IdType>(prefix);

        let id = self.key_generator.generate_keyless_id::<IdType>(
            &decoded_prefix[..truncate_len],
            id_type,
            expiration,
            associated_data,
            &mut self.rng,
        )?;
        let encoded = self.b64_engine.encode(id.as_ref());
        Ok(Id::new(&id, encoded, associated_data))
    }

    /// Generates an ECDSA key id with an optional prefix, associated data, and
    /// expiration.
    ///
    /// The difference between `KeyManager::generate_ecdsa_key_and_id` and
    /// `key_generator::generate ecdsa_key_and_id` is that this method encodes
    /// the ID in base64 with the chosen alphabet.
    ///
    /// # Arguments
    ///
    /// - `C` - the ECDSA curve that the key is for
    /// - `IdType` - the ID type you wish to create.
    /// - `prefix` - a potentially user-supplied prefix, which will be sanitized
    ///   in this function
    /// - `expiration` - the expiration date for the ID. This function can
    ///   return an error if the specified ID type always or never uses an
    ///   expiration
    /// - `associated_data` - any associated data you wish to bind this ID to
    ///
    /// # Errors
    ///
    /// Returns an error if the expiration date is too far ahead, or if the
    /// expiration Option is incompatible with the `IdType`'s `TimestampPolicy`.
    #[inline]
    pub fn generate_ecdsa_key_and_id<C, IdType>(
        &mut self,
        prefix: &str,
        expiration: Option<u64>,
        associated_data: Option<&[u8]>,
    ) -> Result<(Id<IdType>, SigningKey<C>), IdCreationError>
    where
        C: EcdsaCurve + JwkParameters + CurveArithmetic,
        Scalar<C>: Invert<Output = CtOption<Scalar<C>>>,
        SignatureSize<C>: ArraySize,
        IdType: EncodedId,
    {
        let (decoded_prefix, truncate_len) = self.decode_and_truncate_prefix::<IdType>(prefix);

        let (id, key) = self.key_generator.generate_ecdsa_key_and_id::<C, IdType>(
            &decoded_prefix[..truncate_len],
            expiration,
            associated_data,
            &mut self.rng,
        )?;
        let encoded = self.b64_engine.encode(id.as_ref());
        Ok((Id::new(&id, encoded, associated_data), key))
    }

    /// Validates an ECDSA key id.
    ///
    /// The difference between `KeyManager::validate_ecdsa_key_id` and
    /// `key_generator::generate ecdsa_key_and_id` is that this method encodes
    /// the ID in base64 with the chosen alphabet.
    ///
    /// # Arguments
    ///
    /// - `C` - the curve that the ID is for
    /// - `IdType` - the ID type you wish to create.
    /// - `associated_data` - any associated data you wish to bind this ID to
    ///
    /// # Errors
    ///
    /// Returns an error if the expiration date is too far ahead, or if the
    /// expiration Option is incompatible with the `IdType`'s `TimestampPolicy`.
    #[inline]
    pub fn validate_ecdsa_key_id<C, IdType>(
        &mut self,
        id: &str,
        associated_data: Option<&[u8]>,
    ) -> Result<Id<IdType>, ProtocolError>
    where
        C: EcdsaCurve + JwkParameters + CurveArithmetic,
        Scalar<C>: Invert<Output = CtOption<Scalar<C>>>,
        SignatureSize<C>: ArraySize,
        IdType: EncodedId,
    {
        // trimming length to a size greater than the ID length because there could be
        // extra chars, such as dashes
        let sanitized = id
            .trim_length(IdType::IdLen::USIZE << 1)
            .sanitize_str(self.base64_alphabet.as_str());

        let decoded = self
            .b64_engine
            .decode(sanitized)
            .expect("We have sanitized the id");
        let binary_id = self
            .key_generator
            .validate_ecdsa_key_id::<C, IdType>(&decoded, associated_data)?;
        Ok(Id::new(&binary_id, id.to_string(), associated_data))
    }

    /// Validates an ECDSA key id.
    ///
    /// The difference between `KeyManager::validate_ecdsa_key_id` and
    /// `key_generator::generate ecdsa_key_and_id` is that this method encodes
    /// the ID in base64 with the chosen alphabet.
    ///
    /// # Arguments
    ///
    /// - `C` - the curve that the ID is for
    /// - `IdType` - the ID type you wish to create.
    /// - `associated_data` - any associated data you wish to bind this ID to
    ///
    /// # Errors
    ///
    /// Returns an error if the expiration date is too far ahead, or if the
    /// expiration Option is incompatible with the `IdType`'s `TimestampPolicy`.
    #[inline]
    pub fn validate_keyless_id<IdType>(
        &mut self,
        id: &str,
        id_type: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Id<IdType>, ProtocolError>
    where
        IdType: EncodedId,
    {
        // trimming length to a size greater than the ID length because there could be
        // extra chars, such as dashes
        let sanitized = id
            .trim_length(IdType::IdLen::USIZE << 1)
            .sanitize_str(self.base64_alphabet.as_str());

        let decoded = self
            .b64_engine
            .decode(sanitized)
            .expect("We have sanitized the id");
        let binary_id =
            self.key_generator
                .validate_keyless_id::<IdType>(&decoded, id_type, associated_data)?;
        Ok(Id::new(&binary_id, id.to_string(), associated_data))
    }

    /// Signs data with a signing key derived from a key ID.
    #[inline]
    pub fn sign_data_with_key_id<C, KeyId, Hash>(
        &mut self,
        data: &[u8],
        key_id: &Id<KeyId>,
    ) -> Result<Signature<C>, ProtocolError>
    where
        C: EcdsaCurve + CurveArithmetic + JwkParameters + DigestPrimitive,
        Scalar<C>: Invert<Output = CtOption<Scalar<C>>>,
        SignatureSize<C>: ArraySize,
        KeyId: EncodedId,
        Hash: Digest,
    {
        let signing_key = self.key_generator.generate_ecdsa_key_from_id::<C, KeyId>(
            &key_id.binary_id,
            Some(&key_id.associated_data),
        );
        let (signature, _): (Signature<C>, _) =
            signing_key.try_sign_digest(Hash::new_with_prefix(data))?;
        Ok(signature)
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
    ///
    /// # Errors
    ///
    /// Returns an error if there is an issue with the expiration time, such as
    /// if it:
    ///
    /// * should or should not be present based on the EcdhKey Id type's
    ///   specifications
    /// * is larger than MAX_KEY_EXPIRATION_TIME
    #[inline]
    pub fn generate_ecdh_pubkeys_and_ids(
        &mut self,
        count: usize,
        expiration: Option<u64>,
    ) -> Result<Vec<(EcdhKId, PublicKey<Ecdh>)>, ProtocolError> {
        let mut output: Vec<(EcdhKId, PublicKey<Ecdh>)> = Vec::with_capacity(count);

        for _ in 0..count {
            output.push(
                self.key_generator
                    .generate_ecdh_pubkey_and_id::<Ecdh, EcdhKId>(
                        &[],
                        expiration,
                        None,
                        &mut self.rng,
                    )?,
            );
        }

        Ok(output)
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
    #[inline]
    pub fn decrypt_and_hash_request<Aead, Hasher, DecryptedOutput>(
        &mut self,
        request: &mut Request,
        request_bytes: &[u8],
        is_handshake: bool,
    ) -> Result<(DecryptedOutput, Hasher), ProtocolError>
    where
        Aead: AeadCore + KeyInit + AeadInPlace,
        Hasher: Digest,
        DecryptedOutput: Message + Default,
    {
        debug_log!("In decrypt_and_hash_request");
        self.is_handshake = is_handshake;

        // reject a request if the ClientID is longer than 2 times our ID length. If it
        // was originally encoded in base64, it wouldn't be much larger than 133% of the
        // length
        if request.client_id.len() > CId::IdLen::USIZE << 1 {
            return Err(ProtocolError::InvalidRequest(
                "Client ID is too long.".into(),
            ));
        }
        debug_log!("About to get decryptption_info");
        let decrypt_info = request
            .decryption_info
            .as_ref()
            .expect("Decryption info is missing");

        // generate a new client ID if this is the first handshake; otherwise, update
        // self to contain the client ID
        if is_handshake {
            debug_log!("Generating a client ID");
            let (decoded_prefix, truncate_len) =
                self.decode_and_truncate_prefix::<CId>(&request.client_id);

            self.client_id = self.key_generator.generate_keyless_id(
                &decoded_prefix[..truncate_len],
                b"client ID",
                None,
                None,
                &mut self.rng,
            )?;
        } else {
            debug_log!("Validating a client ID");
            // validate the client's ID
            self.client_id = self
                .validate_keyless_id(&request.client_id, b"client ID", None)?
                .binary_id
        }

        debug_log!("Validing an ecdsa_key_id");
        // validate signing key ID. If we wanted to... we could associate the signing
        // key with a client. Not entirely sure how useful it would be, but it doesn't
        // cost anything to include the client's ID here during validation
        self.ecdsa_key_id = self
            .key_generator
            .validate_ecdsa_key_id::<Ecdsa, EcdsaKId>(
                request.server_ecdsa_key_id.as_slice(),
                Some(self.client_id.as_ref()),
            )?;

        let associated_data = request.client_id.as_bytes();

        debug_log!("Validating an ECDH Key ID");
        let ecdh_key_id = self.key_generator.validate_ecdh_key_id::<EcdhKId>(
            &decrypt_info.server_ecdh_key_id,
            Some(associated_data),
        )?;

        debug_log!("Setting client_public_key");
        let client_public_key =
            PublicKey::<Ecdh>::from_sec1_bytes(&decrypt_info.client_ecdh_pubkey)?;

        debug_log!("Getting the shared_secret");
        let shared_secret = self.key_generator.ecdh_using_key_id(
            &ecdh_key_id,
            Some(associated_data),
            client_public_key,
        );

        debug_log!("Initialized KDF");
        let kdf = shared_secret.extract::<EcdhKdf>(Some(&decrypt_info.ecdh_salt));

        if self.symmetric_key.len() != Aead::KeySize::USIZE {
            self.symmetric_key = vec![0u8; Aead::KeySize::USIZE];
        }

        debug_log!("Expanding symmetric key");
        kdf.expand(&decrypt_info.ecdh_info, &mut self.symmetric_key)
            .expect("Key size should be smaller than 256 bytes");

        self.nonce = request.data[..Aead::NonceSize::USIZE].to_vec();

        let key = aead::Key::<Aead>::from_slice(&self.symmetric_key);

        let decryptor = Aead::new(key);

        debug_log!("Decrypting payload");

        #[allow(unused_mut)]
        let mut decrypted = decryptor.decrypt(
            self.nonce.as_slice().into(),
            &request.data[Aead::NonceSize::USIZE..],
        )?;
        //let decrypt_result =
        // decryptor.decrypt_in_place_detached(self.nonce.as_slice().try_into().
        // unwrap(), associated_data, &mut
        // request.data[Aead::NonceSize::USIZE..tag_index], &tag);

        debug_log!("Initialized hasher");
        let hasher = Hasher::new_with_prefix(request_bytes);

        debug_log!("Decoding decrypted_data");
        let decoded = DecryptedOutput::decode_length_delimited(decrypted.as_slice())?;

        let output = Ok((decoded, hasher));

        #[cfg(feature = "zeroize")]
        decrypted.zeroize();

        debug_log!("Returned result in decrypt_and_hash_request");
        output
    }

    /// Encrypts and signs a response.
    ///
    /// Pass in the AEAD you wish to encrypt the request with, and this will
    /// return `(EncryptedPayload, Signature)`.
    ///
    /// This used to return a hash as well, but the clients will hash this
    /// themselves anyway.
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
    /// * `response` - the Protocol Buffer message that you wish to encrypt. You
    ///   might want it to impl ZeriozeOnDrop
    ///
    /// # Panics
    /// This panics when `encrypt_and_sign_response()` is called prior to
    /// calling `decrypt_and_hash_request()` for a given KeyManager struct.
    #[inline]
    pub fn encrypt_and_sign_response<Aead_, InputData>(
        &mut self,
        response: &mut InputData,
    ) -> Result<(Response, Signature<Ecdsa>), ProtocolError>
    where
        Aead_: AeadCore + KeyInit + Aead,
        InputData: Message,
    {
        if !self.has_decrypted_request() {
            return Err(ProtocolError::NoRequestToRespondTo);
        }

        let key = aead::Key::<Aead_>::from_slice(&self.symmetric_key);

        #[allow(unused_mut)]
        let mut plaintext = response.encode_length_delimited_to_vec();

        // the server will be skipping a random nonce generation in favor of simply
        // using a different nonce. Because the client should pick different nonces for
        // each request, and this will suffice given that the client should be picking a
        // different ephemeral key, and they will be receiving a new ECDH key as part of
        // this response
        for (i, n) in self.nonce.iter_mut().enumerate() {
            *n = n.wrapping_add(i as u8);
        }

        let encryptor = Aead_::new(key);
        let mut encrypted =
            encryptor.encrypt(self.nonce.as_slice().into(), plaintext.as_slice())?;

        // TODO: update AEAD crate
        //let mut encrypted =
        // encryptor.encrypt(&self.nonce.as_slice().try_into().unwrap(),
        // plaintext.as_slice())?;

        #[cfg(feature = "zeroize")]
        plaintext.zeroize();

        encrypted.splice(0..0, self.nonce.drain(..));

        #[cfg(feature = "zeroize")]
        self.symmetric_key.zeroize();

        let (key_id, pubkey) = self
            .key_generator
            .generate_ecdh_pubkey_and_id::<Ecdh, EcdhKId>(
                &[],
                None,
                Some(self.client_id.as_ref()),
                &mut self.rng,
            )?;

        let next_key = EcdhKey {
            ecdh_key_id: key_id.as_ref().to_vec(),
            ecdh_public_key: pubkey.to_sec1_bytes().as_ref().to_vec(),
            ecdh_public_key_pem: pubkey.to_string(),
        };

        let resp = Response {
            data: encrypted,
            next_ecdh_key: Some(next_key),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        let signer = self
            .key_generator
            .generate_ecdsa_key_from_id::<Ecdsa, EcdsaKId>(
                &self.ecdsa_key_id,
                Some(self.client_id.as_ref()),
            );

        let (signature, _): (Signature<Ecdsa>, _) = signer.try_sign_digest(
            EcdsaDigest::new_with_prefix(resp.encode_length_delimited_to_vec().as_slice()),
        )?;

        // reset state to prepare for the next request, if there is one
        self.is_handshake = false;
        self.ecdsa_key_id = EcdsaKId::default();
        self.client_id = CId::default();
        Ok((resp, signature))
    }

    /// A simple function that determines whether we have decrypted a request
    /// yet. This is mainly used to prevent misuse.
    #[inline]
    fn has_decrypted_request(&self) -> bool {
        self.symmetric_key.len().ne(&0)
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
    #[inline]
    pub fn get_client_id_as_slice(&self) -> Result<&[u8], ProtocolError> {
        if !self.has_decrypted_request() {
            return Err(ProtocolError::ClientIdNotSet);
        }
        Ok(self.client_id.as_ref())
    }

    /// Gets the client ID.
    ///
    /// This must be called after a request is decrypted.
    #[inline]
    pub fn get_client_id(&self) -> Result<Id<CId>, ProtocolError> {
        if !self.has_decrypted_request() {
            return Err(ProtocolError::ClientIdNotSet);
        }

        Ok(Id::new(
            &self.client_id,
            self.b64_engine.encode(self.client_id.as_ref()),
            None,
        ))
    }

    /// Sets the client ID.
    ///
    /// This must be called after a request is decrypted.
    #[inline]
    pub fn set_client_id(&mut self, id: &CId) -> Result<(), ProtocolError> {
        if !self.has_decrypted_request() {
            return Err(ProtocolError::ClientIdNotSet);
        }
        Ok(self.client_id = id.clone())
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
    #[inline]
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
        )?;
        Ok(self.client_id.as_ref())
    }

    /// Encrypts a resource.
    ///
    /// This stores a version and nonce in the first few bytes of the encrypted
    /// data so that the key can be rotated, decreasing the chance of nonce+key
    /// reuse.
    ///
    /// # Arguments
    ///
    /// * `data` - the data to be encrypted
    /// * `resource_id` - some information about the resource, which helps
    ///   ensure that the key is unique
    /// * `client_id` - some information about the client, which also helps
    ///   ensure that the key is unique
    /// * `misc_info` - some misc info that helps ensure that the key is unique.
    ///   Pass in an empty slice if you don't have any more.
    #[inline]
    pub fn encrypt_resource<Aead_>(
        &mut self,
        data: &[u8],
        resource_id: &[u8],
        client_id: &[u8],
        misc_info: &[u8],
    ) -> Result<Vec<u8>, ProtocolError>
    where
        Aead_: AeadCore + KeyInit + Aead,
    {
        let mut key = aead::Key::<Aead_>::default();
        let version = self.key_generator.generate_resource_encryption_key(
            resource_id,
            client_id,
            misc_info,
            &mut key,
        );
        let mut nonce = aead::Nonce::<Aead_>::default();
        self.rng.fill_bytes(&mut nonce);
        let encryptor = Aead_::new(&key);
        let mut encrypted = encryptor.encrypt(&nonce, data)?;
        let mut prefix = [&version, nonce.as_slice()].concat();
        encrypted.splice(0..0, prefix.drain(..));
        Ok(encrypted)
    }

    /// Decrypts a resource.
    ///
    /// This stores a version and nonce in the first few bytes of the encrypted
    /// data so that the key can be rotated, decreasing the chance of nonce+key
    /// reuse.
    ///
    /// # Arguments
    ///
    /// * `data` - the data to be decrypted
    /// * `resource_id` - some information about the resource. This must be the
    ///   same data that was provided when it was encrypted.
    /// * `client_id` - some information about the client. This must be the same
    ///   data that was provided when it was encrypted.
    /// * `misc_info` - some misc info that helps ensure that the key is unique.
    ///   This must be the same data that was provided when it was encrypted.
    #[inline]
    pub fn decrypt_resource<Aead_>(
        &mut self,
        data: &[u8],
        resource_id: &[u8],
        client_id: &[u8],
        misc_info: &[u8],
    ) -> Result<Vec<u8>, ProtocolError>
    where
        Aead_: AeadCore + KeyInit + Aead,
    {
        debug_log!("In decrypt_resource()");
        let mut key = aead::Key::<Aead_>::default();
        self.key_generator.generate_resource_decryption_key(
            resource_id,
            client_id,
            misc_info,
            &data[..4]
                .try_into()
                .expect("Tried decrypting a resource that was not encrypted correctly"),
            &mut key,
        );
        debug_log!("Generated resource decryption key");

        let nonce: &aead::Nonce<Aead_> = data[4..4 + Aead_::NonceSize::USIZE].into();

        let decryptor = Aead_::new(&key);
        let decrypted = decryptor.decrypt(&nonce, &data[4 + Aead_::NonceSize::USIZE..])?;
        debug_log!("Decrypted the resource");
        Ok(decrypted)
    }
}

#[cfg(test)]
mod tests {
    use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
    use p384::{ecdh::EphemeralSecret, NistP384};
    use private_key_generator::hkdf::hmac::Hmac;
    use rand_core_previous::OsRng;

    use crate::prelude::*;
    use sha2::Sha384;

    use super::*;

    type BigId = BinaryId<U48, U8, 6, use_timestamps::Sometimes>;
    type EcdsaKeyId = BinaryId<U48, U10, 6, use_timestamps::Always>;

    type TestVersionConfig =
        VersioningConfig<0, { years_to_seconds(1) }, 32, 32, 8, { years_to_seconds(1) }>;
    type TestKeyGen = KeyGenerator<Hmac<Sha384>, TestVersionConfig, ChaCha8Rng, Sha384>;
    type TestKeyManager = HttpPrivateKeyManager<
        TestKeyGen,
        NistP384,
        Sha384,
        NistP384,
        Sha384,
        BigId,
        BigId,
        EcdsaKeyId,
        ChaCha8Rng,
    >;

    fn init_key_manager() -> TestKeyManager {
        TestKeyManager::from_key_generator(
            TestKeyGen::new(&[32u8; 48], b"software licensor"),
            Alphabet::new("qwertyuiopasdfghjklzxcvbnm1234567890QWERTYUIOPASDFGHJKLZXCVBNM/_")
                .unwrap(),
        )
    }

    #[test]
    fn decryption_and_decoding() {
        let mut server_key_manager = init_key_manager();
        let server_ecdh_keys: (BigId, PublicKey<NistP384>) = server_key_manager
            .generate_ecdh_pubkeys_and_ids(1, None)
            .unwrap()[0]
            .clone();

        let (server_ecdsa_key_id, _server_ecdsa_key) = server_key_manager
            .generate_ecdsa_key_and_id::<NistP384, EcdsaKeyId>(
                "test",
                Some(
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs()
                        + years_to_seconds(1),
                ),
                None,
            )
            .unwrap();

        let client_key = EphemeralSecret::random(&mut OsRng);

        let ecdh_info = b"test_info".to_vec();
        let ecdh_salt = b"test salt".to_vec();
        let inner = Request {
            symmetric_algorithm: "chacha20poly1305".into(),
            client_id: "Handshake".into(),
            data: Vec::new(),
            decryption_info: Some(DecryptInfo {
                server_ecdh_key_id: server_ecdh_keys.0.as_ref().to_vec(),
                client_ecdh_pubkey: client_key.public_key().to_sec1_bytes().to_vec(),
                ecdh_info: ecdh_info.clone(),
                ecdh_salt: ecdh_salt.clone(),
            }),
            server_ecdsa_key_id: server_ecdsa_key_id.binary_id.as_ref().to_vec(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };
        let mut outer = inner.clone();

        let mut key = Key::default();
        let shared_secret = client_key.diffie_hellman(&server_ecdh_keys.1);
        let kdf = shared_secret.extract::<Sha384>(Some(ecdh_salt.as_slice()));
        kdf.expand(ecdh_info.as_slice(), &mut key)
            .expect("This key should be small enough");

        let nonce = Nonce::default();
        let encryptor = ChaCha20Poly1305::new(&key);
        let mut encrypted_payload = encryptor
            .encrypt(&nonce, inner.encode_length_delimited_to_vec().as_slice())
            .unwrap();
        encrypted_payload.splice(0..0, nonce);
        assert_eq!(&encrypted_payload[..nonce.len()], &nonce.to_vec());
        outer.data = encrypted_payload;

        let outer_cloned = outer.clone();

        // decrypt with function
        let decrypt_output = server_key_manager
            .decrypt_and_hash_request::<ChaCha20Poly1305, Sha384, Request>(
                &mut outer,
                &outer_cloned.encode_length_delimited_to_vec(),
                true,
            );

        assert!(
            decrypt_output.is_ok(),
            "Encountered error: {}",
            decrypt_output.unwrap_err().to_string()
        );

        let (inner, _hasher) = decrypt_output.unwrap();
        assert_eq!(inner.client_id, "Handshake");
    }

    #[test]
    fn ecdh_tests() {
        let private_key = EphemeralSecret::random(&mut OsRng);
        let mut server_key_manager = init_key_manager();
        let server_ecdh_keys: (BigId, PublicKey<NistP384>) = server_key_manager
            .generate_ecdh_pubkeys_and_ids(1, None)
            .unwrap()[0]
            .clone();
        let shared_secret = private_key.diffie_hellman(&server_ecdh_keys.1);

        let server_shared_secret = server_key_manager.key_generator.ecdh_using_key_id(
            &server_ecdh_keys.0,
            None,
            private_key.public_key(),
        );

        assert_eq!(
            &server_shared_secret.raw_secret_bytes(),
            &shared_secret.raw_secret_bytes()
        );

        let ecdh_salt = b"fe";
        let ecdh_info = b"ecdh info";
        let client_kdf = shared_secret.extract::<Sha384>(Some(ecdh_salt));
        let mut client_key = [0u8; 32];
        client_kdf.expand(ecdh_info, &mut client_key).unwrap();

        let server_kdf = server_shared_secret.extract::<Sha384>(Some(ecdh_salt));
        let mut server_key = [0u8; 32];
        server_kdf.expand(ecdh_info, &mut server_key).unwrap();

        assert_eq!(server_key, client_key);
    }

    #[test]
    fn resource_encryption_and_decryption_roundtrip() {
        let data = b"test test test";
        let test_resource_id = b"resource id";
        let client_id = b"client ID";
        let misc_info = b"misc info";
        let mut key_manager = init_key_manager();
        let encrypted = key_manager
            .encrypt_resource::<ChaCha20Poly1305>(data, test_resource_id, client_id, misc_info)
            .unwrap();

        let decrypted = key_manager
            .decrypt_resource::<ChaCha20Poly1305>(
                encrypted.as_slice(),
                test_resource_id,
                client_id,
                misc_info,
            )
            .unwrap();

        assert_eq!(data, decrypted.as_slice());
    }

    #[test]
    #[cfg(feature = "zeroize")]
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

    #[test]
    fn generation_and_validation() {
        let mut key_manager = init_key_manager();
        let ecdsa_key = key_manager
            .generate_ecdsa_key_and_id::<NistP384, BigId>("", None, None)
            .unwrap();
        let bytes = ecdsa_key.0.binary_id;
        let result = key_manager
            .key_generator
            .validate_ecdsa_key_id::<NistP384, BigId>(
                bytes.as_ref(),
                Some(b"this should not affect the validation"),
            );
        assert!(result.is_ok())
    }

    /// Initializes a generic key manager with a generic key generator.
    macro_rules! init_generic_key_manager {
        ($key_manager:ty, $key_generator:ty) => {
            <$key_manager>::from_key_generator(
                <$key_generator>::new(&[32u8; 48], b"software licensor"),
                Alphabet::new("qwertyuiopasdfghjklzxcvbnm1234567890QWERTYUIOPASDFGHJKLZXCVBNM/_")
                    .unwrap(),
            )
        };
    }

    /// This test should ensure that resource decryption is possible after
    /// different versions pass. I will accomplish this using different
    /// Version Configs that have different epochs.
    #[test]
    fn db_decryption_with_different_versions() {
        type TemplateVersionConfig<const EPOCH: u64> = VersioningConfig<
            EPOCH,
            { years_to_seconds(5) }, // version lifetime
            32,                      // version bits
            32,                      // timestamp bits
            8,                       // timestamp precision loss
            { years_to_seconds(1) }, // max expiration time
        >;

        type OldVersionConfig = TemplateVersionConfig<0>;
        type NewVersionConfig = TemplateVersionConfig<1719159990>; // june 23, 2024
        type KeyGeneratorTemplate<VersionConfig> =
            KeyGenerator<Hmac<Sha384>, VersionConfig, ChaCha8Rng, Sha384>;

        type OldKeyGenerator = KeyGeneratorTemplate<OldVersionConfig>;
        type NewKeyGenerator = KeyGeneratorTemplate<NewVersionConfig>;

        type KeyManagerTemplate<KeyGeneratorTemp> = HttpPrivateKeyManager<
            KeyGeneratorTemp,
            NistP384,
            Sha384,
            NistP384,
            Sha384,
            BigId,
            BigId,
            BigId,
            ChaCha8Rng,
        >;

        let mut old_key_manager =
            init_generic_key_manager!(KeyManagerTemplate<OldKeyGenerator>, OldKeyGenerator);

        let data = [5u8; 256];
        let resource_id = [1, 1, 2, 3, 5, 8, 13, 21];
        let client_id = [1, 2, 3, 4, 5, 6];
        let encrypted = old_key_manager
            .encrypt_resource::<ChaCha20Poly1305>(&data, &resource_id, &client_id, &[])
            .unwrap();

        assert_ne!(&encrypted, &data);

        let mut new_key_manager =
            init_generic_key_manager!(KeyManagerTemplate<NewKeyGenerator>, NewKeyGenerator);

        let decrypted = new_key_manager
            .decrypt_resource::<ChaCha20Poly1305>(&encrypted, &resource_id, &client_id, &[])
            .unwrap();

        assert_eq!(&data, &decrypted.as_slice());
    }
}

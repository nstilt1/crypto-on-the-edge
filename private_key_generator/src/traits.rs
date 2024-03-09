//! A few traits that could be used as generic arguments.

use crate::error::InvalidId;
use ecdsa::{EcdsaCurve, SignatureSize, SigningKey};
use elliptic_curve::{
    ecdh::SharedSecret,
    ops::Invert,
    rand_core::RngCore,
    sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint},
    AffinePoint, CurveArithmetic, FieldBytesSize, JwkParameters, PublicKey, Scalar,
};
use hkdf::hmac::digest::{
    array::{Array, ArraySize},
    OutputSizeUser,
};
use subtle::CtOption;

/// A trait for encoded IDs.
///
/// IDs of this type do not consist solely of random bytes. The ID is encoded
/// with a version number, a bit to determine if the ID's HMAC was computed with
/// extra data, a bit to determine whether there is an expiration timestamp, an
/// expiration timestamp if there is one, and a truncated HMAC.
pub trait EncodedId:
    AsRef<[u8]> + AsMut<[u8]> + for<'a> TryFrom<&'a [u8], Error = InvalidId>
{
    /// The length of the ID in bytes
    const ID_LEN: usize;
    /// The metadata start index
    const METADATA_IDX: usize;
    /// The length of the HMAC within the ID in bytes.
    const HMAC_LENGTH: usize;
    /// The HMAC start index.
    const HMAC_START_INDEX: usize;
    /// The version of this ID
    const VERSION: u8;
    /// The maximum prefix length for this ID
    const MAX_PREFIX_LEN: usize;

    /// The ID type, used for initializing an empty ID array
    type IdBytes: AsRef<[u8]> + AsMut<[u8]>;

    /// The HMAC byte array type, used for initializing an empty HMAC array for
    /// validation of a given ID.
    type HmacBytes: AsRef<[u8]> + AsMut<[u8]> + Default;

    /// A function that generates a pseudorandom ID, with an empty HMAC.
    fn generate(
        prefix: &[u8],
        expire_time: Option<u64>,
        uses_associated_data: bool,
        rng: &mut dyn RngCore,
    ) -> Self;

    /// This method attempts to get the "version" of a given Id byte slice.
    ///
    /// Just because this method returns a value does not mean that this is a
    /// valid ID. It only extracts the supposed "version" at index
    /// `METADATA_IDX`. Different versions of IDs could have a different hash
    /// function, or a different HMAC key or PRK, or a different length of the
    /// ID.
    ///
    /// This method will only return an error if the id's length is smaller than
    /// `METADATA_IDX`.
    fn get_version(id: &[u8]) -> Result<u8, InvalidId>;

    /// Checks if the ID is meant to expire, and returns the expiration time if
    /// it does.
    fn get_expiration_time(&self) -> Option<u64>;

    /// Validates the expiration time of the ID. It does not validate anything
    /// else.
    ///
    /// This only works with the `std` feature, but if you aren't using `std`
    /// and you are able to get the seconds since EPOCH, you could still use
    /// `get_expiration_time()` to manually check the expiration, or you could
    /// refrain from using expiring key IDs.
    fn validate_expiration_time(&self) -> Result<(), InvalidId>;

    /// Checks the "info byte" to see if the HMAC should be computed using any
    /// additional associated data. This could include a "client id" for when
    /// only a specific client should use the ID.
    fn uses_associated_data(&self) -> bool;
}

/// Defines some methods for the `KeyGenerator` so that this can be used in
/// another library.
pub trait CryptoKeyGenerator: Sized {
    /// The digest used within the HMAC of the HKDF
    type HmacDigest: OutputSizeUser;

    /// A convenience method for [extract()](CryptoKeyGenerator::extract) that
    /// discards the PRK value.
    ///
    /// See [Hkdf::new()](hkdf::Hkdf::new).
    fn new(hmac_key: &[u8], application_id: &[u8]) -> Self {
        let (_, hkdf) = Self::extract(hmac_key, application_id);
        hkdf
    }

    /// Creates a new `CryptoKeyGenerator` using an `hmac_key` and
    /// `application_id`, returning the pseudorandom key from the
    /// [HKDF::extract()](hkdf::Hkdf::extract) operation.
    ///
    /// # Arguments
    ///
    /// * `hmac_key` - the HMAC key used to initialize the HKDF. This should be
    ///   a minimum length of the hash function's output, and a maximum length
    ///   of the hash function's internal buffer[^note].
    /// * `application_id` - an arbitrary application-specific value which does
    ///   not need to be an actual identifier.
    ///
    /// # Recommended key length bounds
    /// Here are the recommended minimum and maximum key length boundaries for
    /// some common hash functions.
    ///
    /// | Hash     | Output Size | Internal Buffer Size |
    /// |----------|-------------|----------------------|
    /// | sha2_224 | 28 bytes    | 64 bytes             |
    /// | sha2_256 | 32 bytes    | 64 bytes             |
    /// | sha2_384 | 48 bytes    | 128 bytes            |
    /// | sha2_512 | 64 bytes    | 128 bytes            |
    /// | sha3_224 | 28 bytes    | 144 bytes            |
    /// | sha3_256 | 32 bytes    | 136 bytes            |
    /// | sha3_384 | 48 bytes    | 104 bytes            |
    /// | sha3_512 | 64 bytes    | 72 bytes             |
    ///
    /// Some notes about HMAC key lengths from [RFC 2104](https://datatracker.ietf.org/doc/html/rfc2104#section-3):
    /// * keys shorter than the `Output Size` will be less secure
    /// * keys longer than the `Internal Buffer Size` will be hashed to the
    ///   `Output Size` length.
    /// * keys longer than the `Output Size` are acceptable, but this is
    ///   primarily viable for lower-entropy HMAC keys
    fn extract(
        hmac_key: &[u8],
        application_id: &[u8],
    ) -> (
        Array<u8, <Self::HmacDigest as OutputSizeUser>::OutputSize>,
        Self,
    );

    /// Initializes a `CryptoKeyGenerator` from a pseudorandom key. See
    /// [Hkdf](hkdf::Hkdf::from_prk).
    ///
    /// You could precompute the `prk` using `CryptoKeyGenerator::new()` to save
    /// a little time, as well as only having a single key to erase when
    /// initializing this type.
    ///
    /// # Arguments
    ///
    /// * `prk` - This value must be cryptographically strong, and the length
    ///   must be at least the output size of the hash function used.
    ///
    /// # Panics
    /// This panics when the `prk`'s length is less than the output size of the
    /// hash function.
    fn from_prk(prk: &[u8]) -> Self;

    /// Generates an ID that is not explicitly used for generating a private
    /// key.
    ///
    /// This function accepts an `expiration` argument, but the most common use
    /// cases might want to consider using `None` for the keyless ID's
    /// expiration time. This argument is only here for flexibility.
    ///
    /// # Arguments
    ///
    /// * `prefix` - the client's desired ID prefix, but it must be decoded to
    ///   binary if it is encoded in Base64 or a similar encoding. It will be
    ///   trimmed to the [maximum prefix length](EncodedId::MAX_PREFIX_LEN)
    ///   specified in the ID type.
    /// * `id_type` - the type of ID. you will need to provide this when
    ///   validating it.
    /// * `rng` - an RNG that will generate the majority of the pseudorandom
    ///   bytes in the ID
    fn generate_keyless_id<Id>(
        &self,
        prefix: &[u8],
        id_type: &[u8],
        expiration: Option<u64>,
        associated_data: Option<&[u8]>,
        rng: &mut dyn RngCore,
    ) -> Id
    where
        Id: EncodedId;

    /// Validates a keyless ID; if the ID is encoded in Base64, you will need to
    /// decode it first.
    ///
    /// This method will attempt to validate an ID based on the ID's length, the
    /// encoded version number, the HMAC, and the `id_type` that you provided
    /// when you generated the ID.
    ///
    /// # Arguments
    ///
    /// * `id` - the binary ID slice
    /// * `id_type` - the type of ID
    fn validate_keyless_id<Id>(
        &self,
        id: &[u8],
        id_type: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Id, InvalidId>
    where
        Id: EncodedId;

    /// Generates an ECDSA Signing Key and a public ECDSA Key ID.
    ///
    /// # Arguments
    ///
    /// * `prefix` - a prefix you or a user wants to be at the front of the ID.
    ///   If you don't have one, supply an empty slice. If you received a prefix
    ///   encoded with Base64 or something similar, decode it to binary first.
    /// * `expiration` - the time that this ECDSA Signing Key should expire, in
    ///   seconds since `UNIX_EPOCH`.
    /// * `associated_data` - any data that you want to be associated with this
    ///   ECDSA key. You will need to supply this data when using
    ///   [generate_ecdsa_key_from_id()](CryptoKeyGenerator::generate_ecdsa_key_from_id).
    /// * `rng` - an RNG that will generate the majority of the pseudorandom
    ///   bytes in the ID
    fn generate_ecdsa_key_and_id<C, Id>(
        &self,
        prefix: &[u8],
        expiration: Option<u64>,
        associated_data: Option<&[u8]>,
        rng: &mut dyn RngCore,
    ) -> (Id, SigningKey<C>)
    where
        C: EcdsaCurve + CurveArithmetic + JwkParameters,
        Scalar<C>: Invert<Output = CtOption<Scalar<C>>>,
        SignatureSize<C>: ArraySize,
        Id: EncodedId;

    /// Validates an ECDSA key ID.
    ///
    /// If you disabled the `std` feature, this will not check for expiration
    /// timestamps, but you can still try to check it using
    /// [EncodedId::get_expiration_time()](EncodedId::get_expiration_time()) if
    /// you are able to get the current time.
    ///
    /// # Arguments
    ///
    /// * `id` - the ECDSA key ID. If this is in Base64, you will need to decode
    ///   it to binary.
    /// * `associated_data` - Any potentially associated data, such as a client
    ///   ID.
    fn validate_ecdsa_key_id<C, Id>(
        &self,
        id: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Id, InvalidId>
    where
        C: EcdsaCurve + CurveArithmetic + JwkParameters,
        Scalar<C>: Invert<Output = CtOption<Scalar<C>>>,
        SignatureSize<C>: ArraySize,
        Id: EncodedId;

    /// Generates an ECDSA private key from an ID. You might want to validate
    /// the ID first.
    ///
    /// # Arguments
    ///
    /// * `id` - the ID you are trying to make a private key with
    /// * `associated_data` - any data that might have been associated with the
    ///   key when it was originally generated with
    ///   [generate_ecdsa_key_and_id()](CryptoKeyGenerator::generate_ecdsa_key_and_id).
    ///
    /// # Panics
    /// Panics if the curve's `FieldBytesSize` is larger than the hash
    /// function's `OutputSize * 255`. This should not happen unless the
    /// `FieldBytesSize` is ridiculously large.
    fn generate_ecdsa_key_from_id<C, Id>(
        &self,
        id: Id,
        associated_data: Option<&[u8]>,
    ) -> SigningKey<C>
    where
        C: EcdsaCurve + CurveArithmetic + JwkParameters,
        Scalar<C>: Invert<Output = CtOption<Scalar<C>>>,
        SignatureSize<C>: ArraySize,
        Id: EncodedId;

    /// Generates an ECDH public key with an optional expiration timestamp and
    /// associated data.
    ///
    /// Notice that this method does not return a private key. It is like this
    /// for two reasons:
    /// 1. `elliptic_curve` does not offer an easy way to do this without
    ///    returning a raw scalar.
    /// 2. This library is designed for a REST API/Service to receive an ECDH
    ///    Key ID from a client in an API request, and use the same ECDH key for
    ///    the response.
    ///
    /// # Arguments
    ///
    /// * `prefix` - a prefix you or a user wants to be at the front of the ID.
    ///   If you don't have one, supply an empty slice. If you received a prefix
    ///   encoded with Base64 or something similar, decode it to binary first.
    /// * `expiration` - the expiration time of the ECDH key in seconds since
    ///   `UNIX_EPOCH`
    /// * `associated_data` - any data that you want to be associated with this
    ///   ECDH key. You will need to supply this data when using
    ///   [ecdh_using_key_id()](CryptoKeyGenerator::ecdh_using_key_id).
    /// * `rng` - an RNG that will generate the majority of the pseudorandom
    ///   bytes in the ID
    ///
    /// # Panics
    /// Panics if the curve's `FieldBytesSize` is larger than the hash
    /// function's `OutputSize * 255`. This should not happen unless the
    /// `FieldBytesSize` is ridiculously large.
    fn generate_ecdh_pubkey_and_id<C, Id>(
        &self,
        prefix: &[u8],
        expiration: Option<u64>,
        associated_data: Option<&[u8]>,
        rng: &mut dyn RngCore,
    ) -> (Id, PublicKey<C>)
    where
        C: CurveArithmetic + JwkParameters,
        FieldBytesSize<C>: ModulusSize,
        AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
        Id: EncodedId;

    /// Attempts to validate an ECDH ID.
    ///
    /// If you disabled the `std` feature, this will not check for expiration
    /// timestamps, but you can still try to check it using
    /// [EncodedId::get_expiration_time()](EncodedId::get_expiration_time()) if
    /// you are able to get the current time.
    ///
    /// # Arguments
    ///
    /// * `id` - the ID you wish to validate
    /// * `associated_data` - any associated data that might be required for the
    ///   HMAC computation.
    fn validate_ecdh_key_id<Id>(
        &self,
        id: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Id, InvalidId>
    where
        Id: EncodedId;

    /// Generates an ECDH key from an ID, and then performs diffie hellman with
    /// a specified Public Key. You might want to validate the ID first.
    ///
    /// # Arguments
    ///
    /// * `id` - the ECDH key ID you want to use for Diffie Hellman.
    /// * `associated_data` - data that may have been associated with this ECDH
    ///   key ID when it was generated with
    ///   [generate_ecdh_pubkey_and_id()](CryptoKeyGenerator::generate_ecdh_pubkey_and_id).
    /// * `pubkey` - the public key you want to perform diffie hellman with
    ///
    /// # Panics
    /// Panics if the curve's `FieldBytesSize` is larger than the hash
    /// function's `OutputSize * 255`. This should not happen unless the
    /// `FieldBytesSize` is ridiculously large.
    fn ecdh_using_key_id<C, Id>(
        &self,
        id: Id,
        associated_data: Option<&[u8]>,
        pubkey: PublicKey<C>,
    ) -> SharedSecret<C>
    where
        C: CurveArithmetic + JwkParameters,
        FieldBytesSize<C>: ModulusSize,
        AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
        Id: EncodedId;

    /// Generates an encryption key for a resource, such as an item in a
    /// database table.
    ///
    /// # Arguments
    ///
    /// * `resource_id` - a resource identifier, such as a table name or table
    ///   ID. Use an empty slice if you don't need to provide this.
    /// * `client_id` - a client's ID. Use an empty slice if you don't need to
    ///   provide this.
    /// * `misc_info` - any other information that you want to derive the key
    ///   with. Use an empty slice if you don't need to provide this.
    /// * `encryption_key` - a mutable slice for the key you want to use.
    ///
    /// # Panics
    /// Panics if the `symmetric_key` size is larger than `255 * Hash Output
    /// Size`.
    fn generate_resource_encryption_key(
        &self,
        resource_id: &[u8],
        client_id: &[u8],
        misc_info: &[u8],
        symmetric_key: &mut [u8],
    );
}

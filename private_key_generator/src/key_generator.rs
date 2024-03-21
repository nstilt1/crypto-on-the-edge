//! A Private Key Generator based on an [HKDF](hkdf::Hkdf).

//use digest::{CtOutput, Output};
use crate::{
    error::InvalidId,
    id::BITS_IN_USE,
    traits::{AllowedRngs, CryptoKeyGenerator},
    u64_mask,
    utils::{extract_ints_from_slice, insert_ints_into_slice},
};
use ecdsa::{
    elliptic_curve::{ops::Invert, CurveArithmetic, FieldBytes, FieldBytesSize, Scalar},
    EcdsaCurve, SignatureSize, SigningKey,
};
use elliptic_curve::{
    ecdh::{diffie_hellman, SharedSecret},
    sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint},
    AffinePoint, JwkParameters, NonZeroScalar, PublicKey,
};
use hkdf::{
    hmac::{
        digest::{
            array::{Array, ArraySize},
            FixedOutputReset, Output, OutputSizeUser,
        },
        Hmac, Mac, SimpleHmac,
    },
    Hkdf, HmacImpl,
};
use rand_core::RngCore;
use subtle::{ConstantTimeEq, CtOption};
use zeroize::Zeroize;

use core::marker::PhantomData;
#[cfg(feature = "std")]
use std::time::{SystemTime, UNIX_EPOCH};

use crate::traits::EncodedId;

/// A convenience type if you wish to use a hash function that does not
/// implement `EagerHash`.
pub type SimpleKeyGenerator<M, V, Rng, H> = KeyGenerator<M, V, Rng, H, SimpleHmac<H>>;

/// A struct containing some constants for versioning.
pub struct VersioningConfig<
    const EPOCH: u64,
    const VERSION_LIFETIME: u64,
    const REQUIRE_EXPIRING_KEYS: bool,
    const MAXIMUM_KEY_EXPIRATION_TIME: u64,
>;

pub trait VersionConfig {
    /// The start time for version 0.
    const EPOCH: u64;
    /// How long each version lasts.
    const VERSION_LIFETIME: u64;
    /// If set to true, any key ID that doesn't have an expiration time will be
    /// rejected.
    const REQUIRE_EXPIRING_KEYS: bool;
    /// The maximum key expiration time is used to reject key IDs whose version
    /// is too old to possibly valid when `REQUIRE_EXPIRING_KEYS` is set to
    /// true. This constant represents the maximum "delta-time" rather than a
    /// maximum "time".
    const MAXIMUM_KEY_EXPIRATION_TIME: u64;

    /// Gets the minimum accepted key id version. The output will change over
    /// time as more versions are made.
    fn get_minimum_accepted_key_id_version(current_version: u32) -> u32 {
        if !Self::REQUIRE_EXPIRING_KEYS {
            0
        } else {
            if Self::VERSION_LIFETIME > Self::MAXIMUM_KEY_EXPIRATION_TIME {
                current_version - 1
            } else if Self::VERSION_LIFETIME < Self::MAXIMUM_KEY_EXPIRATION_TIME {
                current_version
                    - (Self::MAXIMUM_KEY_EXPIRATION_TIME / Self::VERSION_LIFETIME) as u32
                    - 1
            } else {
                current_version - 2
            }
        }
    }
}

impl<
        const EPOCH: u64,
        const VERSION_LIFETIME: u64,
        const REQUIRE_EXPIRING_KEYS: bool,
        const MAXIMUM_KEY_EXPIRATION_TIME: u64,
    > VersionConfig
    for VersioningConfig<
        EPOCH,
        VERSION_LIFETIME,
        REQUIRE_EXPIRING_KEYS,
        MAXIMUM_KEY_EXPIRATION_TIME,
    >
{
    const EPOCH: u64 = EPOCH;
    const VERSION_LIFETIME: u64 = VERSION_LIFETIME;
    const REQUIRE_EXPIRING_KEYS: bool = REQUIRE_EXPIRING_KEYS;
    const MAXIMUM_KEY_EXPIRATION_TIME: u64 = MAXIMUM_KEY_EXPIRATION_TIME;
}

/// A simplified type that allows for ID versions to change every 365.25 days
/// (accounting for leap years).
pub type AnnualVersionConfig<const REQUIRE_EXPIRING_KEYS: bool> =
    VersioningConfig<1_711_039_489, 31_557_600, REQUIRE_EXPIRING_KEYS, 31_557_600>;

/// A Private Key Generator based on an [HKDF](hkdf::Hkdf).
///
/// If this struct is generating any of your private keys, consider using a hash
/// function with a security level that is greater than or equal to the supposed
/// strength of the private keys... also consider using an HSM.
///
/// Generic Arguments:
///
/// * `M` - the type of MAC you want to use. It doesn't need to be super duper
///   secure, as the MACs will be truncated to just a few bytes.
/// * `HkdfDigest` - the hash function you wish to use for the HKDF's HMAC.
/// * `I` - you may not need to supply this, but if the compiler is complaining
///   about a trait called `Eager Hash` not being implemented for your hash
///   function, then you can pass in `SimpleHmac<H>` to the `I` argument, or use
///   `SimpleKeyGenerator<H>`.
///
/// # Examples
///
/// Creating a KeyGenerator using an `EagerHash` user.
/// ```rust
/// use private_key_generator_docs::{CryptoKeyGenerator, KeyGenerator};
/// use sha2::Sha256;
///
/// let key_generator = KeyGenerator::<Sha256>::new(
///     &[42u8; 32],
///     b"my arbitrary application ID that is only used for this",
/// );
/// ```
///
/// Creating a KeyGenerator with a non-`EagerHash` user
/// ```rust
/// use blake2::Blake2s256;
/// use private_key_generator_docs::{CryptoKeyGenerator, SimpleKeyGenerator};
///
/// let key_generator = SimpleKeyGenerator::<Blake2s256>::new(
///     &[42u8; 32],
///     b"arbitrary application ID",
/// );
/// ```
pub struct KeyGenerator<M, V, Rng, HkdfDigest, I = Hmac<HkdfDigest>>
where
    M: Mac + FixedOutputReset,
    V: VersionConfig,
    Rng: AllowedRngs,
    HkdfDigest: OutputSizeUser,
    I: HmacImpl<HkdfDigest>,
{
    /// The internal HKDF this uses, in case you want to access it
    pub hkdf: Hkdf<HkdfDigest, I>,
    mac: M,
    current_version: u32,
    /// The salt for the current version used for the HKDF and MAC
    current_version_salt: Output<HkdfDigest>,
    _versioning_config: PhantomData<V>,
    rng: Rng,
}

impl<M, V, R, HkdfDigest, I> KeyGenerator<M, V, R, HkdfDigest, I>
where
    M: Mac + FixedOutputReset,
    V: VersionConfig,
    R: AllowedRngs,
    HkdfDigest: OutputSizeUser,
    I: HmacImpl<HkdfDigest>,
{
    /// Gets the current version of IDs
    fn get_current_version() -> u32 {
        #[cfg(feature = "std")]
        {
            let diff = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                - V::EPOCH;
            (diff / V::VERSION_LIFETIME) as u32
        }
        #[cfg(not(feature = "std"))]
        {
            0
        }
    }

    /// Updates the current version if it is different
    fn update_version(&mut self) {
        #[cfg(feature = "std")]
        {
            let diff = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                - V::EPOCH;
            let v = (diff / V::VERSION_LIFETIME) as u32;
            if self.current_version != v {
                self.current_version = v;
                self.rng.get_version_salt(v, &mut self.current_version_salt);
            }
        }
    }

    /// Encodes the version and timestamp into an ID
    fn encode_version_and_timestamp_into_id<Id>(&mut self, id: &mut Id, timestamp: Option<u64>)
    where
        Id: EncodedId,
    {
        // checking if the version needs to be updated prior to encoding the current
        // version in an ID
        self.update_version();
        // compute a small "mac" of the ID where the version and timestamp only have 0s
        Mac::update(&mut self.mac, &id.as_ref()[..Id::HMAC_START_INDEX]);
        let metadata_mask = self.mac.finalize_fixed_reset();

        let mut version_mask_bytes = [0u8; 4];
        version_mask_bytes.copy_from_slice(&metadata_mask[..4]);
        let masked_version = u32::from_le_bytes(version_mask_bytes) ^ self.current_version;

        if let Some(expiration) = timestamp {
            let mut timestamp_mask_bytes = [0u8; 8];
            timestamp_mask_bytes.copy_from_slice(&metadata_mask[4..12]);
            let masked_timestamp = u64::from_le_bytes(timestamp_mask_bytes) ^ expiration;

            insert_ints_into_slice(
                &[masked_version as u64, masked_timestamp],
                &mut id.as_mut()[Id::METADATA_IDX..],
                &[Id::VERSION_BITS, Id::TIMESTAMP_BITS],
                BITS_IN_USE,
            );
        } else {
            insert_ints_into_slice(
                &[masked_version as u64],
                &mut id.as_mut()[Id::METADATA_IDX..],
                &[Id::VERSION_BITS],
                BITS_IN_USE,
            );
        }
    }

    /// Decodes the version from the ID, as well as a timestamp if there is one.
    #[must_use]
    fn decode_version_and_timestamp_from_id<Id>(&mut self, id: &Id) -> (u32, Option<u64>)
    where
        Id: EncodedId,
    {
        // checking if the version needs to be updated prior to decoding a version in an
        // ID
        self.update_version();
        let has_expiration = id.as_ref()[Id::METADATA_IDX] & 0b10 > 0;

        if !has_expiration {
            let mut zeroed_id: Array<u8, Id::IdLen> = Array::clone_from_slice(id.as_ref());
            insert_ints_into_slice(
                &[0],
                &mut zeroed_id.as_mut()[Id::METADATA_IDX..],
                &[Id::VERSION_BITS],
                BITS_IN_USE,
            );

            Mac::update(&mut self.mac, &zeroed_id[..Id::HMAC_START_INDEX]);
            let metadata_mask = self.mac.finalize_fixed_reset();

            let mut version_mask_bytes = [0u8; 4];
            version_mask_bytes.copy_from_slice(&metadata_mask[..4]);

            let [masked_version] = extract_ints_from_slice::<1>(
                &id.as_ref()[Id::METADATA_IDX..],
                &[Id::VERSION_BITS],
                BITS_IN_USE,
            );

            let version_mask = u32::from_le_bytes(version_mask_bytes) & u64_mask!(Id::VERSION_BITS);

            (masked_version as u32 ^ version_mask, None)
        } else {
            let mut zeroed_id: Array<u8, Id::IdLen> = Array::clone_from_slice(id.as_ref());
            insert_ints_into_slice(
                &[0, 0],
                &mut zeroed_id[Id::METADATA_IDX..],
                &[Id::VERSION_BITS, Id::TIMESTAMP_BITS],
                BITS_IN_USE,
            );

            Mac::update(&mut self.mac, &zeroed_id[..Id::HMAC_START_INDEX]);
            let metadata_mask = self.mac.finalize_fixed_reset();

            let mut version_mask_bytes = [0u8; 4];
            let mut timestamp_mask_bytes = [0u8; 8];

            version_mask_bytes.copy_from_slice(&metadata_mask[..4]);
            timestamp_mask_bytes.copy_from_slice(&metadata_mask[4..12]);

            let [masked_version, masked_timestamp] = extract_ints_from_slice::<2>(
                &id.as_ref()[Id::METADATA_IDX..],
                &[Id::VERSION_BITS, Id::TIMESTAMP_BITS],
                BITS_IN_USE,
            );

            let version_mask = u32::from_le_bytes(version_mask_bytes) & u64_mask!(Id::VERSION_BITS);
            let timestamp_mask =
                u64::from_le_bytes(timestamp_mask_bytes) & u64_mask!(Id::TIMESTAMP_BITS);

            (
                masked_version as u32 ^ version_mask,
                Some(masked_timestamp ^ timestamp_mask),
            )
        }
    }

    /// Computes an hmac of an ID.
    fn compute_hmac<Id>(
        &mut self,
        id: &Id,
        id_type: &[u8],
        version: u32,
        additional_input: Option<&[u8]>,
    ) -> Output<M>
    where
        Id: EncodedId,
    {
        let info = if let Some(info) = additional_input {
            info
        } else {
            &[]
        };

        let data = &[&id.as_ref()[..Id::HMAC_START_INDEX], b"hmac", id_type, info];
        for d in data {
            Mac::update(&mut self.mac, d)
        }
        if self.current_version != version {
            let mut salt: Output<HkdfDigest> = Default::default();
            self.rng.get_version_salt(version, &mut salt);
            Mac::update(&mut self.mac, &salt);
        } else {
            Mac::update(&mut self.mac, &self.current_version_salt);
        }
        self.mac.finalize_fixed_reset()
    }

    /// Validates the HMAC of an ID
    fn validate_hmac<Id>(
        &mut self,
        id: &Id,
        id_type: &[u8],
        version: u32,
        additional_input: Option<&[u8]>,
    ) -> Result<(), InvalidId>
    where
        Id: EncodedId,
    {
        let hmac = self.compute_hmac(id, id_type, version, additional_input);
        if id.as_ref()[Id::HMAC_START_INDEX..]
            .ct_eq(&hmac[..Id::HMAC_LENGTH])
            .into()
        {
            Ok(())
        } else {
            Err(InvalidId::BadHMAC)
        }
    }

    /// Fills a freshly generated ID's HMAC
    fn fill_id_hmac<Id>(&mut self, id: &mut Id, id_type: &[u8], additional_input: Option<&[u8]>)
    where
        Id: EncodedId,
    {
        let hmac = self.compute_hmac(id, id_type, self.current_version, additional_input);
        id.as_mut()[Id::HMAC_START_INDEX..].copy_from_slice(&hmac[..Id::HMAC_LENGTH])
    }
}

impl<M, V, R, HkdfDigest, I> CryptoKeyGenerator for KeyGenerator<M, V, R, HkdfDigest, I>
where
    M: Mac + FixedOutputReset,
    V: VersionConfig,
    R: AllowedRngs,
    HkdfDigest: OutputSizeUser,
    I: HmacImpl<HkdfDigest>,
{
    type HkdfDigest = HkdfDigest;
    type Mac = M;
    type Rng = R;

    fn extract(
        hkdf_key: &[u8],
        application_id: &[u8],
        mac: M,
        rng_seed: &mut R::Seed,
    ) -> (
        Array<u8, <Self::HkdfDigest as OutputSizeUser>::OutputSize>,
        Self,
    ) {
        let (prk, hkdf) = Hkdf::<HkdfDigest, I>::extract(Some(hkdf_key), application_id);
        let current_version = Self::get_current_version();
        let mut rng = R::init_rng(rng_seed);
        let mut salt: Output<HkdfDigest> = Default::default();
        R::get_version_salt(&mut rng, current_version, &mut salt);
        (
            prk,
            Self {
                hkdf,
                mac,
                _versioning_config: PhantomData,
                rng,
                current_version,
                current_version_salt: salt,
            },
        )
    }

    fn from_prk(prk: &[u8], mac: M, rng_seed: &mut R::Seed) -> Self {
        let current_version = Self::get_current_version();
        let mut rng = R::init_rng(rng_seed);
        let mut salt: Output<HkdfDigest> = Default::default();
        R::get_version_salt(&mut rng, current_version, &mut salt);
        Self {
            hkdf: Hkdf::<HkdfDigest, I>::from_prk(prk).expect("Your prk was not strong enough"),
            mac,
            _versioning_config: PhantomData,
            rng: R::init_rng(rng_seed),
            current_version,
            current_version_salt: salt,
        }
    }

    fn generate_keyless_id<Id>(
        &mut self,
        prefix: &[u8],
        id_type: &[u8],
        expiration: Option<u64>,
        associated_data: Option<&[u8]>,
        rng: &mut dyn RngCore,
    ) -> Id
    where
        Id: EncodedId,
    {
        let (mut id, trimmed_timestamp) =
            Id::generate(prefix, expiration, associated_data.is_some(), rng);
        self.encode_version_and_timestamp_into_id(&mut id, trimmed_timestamp);
        self.fill_id_hmac(&mut id, id_type, associated_data);
        id
    }

    fn validate_keyless_id<Id>(
        &mut self,
        id: &[u8],
        id_type: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Id, InvalidId>
    where
        Id: EncodedId,
    {
        let id: Id = id.try_into()?;

        let (version, expiration_time) = self.decode_version_and_timestamp_from_id(&id);

        // when ids are the same length, validate the HMAC first, then attempt to return
        // the more descriptive error before the invalid HMAC error
        let hmac_validation: Result<(), InvalidId>;

        if id.uses_associated_data() {
            // TODO: ensure that the compiler doesn't optimize this by checking the if
            // statement before validating the HMAC?
            hmac_validation = self.validate_hmac(&id, id_type, version, associated_data);
            if associated_data.as_ref().is_none() {
                return Err(InvalidId::IdExpectedAssociatedData);
            }
        } else {
            hmac_validation = self.validate_hmac(&id, id_type, version, None);
        }
        hmac_validation?;

        if version > self.current_version {
            return Err(InvalidId::VersionTooLarge);
        }
        if version < V::get_minimum_accepted_key_id_version(self.current_version) {
            return Err(InvalidId::VersionOutOfDate);
        }

        id.validate_expiration_time(expiration_time)?;
        Ok(id)
    }

    fn generate_ecdsa_key_and_id<C, Id>(
        &mut self,
        prefix: &[u8],
        expiration: Option<u64>,
        associated_data: Option<&[u8]>,
        rng: &mut dyn RngCore,
    ) -> (Id, SigningKey<C>)
    where
        C: EcdsaCurve + CurveArithmetic + JwkParameters,
        Scalar<C>: Invert<Output = CtOption<Scalar<C>>>,
        SignatureSize<C>: ArraySize,
        Id: EncodedId,
    {
        let (mut id, trimmed_timestamp) =
            Id::generate(prefix, expiration, associated_data.as_ref().is_some(), rng);
        self.encode_version_and_timestamp_into_id(&mut id, trimmed_timestamp);
        self.fill_id_hmac(&mut id, b"ecdsa", associated_data);

        let additional_info = if let Some(info) = associated_data {
            info
        } else {
            &[]
        };

        let mut key_bytes = FieldBytes::<C>::default();
        let mut ctr: u8 = 0;
        let private_ecdsa_key: SigningKey<C> = loop {
            self.hkdf
                .expand_multi_info(
                    &[
                        b"ecdsa",
                        C::CRV.as_ref(),
                        id.as_ref(),
                        additional_info,
                        &[ctr],
                    ],
                    &mut key_bytes,
                )
                .expect(
                    "ECC keys should be significantly smaller than the maximum output size of an \
                     HKDF.",
                );
            if let Ok(result) = SigningKey::<C>::from_bytes(&key_bytes).into() {
                break result;
            }
            ctr += 1;
        };
        key_bytes.zeroize();
        (id, private_ecdsa_key)
    }

    fn validate_ecdsa_key_id<C, Id>(
        &mut self,
        id: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Id, InvalidId>
    where
        C: EcdsaCurve + CurveArithmetic + JwkParameters,
        Scalar<C>: Invert<Output = CtOption<Scalar<C>>>,
        SignatureSize<C>: ArraySize,
        Id: EncodedId,
    {
        let id: Id = id.try_into()?;

        let (version, expiration) = self.decode_version_and_timestamp_from_id(&id);

        // when ids are the same length, validate the HMAC first, then attempt to return
        // the more descriptive error before the invalid HMAC error
        let hmac_validation: Result<(), InvalidId>;

        if id.uses_associated_data() {
            // TODO: ensure that the compiler doesn't optimize this by checking the if
            // statement before validating the HMAC?
            hmac_validation =
                self.validate_hmac(&id, b"ecdsa", self.current_version, associated_data);
            if associated_data.as_ref().is_none() {
                return Err(InvalidId::IdExpectedAssociatedData);
            }
        } else {
            hmac_validation = self.validate_hmac(&id, b"ecdsa", self.current_version, None);
        }

        hmac_validation?;

        if version > self.current_version {
            return Err(InvalidId::VersionTooLarge);
        }
        if version < V::get_minimum_accepted_key_id_version(self.current_version) {
            return Err(InvalidId::VersionOutOfDate);
        }

        id.validate_expiration_time(expiration)?;
        Ok(id)
    }

    fn generate_ecdsa_key_from_id<C, Id>(
        &mut self,
        id: &Id,
        associated_data: Option<&[u8]>,
    ) -> SigningKey<C>
    where
        C: EcdsaCurve + CurveArithmetic + JwkParameters,
        Scalar<C>: Invert<Output = CtOption<Scalar<C>>>,
        SignatureSize<C>: ArraySize,
        Id: EncodedId,
    {
        let additional_info = if let Some(info) = associated_data {
            if id.uses_associated_data() {
                info
            } else {
                &[]
            }
        } else {
            &[]
        };
        let mut key_bytes = FieldBytes::<C>::default();
        let mut ctr: u8 = 0;
        let private_ecdsa_key: SigningKey<C> = loop {
            self.hkdf
                .expand_multi_info(
                    &[
                        b"ecdsa",
                        C::CRV.as_ref(),
                        id.as_ref(),
                        additional_info,
                        &[ctr],
                    ],
                    &mut key_bytes,
                )
                .expect(
                    "ECC keys should be significantly smaller than the maximum output size of an \
                     HKDF.",
                );

            if let Ok(result) = SigningKey::<C>::from_bytes(&key_bytes).into() {
                break result;
            }
            ctr += 1;
        };
        key_bytes.zeroize();
        private_ecdsa_key
    }

    fn generate_ecdh_pubkey_and_id<C, Id>(
        &mut self,
        prefix: &[u8],
        expiration: Option<u64>,
        associated_data: Option<&[u8]>,
        rng: &mut dyn RngCore,
    ) -> (Id, PublicKey<C>)
    where
        C: CurveArithmetic + JwkParameters,
        FieldBytesSize<C>: ModulusSize,
        AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
        Id: EncodedId,
    {
        let (mut id, trimmed_expiration) =
            Id::generate(prefix, expiration, associated_data.as_ref().is_some(), rng);
        self.encode_version_and_timestamp_into_id(&mut id, trimmed_expiration);
        self.fill_id_hmac(&mut id, b"ecdh", associated_data);

        let additional_info = if let Some(info) = associated_data {
            info
        } else {
            &[]
        };

        let mut ctr: u8 = 0;
        let pubkey: PublicKey<C> = loop {
            let mut key_bytes: FieldBytes<C> = Default::default();
            self.hkdf
                .expand_multi_info(
                    &[
                        b"ecdh",
                        C::CRV.as_ref(),
                        id.as_ref(),
                        additional_info,
                        &[ctr],
                    ],
                    &mut key_bytes,
                )
                .expect(
                    "ECC keys should be significantly smaller than the maximum output size of an \
                     HKDF.",
                );

            if let Some(mut private_key) = NonZeroScalar::<C>::from_repr(key_bytes).into() {
                let pubkey = PublicKey::<C>::from_secret_scalar(&private_key);
                private_key.zeroize();
                break pubkey;
            }
            ctr += 1;
        };
        (id, pubkey)
    }

    fn validate_ecdh_key_id<Id>(
        &mut self,
        id: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Id, InvalidId>
    where
        Id: EncodedId,
    {
        let id: Id = id.try_into()?;

        let (version, trimmed_timestamp) = self.decode_version_and_timestamp_from_id(&id);

        // when ids are the same length, validate the HMAC first, then attempt to return
        // the more descriptive error before the invalid HMAC error
        let hmac_validation: Result<(), InvalidId>;

        if id.uses_associated_data() {
            // TODO: ensure that the compiler doesn't optimize this by checking the if
            // statement before validating the HMAC?
            hmac_validation = self.validate_hmac(&id, b"ecdh", version, associated_data);
            if associated_data.as_ref().is_none() {
                return Err(InvalidId::IdExpectedAssociatedData);
            }
        } else {
            hmac_validation = self.validate_hmac(&id, b"ecdh", version, None);
        }

        hmac_validation?;

        if version > self.current_version {
            return Err(InvalidId::VersionTooLarge);
        }
        if version < V::get_minimum_accepted_key_id_version(self.current_version) {
            return Err(InvalidId::VersionOutOfDate);
        }

        id.validate_expiration_time(trimmed_timestamp)?;
        Ok(id)
    }

    fn ecdh_using_key_id<C, Id>(
        &self,
        id: &Id,
        associated_data: Option<&[u8]>,
        pubkey: PublicKey<C>,
    ) -> SharedSecret<C>
    where
        C: CurveArithmetic + JwkParameters,
        FieldBytesSize<C>: ModulusSize,
        AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
        Id: EncodedId,
    {
        let additional_info = if let Some(info) = associated_data {
            if id.uses_associated_data() {
                info
            } else {
                // this branch will not happen if the ID is validated first
                &[]
            }
        } else {
            &[]
        };

        let mut key_bytes: FieldBytes<C>;
        let mut ctr: u8 = 0;
        let mut private_ecdh_key: NonZeroScalar<C> = loop {
            key_bytes = Default::default();
            self.hkdf
                .expand_multi_info(
                    &[
                        b"ecdh",
                        C::CRV.as_ref(),
                        id.as_ref(),
                        additional_info,
                        &[ctr],
                    ],
                    &mut key_bytes,
                )
                .expect(
                    "ECC keys should be significantly smaller than the maximum output size of an \
                     HKDF.",
                );

            if let Some(private_key) = NonZeroScalar::<C>::from_repr(key_bytes).into() {
                break private_key;
            }
            ctr += 1;
        };

        let shared_secret = diffie_hellman(private_ecdh_key, pubkey.as_affine());
        private_ecdh_key.zeroize();
        shared_secret
    }

    fn generate_resource_encryption_key(
        &self,
        resource_id: &[u8],
        client_id: &[u8],
        misc_info: &[u8],
        symmetric_key: &mut [u8],
    ) {
        self.hkdf
            .expand_multi_info(&[resource_id, client_id, misc_info], symmetric_key)
            .expect("Your symmetric key should not be very large.")
    }
}

#[cfg(test)]
mod tests {
    use crate::error::InvalidId;
    use crate::typenum::consts::{U48, U5};
    use crate::BinaryId;
    use crate::{traits::CryptoKeyGenerator, KeyGenerator};
    use hkdf::hmac::{Hmac, KeyInit};
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;
    use sha2::Sha256;

    use super::AnnualVersionConfig;

    const MAX_PREFIX_LEN: usize = 6;

    type TestId = BinaryId<U48, U5, MAX_PREFIX_LEN, 3, 24, 8, 1709349508>;
    type Sha2KeyGenerator =
        KeyGenerator<Hmac<Sha256>, AnnualVersionConfig<false>, ChaCha8Rng, Sha256>;

    const TEST_HMAC_KEY: [u8; 32] = [42u8; 32];

    const TEST_ID_TYPE: &[u8] = b"test";

    /// Using a seeded RNG to prevent chanced errors
    macro_rules! rng {
        () => {
            StdRng::from_seed([15u8; 32])
        };
    }

    macro_rules! init_keygenerator {
        () => {
            Sha2KeyGenerator::new(
                &TEST_HMAC_KEY,
                &[],
                Hmac::<Sha256>::new_from_slice(&[4; 32]).unwrap(),
                &mut [3u8; 32],
            )
        };
    }

    /// Some validation tests
    mod validation {

        use super::{
            CryptoKeyGenerator, Hmac, InvalidId, KeyInit, SeedableRng, Sha256, Sha2KeyGenerator,
            StdRng, TestId, TEST_HMAC_KEY, TEST_ID_TYPE,
        };

        #[test]
        fn keyless_id_with_associated_data() {
            let mut key_generator = init_keygenerator!();

            let original_associated_data = b"providing additional data for the id generation requires providing the same data during validation. This is useful for when only a specific client should be using a specific Key ID, and it also affects the actual value of the private key associated with Key IDs (although that aspect does not apply to keyless IDs).";

            let id = key_generator.generate_keyless_id::<TestId>(
                &[],
                TEST_ID_TYPE,
                None,
                Some(original_associated_data),
                &mut rng!(),
            );

            let correctly_providing_data = key_generator.validate_keyless_id::<TestId>(
                id.as_ref(),
                TEST_ID_TYPE,
                Some(original_associated_data),
            );

            assert_eq!(correctly_providing_data.is_ok(), true);

            // providing different data results in a BadHMAC error
            let associated_data_mismatch_result = key_generator.validate_keyless_id::<TestId>(
                id.as_ref(),
                b"test ID",
                Some(b"this isn't the data that was originally provided"),
            );

            assert_eq!(
                associated_data_mismatch_result.unwrap_err(),
                InvalidId::BadHMAC
            );

            // providing no associated data during validation **when the id was generated
            // with associated data** results in an `IdExpectedAssociatedData` error, which
            // would have turned out to be a BadHMAC error (assuming that the `METADATA_IDX`
            // did not change, and that METADATA creation did not change)
            let providing_no_data_result =
                key_generator.validate_keyless_id::<TestId>(id.as_ref(), b"test ID", None);

            assert_eq!(
                providing_no_data_result.unwrap_err(),
                InvalidId::IdExpectedAssociatedData
            );
        }

        #[test]
        fn keyless_id_without_associated_data() {
            let mut key_generator = init_keygenerator!();

            let id_without_associated_data =
                key_generator.generate_keyless_id::<TestId>(&[], b"test", None, None, &mut rng!());

            // providing associated data when the ID was not generated with associated data
            // is safe
            let unnecessary_associated_data_result = key_generator.validate_keyless_id::<TestId>(id_without_associated_data.as_ref(), b"test", Some(b"It is okay to provide associated data during validation when the ID was not generated with associated data."));

            assert_eq!(unnecessary_associated_data_result.is_ok(), true);
        }

        #[test]
        fn different_keyless_id_types() {
            let mut key_generator = init_keygenerator!();

            let id_type_1 = key_generator.generate_keyless_id::<TestId>(
                &[],
                b"client_ID",
                None,
                None,
                &mut rng!(),
            );

            // You must provide the same type of ID when creating an ID and validating it
            assert_eq!(
                key_generator
                    .validate_keyless_id::<TestId>(
                        id_type_1.as_ref(),
                        b"some other ID type that is not the original type specified",
                        None
                    )
                    .is_err(),
                true
            );
        }

        #[test]
        fn basic_hmac_checks() {
            let mut key_generator = init_keygenerator!();

            let id = key_generator.generate_keyless_id::<TestId>(
                &[],
                TEST_ID_TYPE,
                None,
                None,
                &mut rng!(),
            );

            // validation
            assert_eq!(
                key_generator
                    .validate_keyless_id::<TestId>(id.as_ref(), TEST_ID_TYPE, None)
                    .is_ok(),
                true
            );

            let len = id.as_ref().len();

            // change each byte and see if the hmac validation fails. There is a chance this
            // test will fail based on the length of the HMAC, and the HMAC_KEY, and the
            // hash function itself, but the test passes with the currently used values
            let mut tampered_id = id.clone();
            for i in 0..len {
                for _ in 1..256 {
                    tampered_id.as_mut()[i] = tampered_id.as_ref()[i].wrapping_add(1);
                    assert_eq!(
                        key_generator
                            .validate_keyless_id::<TestId>(tampered_id.as_ref(), TEST_ID_TYPE, None)
                            .is_err(),
                        true
                    )
                }
                tampered_id.as_mut()[i] = tampered_id.as_ref()[i].wrapping_add(1)
            }
        }
    }

    #[test]
    fn truncated_prefix() {
        let mut key_generator = init_keygenerator!();

        let test_prefix = [1, 2, 3, 4, 5, 6, 7, 8, 9];

        let id = key_generator.generate_keyless_id::<TestId>(
            &test_prefix,
            TEST_ID_TYPE,
            None,
            None,
            &mut rng!(),
        );

        // this is just in case some of the consts in the test change
        assert!(
            MAX_PREFIX_LEN < test_prefix.len(),
            "MAX_PREFIX_LEN was longer than test_prefix_len, which will break this test. You must \
             either decrease MAX_PREFIX_LEN or increase the length of test_prefix."
        );

        // the first MAX_PREFIX_LEN bytes should be the same as the supplied prefix
        assert_eq!(id.as_ref()[..MAX_PREFIX_LEN], test_prefix[..MAX_PREFIX_LEN]);

        // the remaining bytes are unlikely to be equal, but can be, depending on the
        // RNG's output when the ID was generated
        assert_ne!(id.as_ref()[..test_prefix.len()], test_prefix);
    }

    #[test]
    fn ecdh_key_generation_and_regeneration() {
        let key_generator = init_keygenerator!();

        let mut aes_key = [0u8; 32];
        key_generator.generate_resource_encryption_key(b"test", &[], &[], &mut aes_key)

        //let (ecdh_key_id, ecdh_pubkey) =
        // key_generator.generate_ecdh_pubkey_and_id::<NistP256>(None, None);
    }

    #[test]
    fn ecdsa_key_generation_and_regeneration() {}

    #[test]
    fn resource_encryption_key_regeneration() {
        let key_generator = init_keygenerator!();
        let mut aes_key = [0u8; 32];
        key_generator.generate_resource_encryption_key(
            b"my resource",
            b"some client id",
            &[],
            &mut aes_key,
        );
        let mut test = [0u8; 32];
        key_generator.generate_resource_encryption_key(
            b"my resource",
            b"some client id",
            &[],
            &mut test,
        );

        assert_eq!(aes_key, test);
    }
}

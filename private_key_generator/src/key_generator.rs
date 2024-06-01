//! A Private Key Generator based on an [HKDF](hkdf::Hkdf).

//use digest::{CtOutput, Output};
use crate::{
    error::{IdCreationError, InvalidId},
    id::{timestamp_policies::use_timestamps, BITS_IN_USE},
    traits::{AllowedRngs, CryptoKeyGenerator},
    utils::{
        extract_ints_from_slice, insert_ints_into_slice, months_to_seconds, u32_mask, u64_mask,
        years_to_seconds,
    },
};
use chacha20::rand_core::RngCore;
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
            FixedOutputReset, Key, KeyInit, Output, OutputSizeUser,
        },
        Hmac, Mac, SimpleHmac,
    },
    Hkdf, HmacImpl,
};
use subtle::{ConstantTimeEq, CtOption};

#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

use core::marker::PhantomData;
#[cfg(feature = "std")]
use std::{
    format,
    string::String,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::traits::EncodedId;
use crate::typenum::Unsigned;

/// A convenience type if you wish to use a hash function that does not
/// implement `EagerHash`.
#[allow(unused)]
pub type SimpleKeyGenerator<M, V, Rng, H> = KeyGenerator<M, V, Rng, H, SimpleHmac<H>>;

/// A struct containing some constants for versioning.
///
/// # Type Parameters
///
/// - `EPOCH` - this is the start time for the 0th version.
/// - `VERSION_LIFETIME` - how long each version lasts in seconds. Each version
///   has an associated pseudorandom salt.
/// - `VERSION_BITS` - how many bits to reserve in IDs for the version number.
/// - `TIMESTAMP_BITS` - determines how many bits will be used to represent
///   timestamps in IDs. It doesn't need to be very high, it just needs to be
///   able to represent `VERSION_LIFETIME + MAX_EXPIRATION_TIME` seconds, and
///   the amount of required bits can be reduced by making use of the
///   `TIMESTAMP_PRECISION_LOSS` parameter.
/// - `TIMESTAMP_PRECISION_LOSS`: Specifies the loss of timestamp precision for
///   IDs that have embedded timestamps. This value represents how many of the
///   least significant bits will be discarded before being stored. This bit
///   shift reduces the timestamp's precision but extends the maximum
///   representable time. The decoded timestamp will always be between
///   `2^(TIMESTAMP_PRECISION_LOSS - 1) + 1` and `2^(TIMESTAMP_PRECISION_LOSS) +
///   2^(TIMESTAMP_PRECISION_LOSS - 1)` seconds greater than the input value.
/// - `MAX_EXPIRATION_TIME` - This is the maximum expiration time you will ever
///   use for a Key Id, which is only used if `REQUIRE_EXPIRING_KEYS` is true.
///   This is used to invalidate old versions of Key IDs that must have already
///   expired.
pub struct VersioningConfig<
    const EPOCH: u64,
    const VERSION_LIFETIME: u64,
    const VERSION_BITS: u8,
    const TIMESTAMP_BITS: u8,
    const TIMESTAMP_PRECISION_LOSS: u8,
    const MAX_EXPIRATION_TIME: u64,
>;

/// A trait containing constants for versioning.
pub trait VersionConfig {
    /// The start time for version 0.
    const EPOCH: u64;

    /// How long each version lasts in seconds.
    ///
    /// This cannot be 0, and it should be high enough so that
    /// `2^(VERSION_BITS)` don't get ran through very quickly.
    ///
    /// `VERSION_LIFETIME` has a minimum value of 600 seconds. Versions are
    /// essentially an extension of the ID's timestamp, and it is associated
    /// with a pseudorandom salt.
    const VERSION_LIFETIME: u64;

    /// The amount of bits that can be used in an ID for the version number.
    const VERSION_BITS: u8;

    /// Determines how many bits will be used to represent timestamps in IDs. It
    /// doesn't need to be very high, it just needs to be able to represent
    /// `VERSION_LIFETIME + MAX_EXPIRATION_TIME` seconds, and the amount of
    /// required bits can be reduced by making use of the
    /// `TIMESTAMP_PRECISION_LOSS` parameter.
    ///
    /// Use `2^(TIMESTAMP_BITS + TIMESTAMP_PRECISION_LOSS)` to calculate the
    /// maximm representable time in seconds, and verify that it is greater than
    /// `VERSION_LIFETIME + MAX_EXPIRATION_TIME`.
    const TIMESTAMP_BITS: u8;

    /// Specifies the loss of timestamp precision for IDs that have embedded
    /// timestamps. This value represents how many of the least significant bits
    /// will be discarded before being stored. This bit shift reduces the
    /// timestamp's precision but extends the maximum representable time. The
    /// decoded timestamp will always be between `2^(TIMESTAMP_PRECISION_LOSS -
    /// 1) + 1` and `2^(TIMESTAMP_PRECISION_LOSS) + 2^(TIMESTAMP_PRECISION_LOSS
    /// - 1)` seconds greater than the input value.
    const TIMESTAMP_PRECISION_LOSS: u8;

    /// The maximum key expiration time is used to reject key IDs whose version
    /// is too old to possibly valid when `REQUIRE_EXPIRING_KEYS` is set to
    /// true. This constant represents the maximum "delta-time" rather than a
    /// maximum "time".
    const MAX_EXPIRATION_TIME: u64;

    /// Gets the minimum accepted key id version. This only applies when
    /// `REQUIRE_EXPIRING_KEYS` is set to true.
    ///
    /// The output will change over time as more versions are made.
    #[inline]
    fn get_minimum_accepted_key_id_version(current_version: u32) -> u32 {
        if Self::VERSION_LIFETIME > Self::MAX_EXPIRATION_TIME {
            current_version.saturating_sub(1)
        } else if Self::VERSION_LIFETIME < Self::MAX_EXPIRATION_TIME {
            current_version
                .saturating_sub((Self::MAX_EXPIRATION_TIME / Self::VERSION_LIFETIME) as u32)
                .saturating_sub(1)
        } else {
            // this might actually just need to be 1, but it shouldn't hurt to be off by one
            // here
            current_version.saturating_sub(2)
        }
    }
}

impl<
        const EPOCH: u64,
        const VERSION_LIFETIME: u64,
        const VERSION_BITS: u8,
        const TIMESTAMP_BITS: u8,
        const TIMESTAMP_PRECISION_LOSS: u8,
        const MAX_EXPIRATION_TIME: u64,
    > VersionConfig
    for VersioningConfig<
        EPOCH,
        VERSION_LIFETIME,
        VERSION_BITS,
        TIMESTAMP_BITS,
        TIMESTAMP_PRECISION_LOSS,
        MAX_EXPIRATION_TIME,
    >
{
    const EPOCH: u64 = EPOCH;
    const VERSION_LIFETIME: u64 = {
        {
            match VERSION_LIFETIME >= 600 {
                true => VERSION_LIFETIME,
                false => {
                    [ /* VersionConfig::VERSION_LIFETIME must be greater than or equal to 10 minutes (600 seconds) */ ]
                        [VERSION_LIFETIME as usize]
                }
            }
        }
    };
    const VERSION_BITS: u8 = {
        {
            match VERSION_BITS <= 32 {
                true => VERSION_BITS,
                false => {
                    [/* VERSION_BITS must be less than or equal to 32 */][VERSION_BITS as usize]
                }
            }
        }
    };
    const MAX_EXPIRATION_TIME: u64 = MAX_EXPIRATION_TIME;

    const TIMESTAMP_PRECISION_LOSS: u8 = {
        {
            match TIMESTAMP_PRECISION_LOSS + TIMESTAMP_BITS <= 64 {
                true => TIMESTAMP_PRECISION_LOSS,
                false => {
                    [/* TIMESTAMP_PRECISION_LOSS + TIMESTAMP_PRECISION_BITS is greater than 64. A timestamp range of over 2^64 seconds is likely unnecessary, as it surpasses even UNIX timestamps. */]
                        [TIMESTAMP_PRECISION_LOSS as usize]
                }
            };
            match TIMESTAMP_PRECISION_LOSS <= 27 {
                true => TIMESTAMP_PRECISION_LOSS,
                false => {
                    [/* Any value over 28 for the TIMESTAMP_PRECISION_REDUCTION parameter will make your timestamp dates off by over 8 years... */]
                        [TIMESTAMP_PRECISION_LOSS as usize]
                }
            }
        }
    };

    // validate that `TIMESTAMP_BITS` can represent `MAX_EXPIRATION_TIME +
    // VERSION_LIFETIME`.
    const TIMESTAMP_BITS: u8 = {
        {
            let max_time_to_represent = MAX_EXPIRATION_TIME.saturating_add(VERSION_LIFETIME);
            let max_representable_time = u64_mask(TIMESTAMP_BITS + TIMESTAMP_PRECISION_LOSS);

            match max_representable_time >= max_time_to_represent || VERSION_BITS == 0 {
                true => TIMESTAMP_BITS,
                false => {
                    [ /* VersionConfig::TIMESTAMP_BITS and TIMESTAMP_PRECISION_LOSS are unable to represent MAX_EXPIRATION_TIME + VERSION_LIFETIME. The maximum representable time is 2^(TIMESTAMP_BITS + TIMESTAMP_PRECISION_LOSS) */]
                        [TIMESTAMP_BITS as usize]
                }
            };
            match TIMESTAMP_BITS <= 56 {
                true => TIMESTAMP_BITS,
                false => {
                    [/* TIMESTAMP_BITS must be less than or equal to 56 */][TIMESTAMP_BITS as usize]
                }
            }
        }
    };
}

impl<
        const EPOCH: u64,
        const VERSION_LIFETIME: u64,
        const VERSION_BITS: u8,
        const TIMESTAMP_BITS: u8,
        const TIMESTAMP_PRECISION_LOSS: u8,
        const MAX_EXPIRATION_TIME: u64,
    >
    VersioningConfig<
        EPOCH,
        VERSION_LIFETIME,
        VERSION_BITS,
        TIMESTAMP_BITS,
        TIMESTAMP_PRECISION_LOSS,
        MAX_EXPIRATION_TIME,
    >
{
    /// Returns the minimum value for `TIMESTAMP_BITS + VERSION_BITS` to be able
    /// to represent `VERSION_LIFETIME + MAX_KEY_EXPIRATION_TIME`
    #[cfg(feature = "std")]
    pub fn get_minimum_timestamp_params(&self) -> String {
        let min = f64::log2(VERSION_LIFETIME as f64 + MAX_EXPIRATION_TIME as f64).ceil();
        format!(
            "TIMESTAMP_BITS + TIMESTAMP_PRECISION_LOSS must be at least {} to represent \
             VERSION_LIFETIME + MAX_KEY_EXPIRATION_TIME",
            min
        )
    }

    /// Returns the minimum value for `VERSION_BITS` to be able to represent
    /// `breaking_point_years`, excluding leap seconds.
    #[cfg(feature = "std")]
    pub fn get_minimum_version_bits_for_x_years(breaking_point_years: u64) -> String {
        let desired_lifetime = years_to_seconds(breaking_point_years) as f64;

        let min = f64::log2(desired_lifetime / VERSION_LIFETIME as f64).ceil();
        format!(
            "VERSION_BITS must be at least {} to represent {} years",
            min, breaking_point_years
        )
    }
}

/// A simplified versioning configuration that allows for ID versions to change
/// every 365.25 days (accounting for leap years), and with maximum timestamps
/// of 365.25 days.
///
/// # Type Arguments
///
/// - `VERSION_BITS` - Determines how many bits will be used to represent
///   version numbers in IDs. **This needs to be able to represent `the amount
///   of years` you expect this program to run**.
/// - `TIMESTAMP_PRECISION_LOSS` - Specifies how many lower bits of the
///   timestamps are discarded. This bit shift reduces the timestamp's precision
///   but extends the maximum representable time.
/// - `TIMESTAMP_BITS` - Determines how many bits will be used to represent
///   timestamps in IDs. The timestamp parameters must satisfy this inequality:
///   `2^(TIMESTAMP_BITS + TIMESTAMP_PRECISION_LOSS) ≥ 63,115,200` (2 years'
///   worth of seconds).
#[allow(unused)]
pub type AnnualVersionConfig<
    const VERSION_BITS: u8,
    const TIMESTAMP_PRECISION_LOSS: u8,
    const TIMESTAMP_BITS: u8,
> = VersioningConfig<
    1_711_039_489,           // epoch, 2024
    { years_to_seconds(1) }, // version_lifetime
    VERSION_BITS,
    TIMESTAMP_BITS,
    TIMESTAMP_PRECISION_LOSS,
    { years_to_seconds(1) }, // max_key_expiration_time
>;

/// A simplified versioning configuration where versions change every 30 days,
/// and timestamps can be up to 30 days long.
///
/// # Type Arguments
/// - `VERSION_BITS` - Determines how many bits will be used to represent
///   version numbers in IDs. **This needs to be able to count up to `the amount
///   of years you want this program to run * 12`**.
/// - `TIMESTAMP_PRECISION_LOSS` - Specifies how many lower bits of the
///   timestamps are discarded. This bit shift reduces the timestamp's precision
///   but extends the maximum representable time.
/// - `TIMESTAMP_BITS` - Determines how many bits will be used to represent
///   timestamps in IDs. The timestamp parameters must satisfy this inequality:
///   `2^(TIMESTAMP_BITS + TIMESTAMP_PRECISION_LOSS) ≥ 5,184,000` (2 months'
///   worth of seconds).
#[allow(unused)]
pub type MonthlyVersionConfig<
    const VERSION_BITS: u8,
    const TIMESTAMP_PRECISION_LOSS: u8,
    const TIMESTAMP_BITS: u8,
> = VersioningConfig<
    1_711_039_489,
    { months_to_seconds(1) },
    VERSION_BITS,
    TIMESTAMP_BITS,
    TIMESTAMP_PRECISION_LOSS,
    { months_to_seconds(1) },
>;

/// A simplified type where ID versions do not change.
///
/// This may be useful if the target device isn't able to get the current time,
/// such as in a no-std environment. It may also be useful if you just don't
/// want to use versioning for IDs.
///
/// **If you intend to use timestamps in your IDs with this
/// `StaticVersionConfig`, then the timestamp must be able to represent the full
/// range of of time that you want your program to run for**.
///
/// # Type Arguments
///
/// - `TIMESTAMP_BITS` - the amount of bits in IDs reserved for timestamps.
///   **This (plus `TIMESTAMP_PRECION_LOSS`) needs to be able to represent up to
///   the amount of years you expect this program to run for in seconds**. Just
///   put `0` for this parameter if you aren't using timestamps.
/// - `TIMESTAMP_PRECISION_LOSS` - Determines how many bits are discarded when
///   storing timestamps. Just put `0` for this parameter if you aren't using
///   timestamps.
#[allow(unused)]
pub type StaticVersionConfig<const TIMESTAMP_BITS: u8, const TIMESTAMP_PRECISION_LOSS: u8> =
    VersioningConfig<
        1_711_039_489,
        { (0 as u64).wrapping_sub(1) },
        0,
        TIMESTAMP_BITS,
        TIMESTAMP_PRECISION_LOSS,
        { (0 as u64).wrapping_sub(1) },
    >;

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
    M: Mac + KeyInit + FixedOutputReset,
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
    current_version_mac_salt: Output<M>,
    current_version_ecc_salt: Output<HkdfDigest>,
    current_version_symmetric_key_salt: Output<HkdfDigest>,
    current_version_epoch: u64,
    _versioning_config: PhantomData<V>,
    rng: Rng,
}

#[cfg(feature = "zeroize")]
impl<M, V, R, HkdfDigest, I> Drop for KeyGenerator<M, V, R, HkdfDigest, I>
where
    M: Mac + KeyInit + FixedOutputReset,
    V: VersionConfig,
    R: AllowedRngs,
    HkdfDigest: OutputSizeUser,
    I: HmacImpl<HkdfDigest>,
{
    #[inline]
    fn drop(&mut self) {
        self.current_version_mac_salt.zeroize();
        self.current_version_ecc_salt.zeroize();
        self.current_version_symmetric_key_salt.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl<M, V, R, HkdfDigest, I> ZeroizeOnDrop for KeyGenerator<M, V, R, HkdfDigest, I>
where
    M: Mac + KeyInit + FixedOutputReset,
    V: VersionConfig,
    R: AllowedRngs,
    HkdfDigest: OutputSizeUser,
    I: HmacImpl<HkdfDigest>,
{
}

impl<M, V, R, HkdfDigest, I> KeyGenerator<M, V, R, HkdfDigest, I>
where
    M: Mac + KeyInit + FixedOutputReset,
    V: VersionConfig,
    R: AllowedRngs,
    HkdfDigest: OutputSizeUser,
    I: HmacImpl<HkdfDigest>,
{
    /// Gets the version's EPOCH.
    #[inline]
    fn get_version_epoch(version: u32) -> u64 {
        #[cfg(not(feature = "std"))]
        {
            0
        }
        #[cfg(feature = "std")]
        {
            V::EPOCH + (version as u64 * V::VERSION_LIFETIME)
        }
    }
    /// Gets the current version of IDs
    #[inline]
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
    #[inline]
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
                self.rng
                    .get_version_mac_salt(v, &mut self.current_version_mac_salt);
                self.rng
                    .get_version_ecc_salt(v, &mut self.current_version_ecc_salt);
                self.rng.get_version_symmetric_key_salt(
                    v,
                    &mut self.current_version_symmetric_key_salt,
                );
                self.current_version_epoch = Self::get_version_epoch(v)
            }
        }
    }

    /// Encodes the version and timestamp into an ID
    #[inline]
    fn encode_version_and_timestamp_into_id<Id>(&mut self, id: &mut Id, timestamp: Option<u64>)
    where
        Id: EncodedId,
    {
        // checking if the version needs to be updated prior to encoding the current
        // version in an ID
        self.update_version();
        // compute a small "mac" of the ID where the version and timestamp only have 0s
        Mac::update(&mut self.mac, &id.as_ref()[..Id::MAC_START_INDEX]);
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
                &[V::VERSION_BITS, V::TIMESTAMP_BITS],
                BITS_IN_USE,
            );
        } else {
            insert_ints_into_slice(
                &[masked_version as u64],
                &mut id.as_mut()[Id::METADATA_IDX..],
                &[V::VERSION_BITS],
                BITS_IN_USE,
            );
        }
    }

    /// Computes an hmac of an ID.
    #[inline]
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

        let data = &[&id.as_ref()[..Id::MAC_START_INDEX], b"hmac", id_type, info];
        for d in data {
            Mac::update(&mut self.mac, d)
        }
        if self.current_version != version {
            let mut salt: Output<M> = Default::default();
            self.rng.get_version_mac_salt(version, &mut salt);
            Mac::update(&mut self.mac, &salt);
        } else {
            Mac::update(&mut self.mac, &self.current_version_mac_salt);
        }
        self.mac.finalize_fixed_reset()
    }

    /// Validates the HMAC of an ID
    #[inline]
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
        if id.as_ref()[Id::MAC_START_INDEX..]
            .ct_eq(&hmac[..Id::MAC_LENGTH])
            .into()
        {
            Ok(())
        } else {
            Err(InvalidId::BadHMAC)
        }
    }

    /// Fills a freshly generated ID's HMAC
    #[inline]
    fn fill_id_hmac<Id>(&mut self, id: &mut Id, id_type: &[u8], additional_input: Option<&[u8]>)
    where
        Id: EncodedId,
    {
        let hmac = self.compute_hmac(id, id_type, self.current_version, additional_input);
        id.as_mut()[Id::MAC_START_INDEX..].copy_from_slice(&hmac[..Id::MAC_LENGTH])
    }
}

impl<M, V, R, HkdfDigest, I> CryptoKeyGenerator for KeyGenerator<M, V, R, HkdfDigest, I>
where
    M: Mac + FixedOutputReset + KeyInit,
    V: VersionConfig,
    R: AllowedRngs,
    HkdfDigest: OutputSizeUser,
    I: HmacImpl<HkdfDigest>,
{
    type HkdfDigest = HkdfDigest;
    type Mac = M;
    type Rng = R;

    #[inline]
    fn extract(
        hkdf_key: &[u8],
        application_id: &[u8],
    ) -> (
        Array<u8, <Self::HkdfDigest as OutputSizeUser>::OutputSize>,
        Self,
    ) {
        let (prk, lvl_1_hkdf) = Hkdf::<HkdfDigest, I>::extract(Some(hkdf_key), application_id);

        let mut kdf_prk: Output<HkdfDigest> = Default::default();
        let mut mac_key: Key<M> = Default::default();
        let mut rng_seed: R::Seed = Default::default();

        lvl_1_hkdf
            .expand(b"lvl 2 kdf prk", kdf_prk.as_mut())
            .expect("kdf_prk should be small enough");
        lvl_1_hkdf
            .expand(b"lvl 2 mac", mac_key.as_mut())
            .expect("mac key should be small enough");
        lvl_1_hkdf
            .expand(b"lvl 2 rng", &mut R::set_seed(&mut rng_seed))
            .expect("seed should be small enough");

        let hkdf =
            Hkdf::<HkdfDigest, I>::from_prk(&kdf_prk).expect("This key should be long enough");
        let mac = M::new_from_slice(&mac_key).expect("This key should be the correct length");
        let mut rng = R::init_rng(&mut rng_seed);

        let current_version = Self::get_current_version();
        let mut mac_salt: Output<M> = Default::default();
        let mut ecc_salt: Output<HkdfDigest> = Default::default();
        let mut symmetric_key_salt: Output<HkdfDigest> = Default::default();
        R::get_version_mac_salt(&mut rng, current_version, &mut mac_salt);
        R::get_version_ecc_salt(&mut rng, current_version, &mut ecc_salt);
        R::get_version_symmetric_key_salt(&mut rng, current_version, &mut symmetric_key_salt);
        (
            prk,
            Self {
                hkdf,
                mac,
                _versioning_config: PhantomData,
                rng,
                current_version,
                current_version_epoch: Self::get_version_epoch(current_version),
                current_version_mac_salt: mac_salt,
                current_version_ecc_salt: ecc_salt,
                current_version_symmetric_key_salt: symmetric_key_salt,
            },
        )
    }

    #[inline]
    fn from_prk(prk: &[u8]) -> Self {
        let lvl_1_hkdf =
            Hkdf::<HkdfDigest, I>::from_prk(prk).expect("The prk was not strong enough");

        let mut kdf_prk: Output<HkdfDigest> = Default::default();
        let mut mac_key: Key<M> = Default::default();
        let mut rng_seed: R::Seed = Default::default();

        lvl_1_hkdf
            .expand(b"lvl 2 kdf prk", &mut kdf_prk)
            .expect("kdf prk should be small enough");
        lvl_1_hkdf
            .expand(b"lvl 2 mac", &mut mac_key)
            .expect("mac key should be small enough");
        lvl_1_hkdf
            .expand(b"lvl 2 rng", &mut R::set_seed(&mut rng_seed))
            .expect("seed should be small enough");

        let mac = M::new_from_slice(&mac_key).expect("This key should be the correct length");
        let mut rng = R::init_rng(&mut rng_seed);

        let current_version = Self::get_current_version();
        let mut mac_salt: Output<M> = Default::default();
        let mut ecc_salt: Output<HkdfDigest> = Default::default();
        let mut symmetric_key_salt: Output<HkdfDigest> = Default::default();
        R::get_version_mac_salt(&mut rng, current_version, &mut mac_salt);
        R::get_version_ecc_salt(&mut rng, current_version, &mut ecc_salt);
        R::get_version_symmetric_key_salt(&mut rng, current_version, &mut symmetric_key_salt);
        Self {
            hkdf: Hkdf::<HkdfDigest, I>::from_prk(&kdf_prk)
                .expect("Your prk was not strong enough"),
            mac,
            _versioning_config: PhantomData,
            rng,
            current_version,
            current_version_epoch: Self::get_version_epoch(current_version),
            current_version_mac_salt: mac_salt,
            current_version_ecc_salt: ecc_salt,
            current_version_symmetric_key_salt: symmetric_key_salt,
        }
    }

    #[inline]
    fn decode_version_and_timestamp_from_id<Id>(&mut self, id: &Id) -> (u32, Option<u64>)
    where
        Id: EncodedId,
    {
        // checking if the version needs to be updated prior to decoding a version in an
        // ID
        self.update_version();
        let has_expiration = id.as_ref()[Id::METADATA_IDX] & 0b10 > 0;

        if !has_expiration {
            if V::VERSION_BITS == 0 {
                return (0, None);
            }
            let mut zeroed_id: Array<u8, Id::IdLen> = Array::clone_from_slice(id.as_ref());
            insert_ints_into_slice(
                &[0],
                &mut zeroed_id.as_mut()[Id::METADATA_IDX..],
                &[V::VERSION_BITS],
                BITS_IN_USE,
            );

            Mac::update(&mut self.mac, &zeroed_id[..Id::MAC_START_INDEX]);
            let metadata_mask = self.mac.finalize_fixed_reset();

            let mut version_mask_bytes = [0u8; 4];
            version_mask_bytes.copy_from_slice(&metadata_mask[..4]);

            let [encrypted_version] = extract_ints_from_slice::<1>(
                &id.as_ref()[Id::METADATA_IDX..],
                &[V::VERSION_BITS],
                BITS_IN_USE,
            );

            let version_mask = u32::from_le_bytes(version_mask_bytes) & u32_mask(V::VERSION_BITS);

            return (encrypted_version as u32 ^ version_mask, None);
        }

        let mut zeroed_id: Array<u8, Id::IdLen> = Array::clone_from_slice(id.as_ref());
        insert_ints_into_slice(
            &[0, 0],
            &mut zeroed_id[Id::METADATA_IDX..],
            &[V::VERSION_BITS, V::TIMESTAMP_BITS],
            BITS_IN_USE,
        );

        Mac::update(&mut self.mac, &zeroed_id[..Id::MAC_START_INDEX]);
        let metadata_mask = self.mac.finalize_fixed_reset();

        let mut version_mask_bytes = [0u8; 4];
        let mut timestamp_mask_bytes = [0u8; 8];

        version_mask_bytes.copy_from_slice(&metadata_mask[..4]);
        timestamp_mask_bytes.copy_from_slice(&metadata_mask[4..12]);

        let [masked_version, masked_timestamp] = extract_ints_from_slice::<2>(
            &id.as_ref()[Id::METADATA_IDX..],
            &[V::VERSION_BITS, V::TIMESTAMP_BITS],
            BITS_IN_USE,
        );

        let version_mask = u32::from_le_bytes(version_mask_bytes) & u32_mask(V::VERSION_BITS);
        let timestamp_mask = u64::from_le_bytes(timestamp_mask_bytes) & u64_mask(V::TIMESTAMP_BITS);

        let version = masked_version as u32 ^ version_mask & u32_mask(V::VERSION_BITS);

        let timestamp = Id::decompress_expiration_time::<V>(
            Self::get_version_epoch(version),
            masked_timestamp ^ timestamp_mask & u64_mask(V::TIMESTAMP_BITS),
        );

        (version, Some(timestamp))
    }

    #[inline]
    fn generate_keyless_id<Id>(
        &mut self,
        prefix: &[u8],
        id_type: &[u8],
        expiration: Option<u64>,
        associated_data: Option<&[u8]>,
        rng: &mut dyn RngCore,
    ) -> Result<Id, IdCreationError>
    where
        Id: EncodedId,
    {
        let (mut id, trimmed_timestamp) = Id::generate::<V>(
            prefix,
            expiration,
            associated_data.is_some(),
            self.current_version_epoch,
            rng,
        )?;
        self.encode_version_and_timestamp_into_id(&mut id, trimmed_timestamp);
        self.fill_id_hmac(&mut id, id_type, associated_data);
        Ok(id)
    }

    #[inline]
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

        let (version, expiration) = self.decode_version_and_timestamp_from_id(&id);

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

        id.validate_expiration_time(expiration)?;
        Ok(id)
    }

    #[inline]
    fn generate_ecdsa_key_and_id<C, Id>(
        &mut self,
        prefix: &[u8],
        expiration: Option<u64>,
        associated_data: Option<&[u8]>,
        rng: &mut dyn RngCore,
    ) -> Result<(Id, SigningKey<C>), IdCreationError>
    where
        C: EcdsaCurve + CurveArithmetic + JwkParameters,
        Scalar<C>: Invert<Output = CtOption<Scalar<C>>>,
        SignatureSize<C>: ArraySize,
        Id: EncodedId,
    {
        let (mut id, trimmed_timestamp) = Id::generate::<V>(
            prefix,
            expiration,
            associated_data.as_ref().is_some(),
            self.current_version_epoch,
            rng,
        )?;
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

        #[cfg(feature = "zeroize")]
        key_bytes.zeroize();

        Ok((id, private_ecdsa_key))
    }

    #[inline]
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

        if Id::TIMESTAMP_POLICY.eq(&use_timestamps::Always::U8) {
            if version > self.current_version {
                return Err(InvalidId::VersionTooLarge);
            }
            if version < V::get_minimum_accepted_key_id_version(self.current_version) {
                return Err(InvalidId::VersionOutOfDate);
            }
        }

        id.validate_expiration_time(expiration)?;
        Ok(id)
    }

    #[inline]
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

        #[cfg(feature = "zeroize")]
        key_bytes.zeroize();

        private_ecdsa_key
    }

    #[inline]
    fn generate_ecdh_pubkey_and_id<C, Id>(
        &mut self,
        prefix: &[u8],
        expiration: Option<u64>,
        associated_data: Option<&[u8]>,
        rng: &mut dyn RngCore,
    ) -> Result<(Id, PublicKey<C>), IdCreationError>
    where
        C: CurveArithmetic + JwkParameters,
        FieldBytesSize<C>: ModulusSize,
        AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
        Id: EncodedId,
    {
        let (mut id, trimmed_expiration) = Id::generate::<V>(
            prefix,
            expiration,
            associated_data.as_ref().is_some(),
            self.current_version_epoch,
            rng,
        )?;
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

            #[allow(unused_mut)]
            if let Some(mut private_key) = NonZeroScalar::<C>::from_repr(key_bytes).into() {
                let pubkey = PublicKey::<C>::from_secret_scalar(&private_key);

                #[cfg(feature = "zeroize")]
                private_key.zeroize();

                break pubkey;
            }
            ctr += 1;
        };
        Ok((id, pubkey))
    }

    #[inline]
    fn validate_ecdh_key_id<Id>(
        &mut self,
        id: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Id, InvalidId>
    where
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
            hmac_validation = self.validate_hmac(&id, b"ecdh", version, associated_data);
            if associated_data.as_ref().is_none() {
                return Err(InvalidId::IdExpectedAssociatedData);
            }
        } else {
            hmac_validation = self.validate_hmac(&id, b"ecdh", version, None);
        }

        hmac_validation?;

        if Id::TIMESTAMP_POLICY.eq(&use_timestamps::Always::U8) {
            if version > self.current_version {
                return Err(InvalidId::VersionTooLarge);
            }
            if version < V::get_minimum_accepted_key_id_version(self.current_version) {
                return Err(InvalidId::VersionOutOfDate);
            }
        }

        id.validate_expiration_time(expiration)?;
        Ok(id)
    }

    #[inline]
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
        #[allow(unused_mut)]
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

        #[cfg(feature = "zeroize")]
        private_ecdh_key.zeroize();

        shared_secret
    }

    #[inline]
    fn generate_resource_encryption_key(
        &self,
        resource_id: &[u8],
        client_id: &[u8],
        misc_info: &[u8],
        symmetric_key: &mut [u8],
    ) -> [u8; 4] {
        let version = self.current_version.to_le_bytes();
        self.hkdf
            .expand_multi_info(
                &[
                    resource_id,
                    client_id,
                    misc_info,
                    &self.current_version_symmetric_key_salt,
                ],
                symmetric_key,
            )
            .expect("Your symmetric key should not be very large.");
        version
    }

    #[inline]
    fn generate_resource_decryption_key(
        &mut self,
        resource_id: &[u8],
        client_id: &[u8],
        misc_info: &[u8],
        version: &[u8; 4],
        symmetric_key: &mut [u8],
    ) {
        let v = u32::from_le_bytes(*version);
        match v == self.current_version {
            true => self
                .hkdf
                .expand_multi_info(
                    &[
                        resource_id,
                        client_id,
                        misc_info,
                        &self.current_version_symmetric_key_salt,
                    ],
                    symmetric_key,
                )
                .expect("Your symmetric key should not be very large"),
            false => {
                let mut salt: Output<HkdfDigest> = Default::default();
                self.rng.get_version_symmetric_key_salt(v, &mut salt);
                self.hkdf
                    .expand_multi_info(&[resource_id, client_id, misc_info, &salt], symmetric_key)
                    .expect("Your symmetric key should not be very large")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::error::InvalidId;
    use crate::id::timestamp_policies::use_timestamps;
    use crate::key_generator::VersioningConfig;
    use crate::typenum::consts::{U48, U5};
    use crate::BinaryId;
    use crate::{traits::CryptoKeyGenerator, KeyGenerator};
    use chacha20::ChaCha8Rng;
    use hkdf::hmac::Hmac;
    use rand::rngs::OsRng;
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use sha2::Sha256;

    use super::*;

    const MAX_PREFIX_LEN: usize = 6;

    type TestVersionConfig = AnnualVersionConfig<4, 8, 24>;
    type TestId = BinaryId<U48, U5, MAX_PREFIX_LEN, use_timestamps::Sometimes>;
    type KG<VersionConfiguration> =
        KeyGenerator<Hmac<Sha256>, VersionConfiguration, ChaCha8Rng, Sha256>;
    type Sha2KeyGenerator = KG<TestVersionConfig>;

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
            Sha2KeyGenerator::new(&TEST_HMAC_KEY, &[])
        };
    }

    macro_rules! init_keygenerator_with_versioning {
        ($v:ty) => {
            KG::<$v>::new(&TEST_HMAC_KEY, &[])
        };
    }

    mod encoding_and_decoding {
        use super::*;
        use std::time::{SystemTime, UNIX_EPOCH};

        /// Ensures that the decoded expiration times are between
        ///
        /// input time + 2^(precision_reduction - 1) + 1
        /// and
        /// input time + 2^(precision_reduction - 1) + 2^(precision_reduction)
        /// seconds
        #[test]
        fn fuzz_expiration_times() {
            macro_rules! test_id_with_loss_factor {
                ($($precision_reduction:literal), *) => {
                    $(
                        let mut key_generator = init_keygenerator_with_versioning!(VersioningConfig<0, 1_000_000_000, 32, 32, $precision_reduction, 1_000_000_000>);

                        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
                        for t in 0..(1 << $precision_reduction) {
                            let input_expiration_time = t + now;
                            let expiring_id = key_generator.generate_keyless_id::<TestId>(&[], &[], Some(input_expiration_time), None, &mut OsRng).unwrap();

                            let minimum_added_time = if $precision_reduction > 0 {
                                (1 << ($precision_reduction - 1)) + 1
                            } else {
                                1
                            };
                            let maximum_added_time = if $precision_reduction > 0 {
                                (1 << $precision_reduction) + minimum_added_time - 1
                            } else {
                                1
                            };

                            let (_, decoded_expiration_time) = key_generator.decode_version_and_timestamp_from_id(&expiring_id);
                            if let Some(mut decoded_expiration_time) = decoded_expiration_time {
                                decoded_expiration_time -= input_expiration_time;
                                assert!(decoded_expiration_time >= minimum_added_time, "The expiration time was smaller than it was supposed to be.\ninput_expiration = {}\ndecoded_expiration_time = {}\nprecison_reduction = {}", input_expiration_time, decoded_expiration_time, $precision_reduction);
                                assert!(decoded_expiration_time <= maximum_added_time, "The expiration time exceeds how large it was supposed to be\ninput_expiration = {}\ndecoded_expiration_time = {}\nprecison_reduction = {}", input_expiration_time, decoded_expiration_time, $precision_reduction);
                            } else {
                                assert!(false, "Expiration not found in the ID")
                            }
                        }
                    )*
                };
            }

            test_id_with_loss_factor!(0);
            //test_id_with_loss_factor!(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
            // 12, 13);
        }

        /// Versions will be slightly trickier to test given that they are no
        /// longer based on a function parameter, but instead are based on the
        /// current time.
        #[test]
        fn versions() {
            const EPOCH: u64 = 0;
            const VERSION_LIFETIME: u64 = 900_000;
            const MAX_EXPIRATION_TIME: u64 = 30_000;
            type VersionConfig =
                VersioningConfig<EPOCH, VERSION_LIFETIME, 32, 24, 8, MAX_EXPIRATION_TIME>;

            type KeyGen = KeyGenerator<Hmac<Sha256>, VersionConfig, ChaCha8Rng, Sha256>;

            type VersionedTestId = BinaryId<U48, U5, 3, use_timestamps::Sometimes>;

            let mut key_generator = KeyGen::new(&[42u8; 32], b"");
            let id = key_generator
                .generate_keyless_id::<VersionedTestId>(&[], &[], None, None, &mut OsRng)
                .unwrap();

            let (decoded_version, _) = key_generator.decode_version_and_timestamp_from_id(&id);

            let expected_version = (SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                - EPOCH)
                / VERSION_LIFETIME;
            assert_eq!(decoded_version, expected_version as u32)
        }
    }

    /// Some validation tests
    mod validation {

        use chacha20::ChaCha8Rng;
        use elliptic_curve::consts::{U48, U5};
        use rand::rngs::OsRng;

        use crate::{
            id::timestamp_policies::use_timestamps, key_generator::StaticVersionConfig, BinaryId,
            KeyGenerator,
        };

        use super::{
            CryptoKeyGenerator, Hmac, InvalidId, SeedableRng, Sha256, Sha2KeyGenerator, StdRng,
            TestId, TEST_HMAC_KEY, TEST_ID_TYPE,
        };

        #[test]
        fn zero_sized_version_and_timestamp() {
            type StaticVersioning = StaticVersionConfig<0, 0>;
            let mut key_generator =
                KeyGenerator::<Hmac<Sha256>, StaticVersioning, ChaCha8Rng, Sha256>::new(
                    &[42u8; 32],
                    &[43; 32],
                );
            type IdVersion0 = BinaryId<U48, U5, 3, use_timestamps::Never>;

            let id = key_generator
                .generate_keyless_id::<IdVersion0>(&[], &[], None, None, &mut OsRng)
                .unwrap();

            let result = key_generator.validate_keyless_id::<IdVersion0>(id.as_ref(), &[], None);

            assert_eq!(result.is_ok(), true);
        }

        #[test]
        fn keyless_id_with_associated_data() {
            let mut key_generator = init_keygenerator!();

            let original_associated_data = b"providing additional data for the id generation requires providing the same data during validation. This is useful for when only a specific client should be using a specific Key ID, and it also affects the actual value of the private key associated with Key IDs (although that aspect does not apply to keyless IDs).";

            let id = key_generator
                .generate_keyless_id::<TestId>(
                    &[],
                    TEST_ID_TYPE,
                    None,
                    Some(original_associated_data),
                    &mut rng!(),
                )
                .unwrap();

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

            let id_without_associated_data = key_generator
                .generate_keyless_id::<TestId>(&[], b"test", None, None, &mut rng!())
                .unwrap();

            // providing associated data when the ID was not generated with associated data
            // is safe
            let unnecessary_associated_data_result = key_generator.validate_keyless_id::<TestId>(id_without_associated_data.as_ref(), b"test", Some(b"It is okay to provide associated data during validation when the ID was not generated with associated data."));

            assert_eq!(unnecessary_associated_data_result.is_ok(), true);
        }

        #[test]
        fn different_keyless_id_types() {
            let mut key_generator = init_keygenerator!();

            let id_type_1 = key_generator
                .generate_keyless_id::<TestId>(&[], b"client_ID", None, None, &mut rng!())
                .unwrap();

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

            let id = key_generator
                .generate_keyless_id::<TestId>(&[], TEST_ID_TYPE, None, None, &mut rng!())
                .unwrap();

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

        let id = key_generator
            .generate_keyless_id::<TestId>(&test_prefix, TEST_ID_TYPE, None, None, &mut rng!())
            .unwrap();

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
        key_generator.generate_resource_encryption_key(b"test", &[], &[], &mut aes_key);

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

    mod errors {
        use super::*;
        use crate::prelude::*;

        type ShorthandVersionConfig<const VERSION_BITS: u8, const TIMESTAMP_BITS: u8> =
            VersioningConfig<
                0,              // EPOCH
                1_000_000_000,  // VERSION_LIFETIME
                VERSION_BITS,   // VERSION_BITS - 4 bytes
                TIMESTAMP_BITS, //TIMESTAMP_BITS
                8,              // TIMESTAMP_PRECISION_LOSS
                1_000_000_000,  // MAX_EXPIRATION_TIME
            >;

        #[test]
        fn id_length_error() {
            type TestId<IdLen, MacLen, const MAX_PREFIX_LEN: usize> = BinaryId<
                IdLen, // IdLength: okay. Total length sums up to exactly 19 bytes...
                // BUT... there is no room for pseudorandom bytes, other than the prefix
                MacLen,         // MacLength: okay
                MAX_PREFIX_LEN, // MAX_PREFIX_LEN: okay
                use_timestamps::Sometimes,
            >;

            type K = KeyGenerator<
                Hmac<Sha256>,
                ShorthandVersionConfig<32, 56>, // 4 + 7 + 1 bytes
                ChaCha8Rng,
                Sha256,
            >;

            let expiration = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 500000;

            let mut k = K::new(&[48u8; 32], b"ff");

            let length_off_by_1 = k.generate_keyless_id::<TestId<U19, U1, 7>>(
                &[],
                &[],
                Some(expiration),
                None,
                &mut OsRng,
            );

            assert_eq!(length_off_by_1.is_err(), true);

            let length_exact = k.generate_keyless_id::<TestId<U19, U1, 6>>(
                &[],
                &[],
                Some(expiration),
                None,
                &mut OsRng,
            );

            assert_eq!(length_exact.is_ok(), true);
        }

        #[test]
        fn timestamp_policy_errors() {
            type ShorthandId<TimestampPolicy> = BinaryId<U48, U5, 5, TimestampPolicy>;
            type V = ShorthandVersionConfig<32, 40>;
            let mut key_gen = init_keygenerator_with_versioning!(V);
            type TestId = ShorthandId<use_timestamps::Always>;

            let id_should_have_timestamp_error =
                key_gen.generate_keyless_id::<TestId>(&[], &[], None, None, &mut OsRng);

            assert_eq!(
                id_should_have_timestamp_error.unwrap_err(),
                IdCreationError::MissingExpirationTime
            );

            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let expiration_timestamp_too_large_error = key_gen.generate_keyless_id::<TestId>(
                &[],
                &[],
                Some(now + 1_000_000_001),
                None,
                &mut OsRng,
            );

            assert_eq!(
                expiration_timestamp_too_large_error.unwrap_err(),
                IdCreationError::ExpirationTimeTooLarge
            );

            let expiration_timestamp_barely_ok = key_gen.generate_keyless_id::<TestId>(
                &[],
                &[],
                Some(now + 1_000_000_000),
                None,
                &mut OsRng,
            );

            assert_eq!(expiration_timestamp_barely_ok.is_ok(), true);

            type TestId2 = ShorthandId<use_timestamps::Never>;
            let shouldnt_have_expiration_time =
                key_gen.generate_keyless_id::<TestId2>(&[], &[], Some(now + 5), None, &mut OsRng);

            assert_eq!(
                shouldnt_have_expiration_time.unwrap_err(),
                IdCreationError::IdShouldNotHaveExpirationTime
            );
        }
    }
}

//! A binary encoded ID, along with its implementation of
//! [EncodedId](crate::EncodedId).
//!
//! The expiration timestamps located within the ID are compressed from 8 bytes
//! to 3 bytes. It is somewhat lossy compression, but it allows the ID to
//! contain 5 more pseudorandom bytes. This is what is lost in the compressed
//! timestamp:
//!
//! 1. the full range of seconds since UNIX_EPOCH. This timestamp can only
//!    represent 136 years ahead of the chosen `EPOCH`.
//! 2. the exact second that the expiration was meant to occur. Our compression
//!    makes the base unit of time `256 seconds`, and the expiration time will
//!    be rounded up by between 129-384 seconds.
//!
//! The `EPOCH` can be changed using a different `VERSION` of the `BinaryId`,
//! and you can probably safely disregard the minor inconsistency with the
//! expiration time's precision.
//!
//! The following chart shows the increase in time, which is dependent on the
//! chosen expiration time.
//!
//! | Time % 256 | Total Increase  |
//! |------------|-----------------|
//! | 0          | 256 - 0   = 256 |
//! | 64         | 256 - 64  = 192 |
//! | 127        | 256 - 127 = 129 |
//! | 128        | 512 - 128 = 384 |
//! | 129        | 512 - 129 = 383 |
//! | 255        | 512 - 255 = 257 |

use hkdf::hmac::digest::{
    array::{Array, ArraySize},
    typenum::Unsigned,
};

use core::cmp::min;
use core::marker::PhantomData;
use elliptic_curve::rand_core::RngCore;

#[cfg(feature = "std")]
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::InvalidId;
use crate::{traits::EncodedId, utils::BoolMath};

/// Timestamps can represent up to 136 years in the future, but will be between
/// 129-384 seconds ahead of the input expiration time.
#[cfg(all(feature = "lossy-timestamps", feature = "long-timestamp-timespan"))]
const TIMESTAMP_BYTES: usize = 4;
#[cfg(all(feature = "lossy-timestamps", not(feature = "long-timestamp-timespan")))]
const TIMESTAMP_BYTES: usize = 3;

#[cfg(all(
    not(feature = "lossy-timestamps"),
    not(feature = "long-timestamp-timespan")
))]
/// Timestamps can represent up to 136 years in the future, and the exact second
/// of the expiration is preserved
const TIMESTAMP_BYTES: usize = 4;

#[cfg(all(not(feature = "lossy-timestamps"), feature = "long-timestamp-timespan"))]
const TIMESTAMP_BYTES: usize = 5;

/// A binary-encoded ID struct.
///
/// IDs will be of the type `Array<u8, IdLen>`, and will have this format:
/// * `[Prefix][TimeStamp][RandomBytes][HMAC]`
///   * `Prefix` will either be pseudorandom bytes, or a prefix followed by
///     pseudorandom bytes. This region is `MAX_PREFIX_LEN` bytes long. 4 Base64
///     characters can be represented with 3 bytes, so you might want it to be a
///     multiple of 3.
///   * `Timestamp` is only present in expiring IDs, and can only represent
///     times up to 136 years from the specified `EPOCH`. It is 3 bytes long if
///     feature `lossy-timestamps` is active, or 4 bytes long if it is disabled.
///     With a lossy timestamp the timestamp is slightly less precise,
///     increasing the expiration timestamps by a value between 129-384 seconds,
///     depending on the timestamp's value.
///   * `RandomBytes` is a sequence of psuedorandom bytes, with a metadata byte
///     included among them, located at `METADATA_OFFSET` bytes into this
///     region. The metadata byte indicates whether the `HMAC` was calculated
///     with additional data, if there is a timestamp encoded in the ID, and the
///     `VERSION` of the ID. The `VERSION` must be able to be represented with
///     `VERSION_BITS` bits, and must not exceed 6 since the other 2 bits are
///     being used. This might change to optionally use an extra byte or two for
///     the `VERSION`.
///   * `HMAC` is a message authentication code that is used to validate the ID,
///     with a length of `HmacLen` bytes. This `HMAC` may be computed using
///     additional associated data, and that will be indicated in the encoded
///     ID's metadata. Each byte adds 8 bits of security. The following chart
///     shows a few probabilities... but the average for a given `HmacLen` is
///     more like half of the shown probability.
///
/// | HmacLen |  Probability of a false validation |
/// |---------|------------------------------------|
/// | 1       |  1/256                             |
/// | 2       |  1/65,536                          |
/// | 3       |  1/16,777,216                      |
/// | 4       |  1/4,294,967,296                   |
/// | 5       |  1/1,099,511,627,776               |
///
/// # Generic Arguments
/// Here's a quick recap of the generic arguments mentioned above.
///
/// * `IdLen` - the length of the ID in bytes. This must be greater than
///   `MAX_PREFIX_LEN + HmacLen + 4`.
/// * `HmacLen` - the length of the HMAC inside the ID, in bytes
/// * `MAX_PREFIX_LEN` - the maximum length of a prefix in binary bytes (not
///   Base64 chars)
/// * `METADATA_OFFSET` - the offset of the metadata from the beginning of the
///   RandomBytes portion of the ID. This must be less than `IdLen - HmacLen - 4
///   - MAX_PREFIX_LEN`. A safe value is 0.
/// * `VERSION` - the version of your ID
/// * `VERSION_BITS` - the amount of bits used to store your ID's version. This
///   must be less than 7.
/// * `EPOCH` - a constant reference point in `seconds since UNIX_EPOCH` that is
///   used for the timestamp compression. This should be a timestamp in the
///   recent past.
///
/// # Examples
/// ```rust
/// use private_key_generator::{
///     typenum::consts::{U32, U4},
///     BinaryId,
/// };
///
/// // creating a type alias for an ID
/// type ClientId = BinaryId<
///     U32,        // IdLen
///     U4,         // HmacLen
///     6,          // MAX_PREFIX_LEN
///     0,          // METADATA_OFFSET
///     1,          // VERSION
///     3,          // VERSION_BITS
///     1709349508, // EPOCH
/// >;
/// ```
#[derive(Debug, Clone)]
pub struct BinaryId<
    IdLen: Unsigned + ArraySize,
    HmacLen: Unsigned,
    const MAX_PREFIX_LEN: usize,
    const METADATA_OFFSET: usize,
    const VERSION: u8,
    const VERSION_BITS: u8,
    const EPOCH: u64,
> {
    /// A public id for this key
    pub id: Array<u8, IdLen>,
    _hmac_len: PhantomData<HmacLen>,
}

impl<
        IdLen: Unsigned + ArraySize,
        HmacLen: Unsigned + ArraySize,
        const MAX_PREFIX_LEN: usize,
        const METADATA_OFFSET: usize,
        const VERSION: u8,
        const VERSION_BITS: u8,
        const EPOCH: u64,
    > EncodedId
    for BinaryId<IdLen, HmacLen, MAX_PREFIX_LEN, METADATA_OFFSET, VERSION, VERSION_BITS, EPOCH>
where
    IdLen: Unsigned + ArraySize,
    HmacLen: Unsigned + ArraySize,
{
    const HMAC_LENGTH: usize = HmacLen::USIZE;
    const HMAC_START_INDEX: usize = IdLen::USIZE - HmacLen::USIZE;
    const ID_LEN: usize = IdLen::USIZE;
    const METADATA_IDX: usize = MAX_PREFIX_LEN + TIMESTAMP_BYTES + METADATA_OFFSET;
    const VERSION: u8 = VERSION;
    const MAX_PREFIX_LEN: usize = MAX_PREFIX_LEN;

    type HmacBytes = Array<u8, HmacLen>;
    type IdBytes = Array<u8, IdLen>;

    /// Generates an ID and encodes the "Info Byte", but does not compute the
    /// HMAC.
    ///
    /// If a prefix is supplied, up to `MAX_PREFIX_LEN` bytes will be copied to
    /// the beginning of the ID. Then the rest of the bytes up to the
    /// `HMAC_START_INDEX` will be written with pseudorandom bytes.
    ///
    /// If an expiration time is supplied, it will be encoded into 3 bytes
    /// starting at `MAX_PREFIX_LEN` with the following formula, which will
    /// limit the maximum representable time to about 136 years from the `EPOCH`
    /// you specify, and it will add up to 384 seconds to the expiration time
    /// for a small extension: ```ignore
    /// let additional_extension = (expiration_time - EPOCH) >> 7;
    /// let encoded = (expiration_time - EPOCH) >> 8 + additional_extension as u64 + 1;
    /// ```
    /// The signature algorithm you choose will likely be obsolete by the time
    /// this encoding will expire, but by using the `VERSION` identifier, you
    /// can update both the `EPOCH` and the signature algorithm... but you would
    /// need a little more code.
    ///
    /// Afterwards, an "info byte" will be encoded at index `MAX_PREFIX_LEN +
    /// InfoByteIndex`. This byte will have 1 bit to determine if the HMAC uses
    /// the client ID, 1 bit to determine if the ID has an expiration date, and
    /// `VERSION_BITS` bits to encode the version. The remaining bits will be
    /// pseudorandom.
    fn generate(
        prefix: &[u8],
        expire_time_seconds: Option<u64>,
        uses_accociated_data: bool,
        rng: &mut dyn RngCore,
    ) -> Self {
        debug_assert!(
            VERSION_BITS <= 6,
            "The Id can only handle VERSION_BITS less than 7."
        );
        debug_assert!(
            VERSION < 1 << VERSION_BITS,
            "The Id's VERSION must be representable with VERSION_BITS bits."
        );

        let mut id = Self::IdBytes::default();
        let stream_start_idx: usize = min(prefix.len(), MAX_PREFIX_LEN);
        id[..stream_start_idx].copy_from_slice(&prefix[..stream_start_idx]);
        rng.fill_bytes(&mut id[stream_start_idx..Self::HMAC_START_INDEX]);

        let is_expiring = expire_time_seconds.as_ref().is_some();
        if let Some(mut expiration) = expire_time_seconds {
            #[cfg(feature = "lossy-timestamps")]
            {
                // if more than 128 seconds are chopped off with a right bit shift, we will add
                // an extra 256 seconds to the expiration time. The 8th bit determines this
                let eighth_bit = (expiration & 0b1000_0000) >> 7;

                expiration = (expiration - EPOCH) >> 8;

                // This will add between 129-384 seconds to the provided expiration time based
                // on how much time was removed with our bit shift. This is an insignificant
                // amount of time and could be disregarded, and this extra time might be useful
                // for legitimate requests that occur within seconds of the expiration passing.
                expiration += 1 + eighth_bit;
            }
            #[cfg(not(feature = "lossy-timestamps"))]
            {
                expiration = expiration - EPOCH;
            }

            id[MAX_PREFIX_LEN..MAX_PREFIX_LEN + TIMESTAMP_BYTES]
                .copy_from_slice(&expiration.to_le_bytes()[..TIMESTAMP_BYTES]);
        }

        let mut metadata_byte = id[Self::METADATA_IDX];
        metadata_byte = (metadata_byte << (2 + VERSION_BITS))
            | (VERSION << 2)
            | (is_expiring.as_u8() << 1)
            | uses_accociated_data.as_u8();
        id[Self::METADATA_IDX] = metadata_byte;
        Self {
            id,
            _hmac_len: PhantomData,
        }
    }

    fn get_version(id: &[u8]) -> Result<u8, InvalidId> {
        if id.len() < Self::METADATA_IDX {
            return Err(InvalidId::IncorrectLength);
        }
        let result = id[Self::METADATA_IDX] >> 2;
        Ok(result & ((1 << VERSION_BITS) - 1))
    }

    fn get_expiration_time(&self) -> Option<u64> {
        if (&self.id[Self::METADATA_IDX] & 0b10) == 0 {
            return None;
        }
        let mut arr = [0u8; 8];
        arr[..TIMESTAMP_BYTES]
            .copy_from_slice(&self.id[MAX_PREFIX_LEN..MAX_PREFIX_LEN + TIMESTAMP_BYTES]);
        let mut expiration_s = u64::from_le_bytes(arr);
        #[cfg(feature = "lossy-timestamps")]
        {
            expiration_s = expiration_s << 8;
        }
        expiration_s += EPOCH;
        Some(expiration_s)
    }

    fn validate_expiration_time(&self) -> Result<(), InvalidId> {
        #[cfg(not(feature = "std"))]
        return Ok(());

        #[cfg(feature = "std")]
        if let Some(expiration_time) = self.get_expiration_time() {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            if now > expiration_time {
                Err(InvalidId::Expired)
            } else {
                Ok(())
            }
        } else {
            Ok(())
        }
    }

    fn uses_associated_data(&self) -> bool {
        (&self.id[Self::METADATA_IDX] & 0b1) == 1
    }
}

impl<
        IdLen: Unsigned + ArraySize,
        HmacLen: Unsigned,
        const MAX_PREFIX_LEN: usize,
        const METADATA_OFFSET: usize,
        const VERSION: u8,
        const VERSION_BITS: u8,
        const EPOCH: u64,
    > AsRef<[u8]>
    for BinaryId<IdLen, HmacLen, MAX_PREFIX_LEN, METADATA_OFFSET, VERSION, VERSION_BITS, EPOCH>
{
    fn as_ref(&self) -> &[u8] {
        &self.id
    }
}

impl<
        IdLen: Unsigned + ArraySize,
        HmacLen: Unsigned,
        const MAX_PREFIX_LEN: usize,
        const METADATA_OFFSET: usize,
        const VERSION: u8,
        const VERSION_BITS: u8,
        const EPOCH: u64,
    > Default
    for BinaryId<IdLen, HmacLen, MAX_PREFIX_LEN, METADATA_OFFSET, VERSION, VERSION_BITS, EPOCH>
{
    fn default() -> Self {
        Self {
            id: Default::default(),
            _hmac_len: PhantomData,
        }
    }
}

impl<
        IdLen: Unsigned + ArraySize,
        HmacLen: Unsigned,
        const MAX_PREFIX_LEN: usize,
        const METADATA_OFFSET: usize,
        const VERSION: u8,
        const VERSION_BITS: u8,
        const EPOCH: u64,
    > AsMut<[u8]>
    for BinaryId<IdLen, HmacLen, MAX_PREFIX_LEN, METADATA_OFFSET, VERSION, VERSION_BITS, EPOCH>
{
    fn as_mut(&mut self) -> &mut [u8] {
        self.id.as_mut_slice()
    }
}

impl<
        IdLen,
        HmacLen,
        const MAX_PREFIX_LEN: usize,
        const METADATA_OFFSET: usize,
        const VERSION: u8,
        const VERSION_BITS: u8,
        const EPOCH: u64,
    > TryFrom<&[u8]>
    for BinaryId<IdLen, HmacLen, MAX_PREFIX_LEN, METADATA_OFFSET, VERSION, VERSION_BITS, EPOCH>
where
    IdLen: Unsigned + ArraySize,
    HmacLen: Unsigned + ArraySize,
{
    type Error = InvalidId;

    /// Tries some basic validation. It only checks the ID length and the
    /// reported "version". This should be combined with checking the HMAC, as
    /// well as the expiration time.
    fn try_from(id_slice: &[u8]) -> Result<Self, Self::Error> {
        if id_slice.len() != IdLen::USIZE {
            let b64_len = IdLen::USIZE * 4 / 3;
            if id_slice.len() >= b64_len && id_slice.len() < b64_len + 4 {
                return Err(Self::Error::PossiblyInBase64);
            }
            return Err(Self::Error::IncorrectLength);
        }
        if VERSION != <Self as EncodedId>::get_version(id_slice)? {
            return Err(Self::Error::IncorrectVersion);
        }

        let mut id = <Self as EncodedId>::IdBytes::default();
        id.copy_from_slice(&id_slice);

        Ok(Self {
            id,
            _hmac_len: PhantomData,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use hkdf::hmac::digest::consts::{U48, U5};
    use rand_core::OsRng;

    use super::*;

    /// March 1, 2024
    const TEST_EPOCH: u64 = 1709349508;
    const VERSION_BITS: u8 = 3;
    const PREFIX_LEN: usize = 6;
    const METADATA_OFFSET: usize = 0;

    macro_rules! generate_id {
        ($Ty:ty, $rng:expr) => {
            <$Ty>::generate(&[], None, true, &mut $rng)
        };
    }

    /// Tests the `get_version` method to make sure it returns the right
    /// version. Notice that trying to use versions that are greater than
    /// `2^VERSION_BITS - 1` do not work properly.
    #[test]
    fn version_encoding() {
        type IdVersion1 =
            BinaryId<U48, U5, PREFIX_LEN, METADATA_OFFSET, 1, VERSION_BITS, TEST_EPOCH>;
        type IdVersion2 =
            BinaryId<U48, U5, PREFIX_LEN, METADATA_OFFSET, 2, VERSION_BITS, TEST_EPOCH>;
        type IdVersion7 =
            BinaryId<U48, U5, PREFIX_LEN, METADATA_OFFSET, 7, VERSION_BITS, TEST_EPOCH>;

        // The same Version is used to check the version because they all use the same
        // `METADATA_OFFSET`. If these used different values for that, then this test
        // would not work correctly
        let id_v1 = generate_id!(IdVersion1, &mut OsRng);
        assert_eq!(IdVersion1::get_version(id_v1.as_ref()).unwrap(), 1);
        let id_v2 = generate_id!(IdVersion2, &mut OsRng);
        assert_eq!(IdVersion1::get_version(id_v2.as_ref()).unwrap(), 2);
        let id_v7 = generate_id!(IdVersion7, &mut OsRng);
        assert_eq!(IdVersion1::get_version(id_v7.as_ref()).unwrap(), 7);
    }

    // Because there are only 3 bits representing the version, and version number 8
    // would require 4 bits.
    #[test]
    #[should_panic]
    fn version_too_large() {
        type IdVersion8 =
            BinaryId<U48, U5, PREFIX_LEN, METADATA_OFFSET, 8, VERSION_BITS, TEST_EPOCH>;

        let id_v8 = generate_id!(IdVersion8, OsRng);
        assert_ne!(IdVersion8::get_version(id_v8.as_ref()).unwrap(), 8);
    }

    /// This test ensures that the timestamp's signal bit is set correctly, and
    /// that the timestamp is slightly greater than the input time by a few
    /// minutes.
    #[test]
    fn timestamp_encoding() {
        type IdVersion1 =
            BinaryId<U48, U5, PREFIX_LEN, METADATA_OFFSET, 1, VERSION_BITS, TEST_EPOCH>;
        let input_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // the timestamp in the ID will be roughly between `input_time + 128` and
        // `input_time + 384`
        let maximum_accepted_expiration_time = input_time + 600;
        let id_with_expiration = IdVersion1::generate(&[], Some(input_time), false, &mut OsRng);

        let expiration_time = id_with_expiration.get_expiration_time();

        #[cfg(feature = "lossy-timestamps")]
        if let Some(expiration) = expiration_time {
            assert!(
                expiration > input_time,
                "The expiration time {expiration} was less than the input expiration timestamp \
                 {input_time}"
            );
            assert!(
                expiration < maximum_accepted_expiration_time,
                "The expiration time ({expiration}) was larger than the accepted maximum \
                 expiration time ({maximum_accepted_expiration_time})"
            );
        } else {
            assert!(
                false,
                "The signal bit in the info byte did not properly indicate that the ID uses a \
                 timestamp"
            );
        }
        #[cfg(not(feature = "lossy-timestamps"))]
        if let Some(expiration) = expiration_time {
            assert_eq!(expiration, input_time);
        }

        let id_without_expiration = IdVersion1::generate(&[], None, false, &mut OsRng);

        let expiration_time = id_without_expiration.get_expiration_time();

        assert!(
            expiration_time.is_none(),
            "The signal bit in the info byte incorrectly specified that there is an expiration \
             time in the ID."
        );
    }

    /// This test ensures that the signal bit indicating that there's associated
    /// data is correctly set.
    #[test]
    fn uses_associated_data() {
        type IdVersion1 =
            BinaryId<U48, U5, PREFIX_LEN, METADATA_OFFSET, 1, VERSION_BITS, TEST_EPOCH>;

        let id_with_associated_data = IdVersion1::generate(&[], None, true, &mut OsRng);

        let id_without_associated_data = IdVersion1::generate(&[], None, false, &mut OsRng);

        assert!(
            id_with_associated_data.uses_associated_data(),
            "The signal bit did not indicate that the ID needed some associated data"
        );

        assert!(
            !id_without_associated_data.uses_associated_data(),
            "The signal bit incorrectly indicated that the ID needed some associated data"
        );
    }
}

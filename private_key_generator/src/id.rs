//! A binary encoded ID, along with its implementation of
//! [EncodedId](crate::EncodedId).
//!
//! The expiration timestamps located within the ID are compressed from 8 bytes
//! to TIMESTAMP_BITS bits. It is somewhat lossy compression, but it allows you
//! to specify the length. This is what is lost in the compressed timestamp:
//!
//! 1. the full range of seconds since UNIX_EPOCH. This timestamp can only
//!    represent up to `2^(TIMESTAMP_BITS + TIMESTAMP_PRECISION_REDUCTION)`
//!    seconds from the specified EPOCH.
//! 2. the exact second that the expiration was meant to occur. If
//!    `TIMESTAMP_PRECISION_REDUCTION` is greater than 0, the expiration time in
//!    the ID will be a little bit larger than the input time. The expiration
//!    time will be between `2^(TIMESTAMP_PRECISION_REDUCTION - 1) + 1` seconds
//!    to `2^(TIMESTAMP_PRECISION_REDUCTION) + 2^(TIMESTAMP_PRECISION_REDUCTION
//!    - 1)` seconds larger than the original expiration time.
//!
//! The `EPOCH` can be changed using a different `VERSION` of the `BinaryId`,
//! but it will likely be turned into a function parameter rather than a
//! constant parameter to allow for automatically versioning IDs.

use hkdf::hmac::digest::{
    array::{Array, ArraySize},
    typenum::Unsigned,
};

use core::cmp::min;
use core::marker::PhantomData;
use elliptic_curve::rand_core::RngCore;

#[cfg(feature = "std")]
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{error::InvalidId, utils::insert_ints_into_slice};
use crate::{traits::EncodedId, utils::BoolMath};

/// The amount of bits being used for bools by this ID in the metadata byte
pub(crate) const BITS_IN_USE: u8 = 2;

/// Represents a Binary ID structure with configurable parameters for size,
/// versioning, and expiration encoding.
///
/// IDs will be of the type `Array<u8, IdLength>`, and will have this format:
///
/// `[Prefix][Metadata][RandomBytes][MAC]`
///
/// # Type Parameters
///
/// - `IdLength`: The total length of the ID in bytes.
/// - `MacLength`: The length of the MAC token at the end of the ID in bytes.
/// - `MAX_PREFIX_LEN`: The maximum length of any prefix before the ID data.
///   This length is in bytes.
/// - `VERSION_BITS`: The number of bits used to represent the version of the
///   ID. This value must be less than 32 to fit within the constraints. The
///   version is stored in Little Endian order. If you don't want to use
///   versions for the ID, set this to zero.
/// - `TIMESTAMP_BITS`: The number of bits used to encode the expiration
///   timestamp of the ID. This value must be less than 57. The timestamp is
///   stored in Little Endian order.
/// - `TIMESTAMP_PRECISION_REDUCTION`: Specifies the reduction in timestamp
///   precision. It is the number of least significant bits by which the
///   timestamp value is right-shifted before being stored. This shift reduces
///   the timestamp's precision but extends the maximum representable time. The
///   decoded timestamp will always be between `2^(TIMESTAMP_PRECISION_REDUCTION
///   - 1) + 1` and `2^(TIMESTAMP_PRECISION_REDUCTION) +
///   2^(TIMESTAMP_PRECISION_REDUCTION - 1)` seconds greater than the input
///   valued.
///
/// # Remarks
/// The `BinaryId` struct allows for detailed control over the encoding of
/// version and timestamp information within a binary ID format, offering a
/// balance between precision and space efficiency. The
/// `TIMESTAMP_PRECISION_REDUCTION` parameter, in particular, provides a
/// mechanism to adjust the granularity of timestamp encoding to suit different
/// time range and precision requirements.
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
///     U32,        // IdLength
///     U4,         // MacLength
///     6,          // MAX_PREFIX_LEN
///     3,          // VERSION_BITS
///     24,         // TIMESTAMP_BITS
///     8,          // TIMESTAMP_PRECISION_REDUCTION
///     1709349508, // EPOCH
/// >;
/// ```
#[derive(Debug, Clone)]
pub struct BinaryId<
    IdLength: Unsigned + ArraySize,
    MacLength: Unsigned,
    const MAX_PREFIX_LEN: usize,
    const VERSION_BITS: u8,
    const TIMESTAMP_BITS: u8,
    const TIMESTAMP_PRECISION_REDUCTION: u8,
> {
    /// A public id for this key
    pub id: Array<u8, IdLength>,
    _mac_len: PhantomData<MacLength>,
}

impl<
        IdLength: Unsigned + ArraySize,
        MacLength: Unsigned,
        const MAX_PREFIX_LEN: usize,
        const VERSION_BITS: u8,
        const TIMESTAMP_BITS: u8,
        const TIMESTAMP_PRECISION_REDUCTION: u8,
    > EncodedId
    for BinaryId<
        IdLength,
        MacLength,
        MAX_PREFIX_LEN,
        VERSION_BITS,
        TIMESTAMP_BITS,
        TIMESTAMP_PRECISION_REDUCTION,
    >
where
    IdLength: Unsigned + ArraySize,
    MacLength: Unsigned,
{
    const MAC_LENGTH: usize = {
        let bits_in_use = BITS_IN_USE + VERSION_BITS + TIMESTAMP_BITS;
        let metadata_bytes = (bits_in_use >> 3) as usize + ((bits_in_use & 0b111) > 0) as usize;

        let max_mac_len = IdLength::USIZE - MAX_PREFIX_LEN - metadata_bytes;

        match MacLength::USIZE <= max_mac_len {
            true => MacLength::USIZE,
            false => {
                [/* The IdLength must be large enough to hold `MacLength bytes + MAX_PREFIX_LENGTH bytes + (2 + VERSION_BITS + TIMESTAMP_BITS) worth of bytes` */]
                    [MacLength::USIZE]
            }
        }
    };

    const MAC_START_INDEX: usize = IdLength::USIZE - MacLength::USIZE;

    const METADATA_IDX: usize = MAX_PREFIX_LEN;

    const MAX_PREFIX_LEN: usize = {
        let bits_in_use = BITS_IN_USE + VERSION_BITS + TIMESTAMP_BITS;
        let metadata_bytes = (bits_in_use >> 3) as usize + ((bits_in_use & 0b111) > 0) as usize;

        let max_possible_prefix_len = IdLength::USIZE - MacLength::USIZE - metadata_bytes;

        match MAX_PREFIX_LEN as usize <= max_possible_prefix_len {
            true => MAX_PREFIX_LEN,
            false => {
                [/* The ID must be large enough to hold `MacLength bytes + MAX_PREFIX_LENGTH bytes + (2 + VERSION_BITS + TIMESTAMP_BITS) worth of bytes` */]
                    [MAX_PREFIX_LEN]
            }
        }
    };
    type IdLen = IdLength;

    const VERSION_BITS: u8 = {
        match VERSION_BITS <= 32 {
            true => VERSION_BITS,
            false => [/* VERSION_BITS must be less than or equal to 32. */][VERSION_BITS as usize],
        }
    };

    const TIMESTAMP_BITS: u8 = {
        match TIMESTAMP_BITS <= 56 {
            true => TIMESTAMP_BITS,
            false => {
                [/* TIMESTAMP_BITS must be less than or equal to 56 */][TIMESTAMP_BITS as usize]
            }
        }
    };

    const TIMESTAMP_PRECISION_REDUCTION: u8 = {
        match TIMESTAMP_PRECISION_REDUCTION <= 27 {
            true => TIMESTAMP_PRECISION_REDUCTION,
            false => {
                [/* Any value over 28 for the TIMESTAMP_PRECISION_REDUCTION parameter will make your timestamp dates off by over 8 years... */]
                    [TIMESTAMP_PRECISION_REDUCTION as usize]
            }
        }
    };

    #[inline]
    fn generate(
        prefix: &[u8],
        expire_time_seconds: Option<u64>,
        uses_accociated_data: bool,
        version_epoch: u64,
        rng: &mut dyn RngCore,
    ) -> (Self, Option<u64>) {
        debug_assert!(
            VERSION_BITS <= 56,
            "The Id can only handle VERSION_BITS between 0 <= VB <= 56."
        );

        let mut id: Array<u8, IdLength> = Default::default();
        let stream_start_idx: usize = min(prefix.len(), MAX_PREFIX_LEN);
        id[..stream_start_idx].copy_from_slice(&prefix[..stream_start_idx]);
        rng.fill_bytes(&mut id[stream_start_idx..Self::MAC_START_INDEX]);

        let is_expiring = expire_time_seconds.as_ref().is_some();

        // fill the metadata byte that contains the bools first
        let mut metadata_start = id[Self::METADATA_IDX];

        metadata_start = metadata_start << BITS_IN_USE;
        metadata_start |= (is_expiring.as_u8() << 1) | uses_accociated_data.as_u8();
        id[Self::METADATA_IDX] = metadata_start;

        if let Some(mut expiration) = expire_time_seconds {
            expiration -= version_epoch;

            if Self::TIMESTAMP_PRECISION_REDUCTION > 0 {
                // determine if right shifting by TIMESTAMP_PRECISION_REDUCTION removes a
                // sizeable amount of time, then add some extra time

                // to be exact, this checks if the time removed is greater than or equal to half
                // of the maximum amount of time the removed value can hold by checking the next
                // bit's value
                let next_bit_idx = Self::TIMESTAMP_PRECISION_REDUCTION - 1;
                let next_high_bit = (expiration >> next_bit_idx) & 0b1;

                expiration = (expiration >> Self::TIMESTAMP_PRECISION_REDUCTION) + next_high_bit + 1
            } else {
                expiration += 1;
            }

            // insert 0s as placeholders into timestamp area
            insert_ints_into_slice(
                &[0, 0],
                &mut id[Self::METADATA_IDX..],
                &[VERSION_BITS, TIMESTAMP_BITS],
                BITS_IN_USE,
            );

            (
                Self {
                    id,
                    _mac_len: PhantomData,
                },
                Some(expiration),
            )
        } else {
            // insert 0s as placeholder into version area
            insert_ints_into_slice(
                &[0],
                &mut id[Self::METADATA_IDX..],
                &[VERSION_BITS],
                BITS_IN_USE,
            );
            (
                Self {
                    id,
                    _mac_len: PhantomData,
                },
                None,
            )
        }
    }

    #[inline]
    fn decompress_expiration_time(version_epoch: u64, timestamp: u64) -> u64 {
        (timestamp << Self::TIMESTAMP_PRECISION_REDUCTION) + version_epoch
    }

    #[inline]
    fn validate_expiration_time(&self, expire_time: Option<u64>) -> Result<(), InvalidId> {
        #[cfg(not(feature = "std"))]
        return Ok(());

        #[cfg(feature = "std")]
        if let Some(expiration_time) = expire_time {
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

    #[inline]
    fn uses_associated_data(&self) -> bool {
        (&self.id[Self::METADATA_IDX] & 0b1) == 1
    }
}

impl<
        IdLength: Unsigned + ArraySize,
        MacLength: Unsigned,
        const MAX_PREFIX_LEN: usize,
        const VERSION_BITS: u8,
        const TIMESTAMP_BITS: u8,
        const TIMESTAMP_PRECISION_REDUCTION: u8,
    > AsRef<[u8]>
    for BinaryId<
        IdLength,
        MacLength,
        MAX_PREFIX_LEN,
        VERSION_BITS,
        TIMESTAMP_BITS,
        TIMESTAMP_PRECISION_REDUCTION,
    >
{
    fn as_ref(&self) -> &[u8] {
        &self.id
    }
}

impl<
        IdLength: Unsigned + ArraySize,
        MacLength: Unsigned,
        const MAX_PREFIX_LEN: usize,
        const VERSION_BITS: u8,
        const TIMESTAMP_BITS: u8,
        const TIMESTAMP_PRECISION_REDUCTION: u8,
    > Default
    for BinaryId<
        IdLength,
        MacLength,
        MAX_PREFIX_LEN,
        VERSION_BITS,
        TIMESTAMP_BITS,
        TIMESTAMP_PRECISION_REDUCTION,
    >
{
    fn default() -> Self {
        Self {
            id: Default::default(),
            _mac_len: PhantomData,
        }
    }
}

impl<
        IdLength: Unsigned + ArraySize,
        MacLength: Unsigned,
        const MAX_PREFIX_LEN: usize,
        const VERSION_BITS: u8,
        const TIMESTAMP_BITS: u8,
        const TIMESTAMP_PRECISION_REDUCTION: u8,
    > AsMut<[u8]>
    for BinaryId<
        IdLength,
        MacLength,
        MAX_PREFIX_LEN,
        VERSION_BITS,
        TIMESTAMP_BITS,
        TIMESTAMP_PRECISION_REDUCTION,
    >
{
    fn as_mut(&mut self) -> &mut [u8] {
        self.id.as_mut_slice()
    }
}

impl<
        IdLength,
        MacLength,
        const MAX_PREFIX_LEN: usize,
        const VERSION_BITS: u8,
        const TIMESTAMP_BITS: u8,
        const TIMESTAMP_PRECISION_REDUCTION: u8,
    > TryFrom<&[u8]>
    for BinaryId<
        IdLength,
        MacLength,
        MAX_PREFIX_LEN,
        VERSION_BITS,
        TIMESTAMP_BITS,
        TIMESTAMP_PRECISION_REDUCTION,
    >
where
    IdLength: Unsigned + ArraySize,
    MacLength: Unsigned,
{
    type Error = InvalidId;

    /// Tries some basic validation. It only checks the ID length. This should
    /// be combined with checking the MAC and expiration time.
    #[inline]
    fn try_from(id_slice: &[u8]) -> Result<Self, Self::Error> {
        if id_slice.len() != IdLength::USIZE {
            let b64_len = IdLength::USIZE * 4 / 3;
            if id_slice.len() >= b64_len && id_slice.len() < b64_len + 4 {
                return Err(Self::Error::PossiblyInBase64);
            }
            return Err(Self::Error::IncorrectLength);
        }

        let mut id: Array<u8, IdLength> = Default::default();
        id.copy_from_slice(&id_slice);

        Ok(Self {
            id,
            _mac_len: PhantomData,
        })
    }
}

#[cfg(test)]
mod tests {
    use hkdf::hmac::digest::consts::{U48, U5};
    use rand_core::OsRng;

    use super::*;

    const VERSION_BITS: u8 = 3;
    const PREFIX_LEN: usize = 6;

    const TIMESTAMP_BITS: u8 = 24;
    const TIMESTAMP_PRECISION_REDUCTION: u8 = 8;

    #[test]
    fn uses_associated_data() {
        use super::EncodedId;
        type IdVersion1 = BinaryId<
            U48,
            U5,
            PREFIX_LEN,
            VERSION_BITS,
            TIMESTAMP_BITS,
            TIMESTAMP_PRECISION_REDUCTION,
        >;

        let (id_with_associated_data, _) = IdVersion1::generate(&[], None, true, 3, &mut OsRng);

        let (id_without_associated_data, _) = IdVersion1::generate(&[], None, false, 3, &mut OsRng);

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

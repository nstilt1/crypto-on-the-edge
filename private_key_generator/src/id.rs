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

use crate::{
    error::InvalidId,
    utils::{extract_ints_from_slice, insert_ints_into_slice},
};
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
/// - `MacLength`: The length of the HMAC token at the end of the ID in bytes.
/// - `MAX_PREFIX_LEN`: The maximum length of any prefix before the ID data.
///   This length is in bytes.
/// - `VERSION_BITS`: The number of bits used to represent the version of the
///   ID. This value must be less than 32 to fit within the constraints. The
///   version is stored in Little Endian order.
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
    const EPOCH: u64,
> {
    /// A public id for this key
    pub id: Array<u8, IdLength>,
    _hmac_len: PhantomData<MacLength>,
}

/// Configuration info for IDs?
///
/// ```ignore
/// pub struct IdConfig {
///     version_bits: u8,
///     hmac_len: u8,
///     lossy_timestamp: bool,
///     short_timestamp_range: bool,
///     prefix_len: usize,
///     epoch: u64,
/// }
/// ```

impl<
        IdLength: Unsigned + ArraySize,
        MacLength: Unsigned,
        const MAX_PREFIX_LEN: usize,
        const VERSION_BITS: u8,
        const TIMESTAMP_BITS: u8,
        const TIMESTAMP_PRECISION_REDUCTION: u8,
        const EPOCH: u64,
    > EncodedId
    for BinaryId<
        IdLength,
        MacLength,
        MAX_PREFIX_LEN,
        VERSION_BITS,
        TIMESTAMP_BITS,
        TIMESTAMP_PRECISION_REDUCTION,
        EPOCH,
    >
where
    IdLength: Unsigned + ArraySize,
    MacLength: Unsigned,
{
    const HMAC_LENGTH: usize = MacLength::USIZE;
    const HMAC_START_INDEX: usize = IdLength::USIZE - MacLength::USIZE;
    const METADATA_IDX: usize = MAX_PREFIX_LEN;
    const MAX_PREFIX_LEN: usize = MAX_PREFIX_LEN;
    type IdLen = IdLength;
    const VERSION_BITS: u8 = VERSION_BITS;
    const TIMESTAMP_BITS: u8 = TIMESTAMP_BITS;

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
    ) -> (Self, Option<u64>) {
        debug_assert!(
            VERSION_BITS <= 56,
            "The Id can only handle VERSION_BITS between 0 <= VB <= 56."
        );

        let mut id: Array<u8, IdLength> = Default::default();
        let stream_start_idx: usize = min(prefix.len(), MAX_PREFIX_LEN);
        id[..stream_start_idx].copy_from_slice(&prefix[..stream_start_idx]);
        rng.fill_bytes(&mut id[stream_start_idx..Self::HMAC_START_INDEX]);

        let is_expiring = expire_time_seconds.as_ref().is_some();

        // fill the metadata byte that contains the bools first
        let mut metadata_start = id[Self::METADATA_IDX];

        metadata_start = metadata_start << BITS_IN_USE;
        metadata_start |= (is_expiring.as_u8() << 1) | uses_accociated_data.as_u8();
        id[Self::METADATA_IDX] = metadata_start;

        if let Some(mut expiration) = expire_time_seconds {
            expiration -= EPOCH;

            if TIMESTAMP_PRECISION_REDUCTION > 0 {
                // determine if right shifting by TIMESTAMP_PRECISION_REDUCTION removes a
                // sizeable amount of time, then add some extra time

                // to be exact, this checks if the time removed is greater than or equal to half
                // of the maximum amount of time the removed value can hold by checking the next
                // bit's value
                let next_bit_idx = TIMESTAMP_PRECISION_REDUCTION - 1;
                let next_high_bit = (expiration >> next_bit_idx) & 0b1;

                expiration = (expiration >> TIMESTAMP_PRECISION_REDUCTION) + next_high_bit + 1
            } else {
                expiration += 1;
            }

            // insert 0s as placeholder into timestamp area
            insert_ints_into_slice(
                &[0, 0],
                &mut id[Self::METADATA_IDX..],
                &[VERSION_BITS, TIMESTAMP_BITS],
                BITS_IN_USE,
            );

            (
                Self {
                    id,
                    _hmac_len: PhantomData,
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
                    _hmac_len: PhantomData,
                },
                None,
            )
        }
    }

    fn get_version(id: &[u8]) -> Result<u32, InvalidId> {
        if id.len()
            < Self::METADATA_IDX
                + ((VERSION_BITS + 2) >> 3) as usize
                + ((VERSION_BITS + 2) & 0b111 > 0) as usize
        {
            return Err(InvalidId::IncorrectLength);
        }

        Ok(extract_ints_from_slice::<1>(&id[Self::METADATA_IDX..], &[VERSION_BITS], 2)[0] as u32)
    }

    fn get_expiration_time(&self) -> Option<u64> {
        if (&self.id[Self::METADATA_IDX] & 0b10) == 0 {
            return None;
        }

        let [_, found_expiration] = extract_ints_from_slice::<2>(
            &self.id[Self::METADATA_IDX..],
            &[VERSION_BITS, TIMESTAMP_BITS],
            2,
        );

        Some((found_expiration << TIMESTAMP_PRECISION_REDUCTION) + EPOCH)
    }

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
        const EPOCH: u64,
    > AsRef<[u8]>
    for BinaryId<
        IdLength,
        MacLength,
        MAX_PREFIX_LEN,
        VERSION_BITS,
        TIMESTAMP_BITS,
        TIMESTAMP_PRECISION_REDUCTION,
        EPOCH,
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
        const EPOCH: u64,
    > Default
    for BinaryId<
        IdLength,
        MacLength,
        MAX_PREFIX_LEN,
        VERSION_BITS,
        TIMESTAMP_BITS,
        TIMESTAMP_PRECISION_REDUCTION,
        EPOCH,
    >
{
    fn default() -> Self {
        Self {
            id: Default::default(),
            _hmac_len: PhantomData,
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
        const EPOCH: u64,
    > AsMut<[u8]>
    for BinaryId<
        IdLength,
        MacLength,
        MAX_PREFIX_LEN,
        VERSION_BITS,
        TIMESTAMP_BITS,
        TIMESTAMP_PRECISION_REDUCTION,
        EPOCH,
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
        const EPOCH: u64,
    > TryFrom<&[u8]>
    for BinaryId<
        IdLength,
        MacLength,
        MAX_PREFIX_LEN,
        VERSION_BITS,
        TIMESTAMP_BITS,
        TIMESTAMP_PRECISION_REDUCTION,
        EPOCH,
    >
where
    IdLength: Unsigned + ArraySize,
    MacLength: Unsigned,
{
    type Error = InvalidId;

    /// Tries some basic validation. It only checks the ID length and the
    /// reported "version". This should be combined with checking the HMAC, as
    /// well as the expiration time.
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

    const TIMESTAMP_BITS: u8 = 24;
    const TIMESTAMP_PRECISION_REDUCTION: u8 = 8;

    macro_rules! generate_id {
        ($Ty:ty, $rng:expr) => {
            <$Ty>::generate(&[], None, true, &mut $rng)
        };
    }

    /// Tests the `get_version` method to make sure it returns the right
    /// version. Notice that trying to use versions that are greater than
    /// `2^VERSION_BITS - 1` do not work properly.
    ///
    /// The versioning has changed pretty significantly since I've begun working
    /// on #7, and now the only way it can be tested is by using the
    /// `VersioningConfig`. I will go ahead and commit some changes before
    /// removing the `const EPOCH` in the BinaryId.
    #[test]
    fn version_encoding() {
        type IdVersion1 = BinaryId<
            U48,
            U5,
            PREFIX_LEN,
            VERSION_BITS,
            TIMESTAMP_BITS,
            TIMESTAMP_PRECISION_REDUCTION,
            TEST_EPOCH,
        >;
        type IdVersion2 = BinaryId<
            U48,
            U5,
            PREFIX_LEN,
            VERSION_BITS,
            TIMESTAMP_BITS,
            TIMESTAMP_PRECISION_REDUCTION,
            TEST_EPOCH,
        >;
        type IdVersion7 = BinaryId<
            U48,
            U5,
            PREFIX_LEN,
            VERSION_BITS,
            TIMESTAMP_BITS,
            TIMESTAMP_PRECISION_REDUCTION,
            TEST_EPOCH,
        >;

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
        type IdVersion8 = BinaryId<
            U48,
            U5,
            PREFIX_LEN,
            VERSION_BITS,
            TIMESTAMP_BITS,
            TIMESTAMP_PRECISION_REDUCTION,
            TEST_EPOCH,
        >;

        let id_v8 = generate_id!(IdVersion8, OsRng);
        assert_ne!(IdVersion8::get_version(id_v8.as_ref()).unwrap(), 8);
    }

    /// This test ensures that the timestamp's signal bit is set correctly, and
    /// that the timestamp is slightly greater than the input time by a few
    /// minutes.
    #[test]
    fn fuzz_timestamp_encoding() {
        /// Creates an ID type where `precison_reduction` bits are lost during
        /// timestamp compression, and tests whether the decoded expiration time
        /// was in the expected range
        macro_rules! test_id_with_loss_factor {
            ($($precison_reduction:literal), *) => {
                $(
                    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
                    for t in 0..(1 << $precison_reduction) {
                        let input_expiration_time = t + now;
                        let expiring_id = BinaryId::<U48, U5, PREFIX_LEN, VERSION_BITS, TIMESTAMP_BITS, $precison_reduction, TEST_EPOCH>::generate(1, &[], Some(input_expiration_time), false, &mut OsRng);

                        let minimum_added_time = if $precison_reduction > 0 {
                            (1 << ($precison_reduction - 1)) + 1
                        } else {
                            1
                        };
                        let maximum_added_time = (1 << $precison_reduction) + minimum_added_time - 1;

                        if let Some(mut decoded_expiration_time) = expiring_id.get_expiration_time() {
                            decoded_expiration_time -= input_expiration_time;
                            assert!(decoded_expiration_time >= minimum_added_time, "The expiration time was smaller than it was supposed to be.\ninput_expiration = {}\ndecoded_expiration_time = {}\nprecison_reduction = {}", input_expiration_time, decoded_expiration_time, $precison_reduction);
                            assert!(decoded_expiration_time <= maximum_added_time, "The expiration time exceeds how large it was supposed to be\ninput_expiration = {}\ndecoded_expiration_time = {}\nprecison_reduction = {}", input_expiration_time, decoded_expiration_time, $precison_reduction);
                        } else {
                            assert!(false, "Expiration not found in the ID")
                        }
                    }
                )*
            };
        }

        test_id_with_loss_factor!(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13);
    }

    /// This test ensures that the signal bit indicating that there's associated
    /// data is correctly set.
    #[test]
    fn uses_associated_data() {
        type IdVersion1 = BinaryId<
            U48,
            U5,
            PREFIX_LEN,
            VERSION_BITS,
            TIMESTAMP_BITS,
            TIMESTAMP_PRECISION_REDUCTION,
            TEST_EPOCH,
        >;

        let id_with_associated_data = IdVersion1::generate(1, &[], None, true, &mut OsRng);

        let id_without_associated_data = IdVersion1::generate(1, &[], None, false, &mut OsRng);

        assert!(
            id_with_associated_data.uses_associated_data(),
            "The signal bit did not indicate that the ID needed some associated data"
        );

        assert!(
            !id_without_associated_data.uses_associated_data(),
            "The signal bit incorrectly indicated that the ID needed some associated data"
        );
    }

    #[test]
    fn testing_version_encoding_and_decoding() {
        type HighVersionIds =
            BinaryId<U48, U5, 6, 27, TIMESTAMP_BITS, TIMESTAMP_PRECISION_REDUCTION, TEST_EPOCH>;

        for i in 0..27 {
            let mut test_version: u32 = 1 << i;
            test_version = test_version.saturating_sub(1);

            let new_id =
                HighVersionIds::generate(test_version, b"does it work", None, false, &mut OsRng);

            assert_eq!(
                HighVersionIds::get_version(new_id.as_ref()).unwrap(),
                test_version
            );
        }
    }
}

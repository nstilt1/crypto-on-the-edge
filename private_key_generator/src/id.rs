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
    error::{IdCreationError, InvalidId},
    utils::insert_ints_into_slice,
    VersionConfig,
};
use crate::{
    traits::EncodedId,
    utils::{byte_mask, BoolMath},
};

/// The amount of bits being used for bools by this ID in the metadata byte
pub(crate) const BITS_IN_USE: u8 = 2;

/// A module containing an enum-like module with types that can restrict the ID
/// validation process based on the presence of a timestamp in the ID.
pub mod timestamp_policies {
    /// Some timestamp policies.
    pub mod use_timestamps {
        use crate::typenum::consts::{U57, U58, U59};

        /// This timestamp policy enforces that every ID created and validated
        /// must have a timestamp. Otherwise, the creation or validation will
        /// return an error.
        pub type Always = U57;
        /// This timestamp policy is more relaxed. You are free to make IDs with
        /// or without timestamps, and timestampless IDs can be successfully
        /// validated.
        pub type Sometimes = U58;
        /// This timestamp policy ensures that there will never be a timestamp
        /// in an associated ID type. This is primarily useful for making
        /// smaller IDs that only contain a prefix, version number, and MAC,
        /// with the rest of the space filled with pseudorandom bits.
        pub type Never = U59;
    }
}
use timestamp_policies::use_timestamps;

/// Represents a Binary ID structure with configurable parameters for size,
/// versioning, and expiration encoding.
///
/// IDs will be of the type `Array<u8, IdLength>`, and will have this format:
///
/// `[Prefix][Metadata][PsuedorandomBytes][MAC]`
///
/// # Type Parameters
///
/// - `IdLength` - The total length of the ID in bytes.
/// - `MacLength` - The length of the MAC token at the end of the ID in bytes.
/// - `MAX_PREFIX_LEN` - The maximum length of any prefix before the ID data.
///   This length is in bytes.
/// - `TimestampPolicy` - The timestamp policy for this ID. This will determine
///   whether the ID will always use timestamps, sometimes use timestamps, or
///   never use timestamps, which enables us to be more or less restrictive when
///   validating IDs.
///
/// # Examples
/// ```rust
/// use private_key_generator::prelude::*;
///
/// // creating a type alias for an ID
/// type ClientId = BinaryId<
///     U32,                       // IdLength
///     U4,                        // MacLength
///     6,                         // MAX_PREFIX_LEN
///     use_timestamps::Sometimes, // Timestamp policy
/// >;
/// ```
#[derive(Debug, Clone)]
pub struct BinaryId<
    IdLength: Unsigned + ArraySize,
    MacLength: Unsigned,
    const MAX_PREFIX_LEN: usize,
    TimestampPolicy: Unsigned,
> {
    /// A public id for this key
    pub id: Array<u8, IdLength>,
    _mac_len: PhantomData<MacLength>,
    _timestamp_policy: PhantomData<TimestampPolicy>,
}

/// Validates an ID's parameter + VersionConfig combination.
///
/// Returns 0 on success.
///
/// # Type parameters
///
/// - `V: VersionConfig` - the versioning config of the key generator, which
///   applies to the ID
/// - `IdLen` - the length of the ID in bytes
/// - `MacLen` - the length of the MAC of the ID in bytes
/// - `MAX_PREFIX_LEN` - the maximum prefix length
/// - `TIMESTAMP_POLICY` - the ID's timestamp policy
const fn validate_id_len<V, IdLen, MacLen, const MAX_PREFIX_LEN: usize, TP>() -> bool
where
    V: VersionConfig,
    IdLen: Unsigned,
    MacLen: Unsigned,
    TP: Unsigned,
{
    let timestamp_bits = match TP::U8 {
        use_timestamps::Always::U8 => V::TIMESTAMP_BITS,
        use_timestamps::Sometimes::U8 => V::TIMESTAMP_BITS,
        use_timestamps::Never::U8 => 0,
        _ => [ /* Use a timestamp_policy from `timestamp_policies` */][TP::USIZE],
    };

    let metadata_bits = timestamp_bits + BITS_IN_USE + V::VERSION_BITS;
    let metadata_bytes = (metadata_bits >> 3) + (metadata_bits & byte_mask(3) > 0) as u8;

    let consumed_bytes = MAX_PREFIX_LEN + metadata_bytes as usize + MacLen::USIZE;

    consumed_bytes <= IdLen::USIZE
}

impl<IdLength, MacLength, const MAX_PREFIX_LEN: usize, TimestampPolicy> EncodedId
    for BinaryId<IdLength, MacLength, MAX_PREFIX_LEN, TimestampPolicy>
where
    IdLength: Unsigned + ArraySize,
    MacLength: Unsigned,
    TimestampPolicy: Unsigned,
{
    const MAC_LENGTH: usize = {
        match MacLength::USIZE >= 1 {
            true => MacLength::USIZE,
            false => {
                [/* You probably want the ID's MAC length to be at least 1 */][MacLength::USIZE]
            }
        }
    };

    const MAC_START_INDEX: usize = IdLength::USIZE - MacLength::USIZE;

    const METADATA_IDX: usize = MAX_PREFIX_LEN;

    const TIMESTAMP_POLICY: u8 = match TimestampPolicy::U8 {
        use_timestamps::Always::U8 => TimestampPolicy::U8,
        use_timestamps::Sometimes::U8 => TimestampPolicy::U8,
        use_timestamps::Never::U8 => TimestampPolicy::U8,
        _ => [ /* Use a TIMESTAMP_POLICY from timestamp_policies */ ][TimestampPolicy::USIZE],
    };

    const MAX_PREFIX_LEN: usize = MAX_PREFIX_LEN;
    type IdLen = IdLength;

    #[inline]
    fn generate<V: VersionConfig>(
        prefix: &[u8],
        expire_time_seconds: Option<u64>,
        uses_accociated_data: bool,
        version_epoch: u64,
        rng: &mut dyn RngCore,
    ) -> Result<(Self, Option<u64>), IdCreationError> {
        if let Some(ref timestamp) = &expire_time_seconds {
            if TimestampPolicy::U8.eq(&use_timestamps::Never::U8) {
                return Err(IdCreationError::IdShouldNotHaveExpirationTime);
            }
            #[cfg(feature = "std")]
            {
                let diff = timestamp
                    - SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                if diff > V::MAX_EXPIRATION_TIME {
                    return Err(IdCreationError::ExpirationTimeTooLarge);
                }
            }
        } else if expire_time_seconds.is_none()
            && TimestampPolicy::U8.eq(&use_timestamps::Always::U8)
        {
            return Err(IdCreationError::MissingExpirationTime);
        }

        if !validate_id_len::<V, IdLength, MacLength, { MAX_PREFIX_LEN }, TimestampPolicy>() {
            return Err(IdCreationError::IdLengthCannotHoldItsData);
        }

        let stream_start_idx: usize = min(prefix.len(), MAX_PREFIX_LEN);
        let mut id: Array<u8, IdLength> = Default::default();

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

            if V::TIMESTAMP_PRECISION_LOSS > 0 {
                // determine if right shifting by TIMESTAMP_PRECISION_REDUCTION removes a
                // sizeable amount of time, then add some extra time if it does. This is to
                // prevent the difference in time potentially being 1 second

                // to be exact, this checks if the time removed is greater than or equal to half
                // of the maximum amount of time the removed value can hold by checking the next
                // bit's value
                let next_bit_idx = V::TIMESTAMP_PRECISION_LOSS - 1;
                let next_high_bit = (expiration >> next_bit_idx) & 0b1;

                expiration = (expiration >> V::TIMESTAMP_PRECISION_LOSS) + next_high_bit + 1
            } else {
                expiration += 1;
            }

            // insert 0s as placeholders into timestamp area
            insert_ints_into_slice(
                &[0, 0],
                &mut id[Self::METADATA_IDX..],
                &[V::VERSION_BITS, V::TIMESTAMP_BITS],
                BITS_IN_USE,
            );

            Ok((
                Self {
                    id,
                    _mac_len: PhantomData,
                    _timestamp_policy: PhantomData,
                },
                Some(expiration),
            ))
        } else {
            // insert 0s as placeholder into version area
            insert_ints_into_slice(
                &[0],
                &mut id[Self::METADATA_IDX..],
                &[V::VERSION_BITS],
                BITS_IN_USE,
            );
            Ok((
                Self {
                    id,
                    _mac_len: PhantomData,
                    _timestamp_policy: PhantomData,
                },
                None,
            ))
        }
    }

    #[inline]
    fn decompress_expiration_time<V: VersionConfig>(version_epoch: u64, timestamp: u64) -> u64 {
        (timestamp << V::TIMESTAMP_PRECISION_LOSS) + version_epoch
    }

    #[inline]
    fn validate_expiration_time(&self, expire_time: Option<u64>) -> Result<(), InvalidId> {
        #[cfg(not(feature = "std"))]
        return Ok(());

        #[cfg(feature = "std")]
        {
            if let Some(expiration_time) = expire_time {
                if TimestampPolicy::U8.ne(&use_timestamps::Never::U8) {
                    return Err(InvalidId::IdMustNotExpire);
                }
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
                if TimestampPolicy::U8.eq(&use_timestamps::Always::U8) {
                    return Err(InvalidId::IdsMustExpire);
                }
                Ok(())
            }
        }
    }

    #[inline]
    fn uses_associated_data(&self) -> bool {
        (&self.id[Self::METADATA_IDX] & 0b1) == 1
    }
}

impl<IdLength, MacLength, const MAX_PREFIX_LEN: usize, TimestampPolicy> AsRef<[u8]>
    for BinaryId<IdLength, MacLength, MAX_PREFIX_LEN, TimestampPolicy>
where
    IdLength: Unsigned + ArraySize,
    MacLength: Unsigned,
    TimestampPolicy: Unsigned,
{
    fn as_ref(&self) -> &[u8] {
        &self.id
    }
}

impl<IdLength, MacLength, const MAX_PREFIX_LEN: usize, TimestampPolicy> Default
    for BinaryId<IdLength, MacLength, MAX_PREFIX_LEN, TimestampPolicy>
where
    IdLength: Unsigned + ArraySize,
    MacLength: Unsigned,
    TimestampPolicy: Unsigned,
{
    fn default() -> Self {
        Self {
            id: Default::default(),
            _mac_len: PhantomData,
            _timestamp_policy: PhantomData,
        }
    }
}

impl<IdLength, MacLength, const MAX_PREFIX_LEN: usize, TimestampPolicy> AsMut<[u8]>
    for BinaryId<IdLength, MacLength, MAX_PREFIX_LEN, TimestampPolicy>
where
    IdLength: Unsigned + ArraySize,
    MacLength: Unsigned,
    TimestampPolicy: Unsigned,
{
    fn as_mut(&mut self) -> &mut [u8] {
        self.id.as_mut_slice()
    }
}

impl<IdLength, MacLength, const MAX_PREFIX_LEN: usize, TimestampPolicy> TryFrom<&[u8]>
    for BinaryId<IdLength, MacLength, MAX_PREFIX_LEN, TimestampPolicy>
where
    IdLength: Unsigned + ArraySize,
    MacLength: Unsigned,
    TimestampPolicy: Unsigned,
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
            _timestamp_policy: PhantomData,
        })
    }
}

#[cfg(test)]
mod tests {
    use hkdf::hmac::digest::consts::{U48, U5};
    use rand_core::OsRng;

    use crate::VersioningConfig;

    use super::*;

    const PREFIX_LEN: usize = 6;

    #[test]
    fn uses_associated_data() {
        use super::EncodedId;
        type TestVersionConfig = VersioningConfig<0, 1_000_000_000, 24, 24, 8, 1_000_000_000, 800>;
        type IdVersion1 = BinaryId<U48, U5, PREFIX_LEN, use_timestamps::Sometimes>;

        let (id_with_associated_data, _) =
            IdVersion1::generate::<TestVersionConfig>(&[], None, true, 3, &mut OsRng).unwrap();

        let (id_without_associated_data, _) =
            IdVersion1::generate::<TestVersionConfig>(&[], None, false, 3, &mut OsRng).unwrap();

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

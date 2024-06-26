//! The primary error type returned by this library.
//!
//! It returns a more descriptive error when running in Debug mode, but the
//! error message is intentionally deceptive in release builds, stating, "ID not
//! found". If you want to change the message, feel free to implement
//! `From<InvalidId>` for your own error type.

/// A validation error indicating that the ID was invalid.
///
/// There are a few types of invalid IDs. Any one of these errors can be caused
/// by a forged ID, but they can also be caused by misuse; in particular, the
/// `IdExpectedAssociatedData` error and the `PossiblyInBase64` error.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum InvalidId {
    /// The length of an ID byte slice was not the same length associated with
    /// your `BinaryId`'s `IdLen` value.
    IncorrectLength,
    /// This error indicates that the ID was of the incorrect length, and that
    /// the length of the input ID was roughly the BinaryID's length times 4/3.
    /// The ID might have been encoded in Base64. Since Base64 alphabets and
    /// implementations may vary, this library does not automatically decode IDs
    /// from Base64. You will need to decode the ID to binary.
    PossiblyInBase64,
    /// The version embedded in the ID byte slice was too large to be valid.\
    VersionTooLarge,
    /// If `REQUIRE_EXPIRING_KEYS` is set to true, this error will be given if
    /// the ID's version is smaller than the output of
    /// `get_minimum_accepted_key_id_version()`
    VersionOutOfDate,
    /// This error will only occur if `timestamp_policies::ALWAYS_USE` is set to
    /// true and the bit that indicates that a timestamp should be in the ID is
    /// not set.
    IdsMustExpire,
    /// This error will only occur if `timestamp_policies::NEVER_USE` is set in
    /// the validated ID's type, and if the bit that indicates that a timestamp
    /// should be in the ID is set.
    IdMustNotExpire,
    /// This error indicates that the expiration timestamp in the ID has passed
    /// or was invalid. This error only occurs with the `std` feature enabled
    /// due to the use of `SystemTime`.
    Expired,
    /// This error happens when an ID is "expecting" associated data for
    /// computing the HMAC, but none was provided. This is based on a single bit
    /// in the ID... and an end user or attacker might be supplying the ID. We
    /// don't need the program to panic here, but this error arises in one of
    /// two scenarios:
    ///
    /// 1. (most likely) - someone tried to forge an ID
    /// 2. (still kind of likely—it depends on how you used this library) - the
    ///    ID may have been legitimately created by this program, but was
    ///    created using associated data such as a "Client ID," and when trying
    ///    to validate the ID's HMAC, no associated data was provided. This
    ///    would have resulted in a `BadHMAC` error.
    IdExpectedAssociatedData,
    /// This type of Invalid ID is almost self explanatory, except for the
    /// caveat related to `IdExpectedAssociatedData`. If you created a key with
    /// an ID (such as an ECDH key ID) and designated it to be used by a client
    /// by passing the Client ID during the key generation, then you must
    /// provide the Client ID when validating the ID.
    BadHMAC,
}

impl core::fmt::Display for InvalidId {
    /// Enable debug mode to view more detailed errors. Otherwise, it will just
    /// say "ID not found," implying that your program checked the database to
    /// see if the ID was there or not. Sometimes, it might be best to let an
    /// attacker think your program is simpler than it is.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        #[cfg(debug_assertions)]
        {
            let msg = match self {
                Self::IncorrectLength => "The ID's length was incorrect",
                Self::PossiblyInBase64 => {
                    "The ID's length was incorrect, but it was roughly the length of a \
                     Base64-encoded ID. You must decode it to binary before validating it"
                }

                Self::VersionTooLarge => "The ID's version was too large",
                Self::VersionOutOfDate => "The ID's version is too old",
                Self::IdsMustExpire => "The Key ID does not expire when its ID type should.",
                Self::IdMustNotExpire => "The Key ID expires when its ID type should not.",
                Self::Expired => "The ID has expired",
                Self::IdExpectedAssociatedData => {
                    "This ID either needs to be validated using associated data, or it was forged."
                }
                Self::BadHMAC => "The HMAC was incorrect",
            };

            f.write_fmt(format_args!(
                "Notice: This application is in debug mode. {msg}"
            ))
        }
        #[cfg(not(debug_assertions))]
        {
            f.write_str(match self {
                Self::Expired => "Token expired",
                _ => "ID not found",
            })
        }
    }
}

/// This error only happens when generating a new key and ID, and when
/// `REQUIRE_EXPIRING_KEYS` is set to true.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum IdCreationError {
    /// This error only occurs when `REQUIRE_EXPIRING_KEYS` is true and the
    /// expiration time on a Key ID is greater than the
    /// `MAXIMUM_KEY_EXPIRATION_TIME`.
    ExpirationTimeTooLarge,
    /// This error only occurs when `REQUIRE_EXPIRING_KEYS` is true and the
    /// expiration time on a Key ID is None.
    MissingExpirationTime,
    /// This error only occurs when `timestamp_policies::Never` is chosen for an
    /// ID, and there was an attempt to create an expiring ID of that ID type.
    IdShouldNotHaveExpirationTime,
    /// This error occurs when the ID's length is not large enough to hold the
    /// ID's data, or that the metadata or prefix are too long.
    IdLengthCannotHoldItsData,
}

impl core::fmt::Display for IdCreationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::ExpirationTimeTooLarge => {
                "The expiration time provided to an ID/Key generation method was larger than the \
                 VersioningConfig's MAX_KEY_EXPIRATION_TIME."
            }
            Self::IdLengthCannotHoldItsData => {
                "The ID's length is not large enough to contain MAX_PREFIX_LEN + METADATA (2 + \
                 VERSION_BITS + TIMESTAMP_BITS) as bytes + MacLength."
            }
            Self::IdShouldNotHaveExpirationTime => {
                "The ID type has the `use_timestamps::Never` timestamp policy, but an expiration \
                 time was supplied."
            }
            Self::MissingExpirationTime => {
                "The ID type has the `use_timestamps::Always` timestamp policy, but an expiration \
                 time was not supplied."
            }
        })
    }
}

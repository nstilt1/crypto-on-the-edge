//! A Private Key Generator based on an [HKDF](hkdf::Hkdf).

//use digest::{CtOutput, Output};
use crate::{error::InvalidId, traits::CryptoKeyGenerator};
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

use crate::traits::EncodedId;

/// A convenience type if you wish to use a hash function that does not
/// implement `EagerHash`.
pub type SimpleKeyGenerator<M, H> = KeyGenerator<M, H, SimpleHmac<H>>;

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
pub struct KeyGenerator<M, HkdfDigest, I = Hmac<HkdfDigest>>
where
    M: Mac + FixedOutputReset,
    HkdfDigest: OutputSizeUser,
    I: HmacImpl<HkdfDigest>,
{
    /// The internal HKDF this uses, in case you want to access it
    pub hkdf: Hkdf<HkdfDigest, I>,
    mac: M,
}

impl<M, HkdfDigest, I> KeyGenerator<M, HkdfDigest, I>
where
    M: Mac + FixedOutputReset,
    HkdfDigest: OutputSizeUser,
    I: HmacImpl<HkdfDigest>,
{
    /// Computes an hmac of an ID.
    fn compute_hmac<Id>(
        &mut self,
        id: &Id,
        id_type: &[u8],
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
        self.mac.finalize_fixed_reset()
    }

    /// Validates the HMAC of an ID
    fn validate_hmac<Id>(
        &mut self,
        id: &Id,
        id_type: &[u8],
        additional_input: Option<&[u8]>,
    ) -> Result<(), InvalidId>
    where
        Id: EncodedId,
    {
        let hmac = self.compute_hmac(id, id_type, additional_input);
        if id.as_ref()[Id::HMAC_START_INDEX..]
            .ct_eq(&hmac[..Id::HMAC_LENGTH])
            .into()
        {
            Ok(())
        } else {
            Err(InvalidId::BadHMAC)
        }
    }

    /// Fills an ID's HMAC
    fn fill_id_hmac<Id>(&mut self, id: &mut Id, id_type: &[u8], additional_input: Option<&[u8]>)
    where
        Id: EncodedId,
    {
        let hmac = self.compute_hmac(id, id_type, additional_input);
        id.as_mut()[Id::HMAC_START_INDEX..].copy_from_slice(&hmac[..Id::HMAC_LENGTH])
    }
}

impl<M, HkdfDigest, I> CryptoKeyGenerator for KeyGenerator<M, HkdfDigest, I>
where
    M: Mac + FixedOutputReset,
    HkdfDigest: OutputSizeUser,
    I: HmacImpl<HkdfDigest>,
{
    type HkdfDigest = HkdfDigest;
    type Mac = M;

    fn extract(
        hkdf_key: &[u8],
        application_id: &[u8],
        mac: M,
    ) -> (
        Array<u8, <Self::HkdfDigest as OutputSizeUser>::OutputSize>,
        Self,
    ) {
        let (prk, hkdf) = Hkdf::<HkdfDigest, I>::extract(Some(hkdf_key), application_id);

        (prk, Self { hkdf, mac })
    }

    fn from_prk(prk: &[u8], mac: M) -> Self {
        Self {
            hkdf: Hkdf::<HkdfDigest, I>::from_prk(prk).expect("Your prk was not strong enough"),
            mac,
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
        let mut id = Id::generate(prefix, expiration, associated_data.is_some(), rng);
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

        // when ids are the same length, validate the HMAC first, then attempt to return
        // the more descriptive error before the invalid HMAC error
        let hmac_validation: Result<(), InvalidId>;

        if id.uses_associated_data() {
            // TODO: ensure that the compiler doesn't optimize this by checking the if
            // statement before validating the HMAC?
            hmac_validation = self.validate_hmac(&id, id_type, associated_data);
            if associated_data.as_ref().is_none() {
                return Err(InvalidId::IdExpectedAssociatedData);
            }
        } else {
            hmac_validation = self.validate_hmac(&id, id_type, None);
        }
        hmac_validation?;
        id.validate_expiration_time()?;
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
        let mut id = Id::generate(prefix, expiration, associated_data.as_ref().is_some(), rng);
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

        // when ids are the same length, validate the HMAC first, then attempt to return
        // the more descriptive error before the invalid HMAC error
        let hmac_validation: Result<(), InvalidId>;

        if id.uses_associated_data() {
            // TODO: ensure that the compiler doesn't optimize this by checking the if
            // statement before validating the HMAC?
            hmac_validation = self.validate_hmac(&id, b"ecdsa", associated_data);
            if associated_data.as_ref().is_none() {
                return Err(InvalidId::IdExpectedAssociatedData);
            }
        } else {
            hmac_validation = self.validate_hmac(&id, b"ecdsa", None);
        }

        hmac_validation?;
        id.validate_expiration_time()?;
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
        let mut id = Id::generate(prefix, expiration, associated_data.as_ref().is_some(), rng);
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

        // when ids are the same length, validate the HMAC first, then attempt to return
        // the more descriptive error before the invalid HMAC error
        let hmac_validation: Result<(), InvalidId>;

        if id.uses_associated_data() {
            // TODO: ensure that the compiler doesn't optimize this by checking the if
            // statement before validating the HMAC?
            hmac_validation = self.validate_hmac(&id, b"ecdh", associated_data);
            if associated_data.as_ref().is_none() {
                return Err(InvalidId::IdExpectedAssociatedData);
            }
        } else {
            hmac_validation = self.validate_hmac(&id, b"ecdh", None);
        }

        hmac_validation?;
        id.validate_expiration_time()?;
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
    use sha2::Sha256;

    const MAX_PREFIX_LEN: usize = 6;

    type TestId = BinaryId<U48, U5, MAX_PREFIX_LEN, 0, 1, 3, 1709349508>;
    type Sha2KeyGenerator = KeyGenerator<Hmac<Sha256>, Sha256>;

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

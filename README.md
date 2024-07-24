# Private Key Management

The `private_key_generator` library provides the core functionality of generating private keys from a user-provided ID, and the `key_manager` library provides functionality of handling API requests using these IDs. The IDs can contain an embedded expiration time and a truncated message authentication code (MAC) to determine probable authenticity. The HMAC can be computed with associated data, which can allow for an ID to only be used by a specific client. The associated data is also used for computing the private key to ensure that it is actually specific to the client, and that another client cannot expect an associated key to work if they don't provide the same associated data.

You might be thinking, "What?! IDs for private keys? How can that be secure???" The IDs behave similarly to having an ID for a locally saved private key. In my use case, I publish some public keys and some related IDs once a month, and set them to expire after a year. Before a client makes their first request, they grab an ECDH public key and an ID, as well as an ECDSA public key and ID, and send the IDs in the request. The server uses the ID to regenerate the private keys using an HKDF that was keyed with a securely generated, uniformly pseudorandom key, verifies the client's signature, then responds to the request, encrypting the data with the generated ECDH key and the client's public key, then signs the data with the expected ECDSA key.

The main differences between saving every private key locally and associating them with an ID, versus publishing and providing clients with these IDs are:
1) We don't have to save every generated private key
2) The IDs have a variable-length MAC at the end, so if a client sends a bogus Client ID or key ID, we will (most likely) instantly find out and reject the request.

## Features

Aside from the ID MACs and associated IDs, this library also provides the following features:

* HKDF flexibility: you can use any `RustCrypto` `Digest` for the HKDF's digest. Note that if you want to use something like `Blake2`, you have to use the provided `SimpleKeyGenerator` because `Blake2` does not implement `EagerHash`.
* ECC flexibility: you can use most ECDH curves so long as they impl `CurveArithmetic` and `JwkParameters`, along with the other main required traits for ECDH. The same is true for ECDSA, although this crate currently only provides functionality for ECDSA, rather than the other signature types.
* Hash flexibility for signatures: you can specify the hash function that will be used for hashing requests and responses when verifying and signing
* Time-based salts: MACs and HKDF outputs use unique salts for each "version". The salts are computed using the `ChaCha` RNG, based on how long the `VERSION_LIFETIME` is and when the original `epoch` is set to. Note that using `ChaCha20Rng` over `ChaCha8Rng` provides little to no security benefits because the outputs of the RNG are not exposed anywhere. They are only used for computing MACs and HKDF outputs
* Macro for handling encryption and decryption of requests, where the encryption algorithm can be chosen by the client
* Functions for encrypting and decrypting locally stored data

## Limitations

The current limitations that can be changed include:

* dependency on ECDH and ECDSA
* dependency on HKDF rather than any other KDF

The current limitations that cannot be changed is primarily the fact that some configurations of the `VersioningConfig` can break. This is the definition of the versioning config:

```rust
pub struct VersioningConfig<
    const EPOCH: u64,
    const VERSION_LIFETIME: u64,
    const VERSION_BITS: u8,
    const TIMESTAMP_BITS: u8,
    const TIMESTAMP_PRECISION_LOSS: u8,
    const MAX_EXPIRATION_TIME: u64,
>;
```

Every `VERSION_LIFETIME` seconds, the version increments. There is a lower bound on this set to 10 minutes, but if you set it to 10 minutes, and the `VERSION_BITS` is set to 3, the code will break after 80 minutes.

The versioning **is primarily supposed to handle rekeying the HKDF and MAC** *periodically*. **It does not NEED to change every 10 minutes**, but if you want it to in a personal project where you know that you will only be alive for less than 80 more years, then you **could** make the program expire in 80 years.

# Security and Compatibility Notice

This library has not received an audit, and it is still a work in progress. If any changes are made in the core functionality of generating keys from IDs, or how the IDs or metadata are represented, it can and will break your code. I will add that I've tested all of this code and it works. There is only one change I might put out that might change things (aside from restructuring or adding functionality), which is supporting up to 57 bits for the length of the `version` in the `private_key_generator`. The only thing that this might break is `encrypt_resource`, where the version is encoded in the encrypted data as 4 bytes, and it would need to be able to encode it as either 4 or 8 bytes to avoid breaking changes.

# Requirements

`private_key_generator` is compatible with `no-std`, but without `std`, this library's `validate_id` functions will not be able to validate the timestamps of IDs. However, if you are able to determine the current time in seconds since `UNIX_EPOCH`, you can call `get_expiration_time()` and manually validate the expiration time.

`key_manager` is dependent on `std`.

`key_manager` also depends on `RustCrypto`'s `elliptic_curves` with the following features enabled:
* `jwk` for generating unique private keys with the same ID for different curves
* `ecdh`

You might need to ensure that those features are enabled when you use `RustCrypto` libraries' curves.

## License

All crates licensed under either of

 * [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
 * [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.


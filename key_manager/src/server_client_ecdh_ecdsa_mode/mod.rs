//! This module provides a way to handle API requests with rotating private
//! keys while only needing to keep track of a single private key. There
//! might be an update that also provides streaming functionalities.

pub mod key_manager;

// #[cfg(feature = "streaming")]
// pub mod streaming;

//! A utility crate for initializing structs on the heap.

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![allow(dead_code)]
#![warn(missing_docs, rust_2018_idioms)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
pub use alloc::boxed::Box;
use zeroize::Zeroize;

// These macros are separate because of https://github.com/rust-lang/rust/issues/15701. I did not feel like adding another experimental feature.

/// Defines a new instance of a data structure that is conditionally on the heap, based on whether the `alloc` feature is enabled.
#[macro_export]
#[cfg(feature = "alloc")]
macro_rules! cfg_new_boxed {
    ($data:expr) => {
        $crate::Box::new($data)
    };
}

/// Defines a new instance of a data structure that is conditionally on the heap, based on whether the `alloc` feature is enabled.
#[macro_export]
#[cfg(not(feature = "alloc"))]
macro_rules! cfg_new_boxed {
    ($data:expr) => {
        $data
    };
}

/// A type alias for Box<T>.
/// 
/// This helps when creating a constructor of a type that might be boxed based on the alloc feature of this crate.
#[cfg(feature = "alloc")]
pub type CfgBoxed<T> = Box<T>;

/// A type alias for Box<T>.
/// 
/// This helps when creating a constructor of a type that might be boxed based on the alloc feature of this crate.
#[cfg(not(feature = "alloc"))]
pub type CfgBoxed<T> = T;

/// A struct for defining a newly initialized piece of data within a struct.
/// 
/// # Examples
/// 
/// ```rust
/// use init_boxed::{CfgBoxed, cfg_new_boxed, Init};
/// 
/// pub struct TestStruct {
///    a: u32,
///    b: Init<u32>,
/// }
///
/// impl TestStruct {
///     pub fn new(a: &u32, b: &u32) -> CfgBoxed<Self> {
///         let mut result = cfg_new_boxed!(
///             TestStruct {
///                 a: *a,
///                 b: Init::<u32>::default()
///             }
///         );
///         // simulating a field that needs to be derived from an input
///         *result.b.as_mut() = a * b;
///         result
///    }
/// }
/// ```
#[repr(transparent)]
pub struct Init<T>(Option<T>);

impl<T> Init<T> {
    /// Initializes an Option as None.
    /// 
    /// You must set this using `set` prior to trying to access or modify it any other way.
    #[inline]
    pub fn new() -> Self {
        Self(None)
    }

    /// Sets self to an Option<T> value.
    #[inline]
    pub fn set(&mut self, v: Option<T>) {
        self.0 = v
    }

    /// Gets a mutable reference to the Option<T>
    #[inline]
    pub fn as_mut_option(&mut self) -> &mut Option<T> {
        &mut self.0
    }
}

impl<T: Default> Default for Init<T> {
    #[inline]
    fn default() -> Self {
        Self(Some(T::default()))
    }
}

impl<T> AsRef<T> for Init<T> {
    #[inline]
    fn as_ref(&self) -> &T {
        if let Some(ref value) = &self.0 {
            value
        } else {
            panic!("Accessed Init<T> when it was None")
        }
    }
}

impl<T> AsMut<T> for Init<T> {
    #[inline]
    fn as_mut(&mut self) -> &mut T {
        if let Some(value) = &mut self.0 {
            value
        } else {
            panic!("Tried to modify Init<T> when it was none")
        }
    }
}

impl<T: Zeroize> Zeroize for Init<T> {
    #[inline]
    fn zeroize(&mut self) {
        self.0.zeroize()
    }
}

#[cfg(test)]
mod tests {
    // testing without importing alloc::boxed::Box;
    use super::{CfgBoxed, cfg_new_boxed, Init};

    pub struct TestStruct {
        a: u32,
        b: Init<u32>,
    }

    impl TestStruct {
        pub fn new(a: &u32, b: &u32) -> CfgBoxed<Self> {
            let mut result = cfg_new_boxed!(
                TestStruct {
                    a: *a,
                    b: Init::<u32>::default()
                }
            );
            // simulating a field that needs to be derived from an input
            *result.b.as_mut() = a * b;
            result
        }

        /// Testing whether this function can still be called via the type alias CfgBoxed<Self>
        pub fn test_fn(&self) -> u32 {
            self.a * self.b.as_ref()
        }
    }

    macro_rules! test_as_ref {
        () => {
            let x = cfg_new_boxed!(
                TestStruct { 
                    a: 5, 
                    b: Init::<u32>::new(),
                }
            );
            assert_eq!(x.a, 5);
        };
    }

    macro_rules! test_as_mut {
        () => {
            let mut x = cfg_new_boxed!(
                TestStruct {
                    a: 10,
                    b: Init::<u32>::default(),
                }
            );
            *x.b.as_mut() = 10;

            assert_eq!(x.b.as_ref(), &10)
        };
    }

    macro_rules! test_set {
        () => {
            let mut x = cfg_new_boxed!(
                TestStruct {
                    a: 10,
                    b: Init::<u32>::new(),
                }
            );
            x.b.set(Some(5));

            assert_eq!(x.b.as_ref(), &5);
        };
    }

    #[cfg(not(feature = "alloc"))]
    mod no_alloc {
        use super::{cfg_new_boxed, Init, TestStruct};

        #[test]
        fn as_ref() {
            test_as_ref!();
        }

        #[test]
        fn set() {
            test_set!();
        }

        #[test]
        fn as_mut() {
            test_as_mut!();
        }
    }
    #[cfg(feature = "alloc")]
    mod with_alloc {
        use super::*;

        #[test]
        fn as_ref() {
            test_as_ref!();
        }

        #[test]
        fn set() {
            test_set!();
        }

        #[test]
        fn as_mut() {
            test_as_mut!();
        }

        #[test]
        fn init_and_test_fn() {
            let x = TestStruct::new(&3, &55);
            assert_eq!(x.test_fn(), 3 * 55 * 3)
        }
    }
}
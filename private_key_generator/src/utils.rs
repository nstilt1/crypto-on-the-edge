use core::cmp::min;

/// A simple trait for getting numbers from bools
pub trait BoolMath {
    fn as_u8(&self) -> u8;
}

impl BoolMath for bool {
    /// Returns 1 or 0 based on the bool
    #[inline(always)]
    fn as_u8(&self) -> u8 {
        match self {
            true => 1u8,
            false => 0u8,
        }
    }
}

impl BoolMath for u32 {
    fn as_u8(&self) -> u8 {
        *self as u8
    }
}

/// Calculates the number of seconds in `num_years` at compile time.
///
/// Does not take into account leap seconds.
#[inline]
#[allow(unused)]
pub const fn years_to_seconds(num_years: u64) -> u64 {
    num_years * days_to_seconds(365)
}
/// Calculates the number of seconds in `num_months` at compile time.
///
/// A month is counted as 30 days.
#[inline]
#[allow(unused)]
pub const fn months_to_seconds(num_months: u64) -> u64 {
    days_to_seconds(30 * num_months)
}
/// Calculates the number of seconds in `num_days` at compile time.
#[inline]
#[allow(unused)]
pub const fn days_to_seconds(num_days: u64) -> u64 {
    num_days * 24 * 60 * 60
}

/// implements a const mask function for some unsigned integers
macro_rules! impl_mask {
    ($name:ident, $type:ty, $bits:literal) => {
        /// Creates a mask that evaluates to (2^pow) - 1, equating to a number that has
        /// `32 - pow` leading 0s followed by `pow` ones.
        ///
        /// # Panics
        ///
        /// This panics if `pow` is greater than the amount of bits of the type.
        pub(crate) const fn $name(pow: u8) -> $type {
            match pow {
                $bits => <$type>::MAX,
                0 => 0,
                _ => (1 << pow) - 1,
            }
        }
    };
}

impl_mask!(byte_mask, u8, 8);
impl_mask!(u32_mask, u32, 32);
impl_mask!(u64_mask, u64, 64);

/// Inserts a specific number of bits of a u64 into a slice.
///
/// Returns the mutable slice starting at where the function left off, and how
/// many bits were used in the final byte.
///
/// This function can insert up to 56 bits of a number into a slice, given that
/// the slice is large enough to hold it. It can also preserve the first n-bits
/// of the first slice, allowing this to be chained for storing multiple numbers
/// with 0 bits between them. It also preserves any unused bits of the last
/// byte.
///
/// # Arguments
///
/// * `int` - the number to encode into the `dest` slice
/// * `dest` - the destination slice to overwrite values at, where the first
///   byte is intended to be affected by this function
/// * `num_bits_to_insert` - the total amount of bits to write to `dest`
/// * `bits_to_preserve` - the amount of lower bits that should be preserved in
///   the `dest` slice's first byte. This will be modulo'd by 8 in case you want
///   to pass in a sum.
#[inline]
fn insert_int_bits_v2(
    mut int: u64,
    dest: &mut [u8],
    mut num_bits_to_insert: u8,
    mut bits_to_preserve: u8,
) -> (&mut [u8], u8) {
    debug_assert!(
        dest.len() > (num_bits_to_insert + bits_to_preserve) as usize >> 3,
        "The destination must have enough space to contain `num_bits_to_insert + \
         bits_to_preserve` bits."
    );
    debug_assert!(
        num_bits_to_insert <= 56,
        "Version numbers and compressed timestamps should not be longer than 56 bits. This \
         function could be changed to accept a u128 with a maximum supported value as 120 bits... \
         but there is no point in those values being that long."
    );

    bits_to_preserve &= 0b111;
    int <<= bits_to_preserve;
    let slice = int.to_le_bytes();

    if num_bits_to_insert < 8 - bits_to_preserve {
        dest[0] &= byte_mask(bits_to_preserve);
        dest[0] |= slice[0] & byte_mask(bits_to_preserve + num_bits_to_insert);
        return (dest, num_bits_to_insert + bits_to_preserve);
    }

    if bits_to_preserve > 0 {
        dest[0] &= byte_mask(bits_to_preserve);
        dest[0] |= slice[0];
        num_bits_to_insert -= 8 - bits_to_preserve;
    } else {
        dest[0] = slice[0];
        num_bits_to_insert -= 8;
    }

    let mut i: usize = 1;
    while num_bits_to_insert != 0 {
        if num_bits_to_insert >= 8 {
            dest[i] = slice[i];
            num_bits_to_insert -= 8;
            i += 1;
        } else {
            let mask = byte_mask(num_bits_to_insert);
            dest[i] &= !mask;
            dest[i] |= slice[i] & mask;
            return (&mut dest[i..], num_bits_to_insert);
        }
    }
    return (&mut dest[i..], 0);
}

/// Extracts an integer from a slice.
///
/// The integer will be `num_bits_to_extract` bits long, represented as a u64.
/// The first `lower_bits_used` bits of the first byte will be disregarded.
///
/// # Arguments
///
/// * `src` - the source slice whose first byte contains data to extract
/// * `num_bits_to_extract` - the number of bits to extract from the slice to
///   form a number
/// * `lower_bits_used` - the number of lower bits that are already being used
///   in the first slice
#[inline]
fn extract_int_v2(src: &[u8], num_bits_to_extract: u8, mut lower_bits_used: u8) -> u64 {
    debug_assert!(num_bits_to_extract <= 56);
    lower_bits_used &= 0b111;

    let mut arr = [0u8; 8];
    let len = min(src.len(), 8);
    arr[..len].copy_from_slice(&src[..len]);
    let mut result = u64::from_le_bytes(arr);
    result >>= lower_bits_used;
    result & u64_mask(num_bits_to_extract)
}

/// Inserts multiple trimmed ints into a slice.
///
/// # Arguments
///
/// * `ints` - the numbers that you want to insert into a slice.
/// * `dest` - the mutable destination slice. The first byte of this slice
///   should be the first byte that should be inserted into.
/// * `bits_of_each_int` - a slice containing the amount of bits from each
///   integer that should be copied into the `dest` slice.
/// * `bits_to_preserve` - the amount of lower bits to preserve in the first
///   byte of the `dest` slice
///
/// # Examples
/// ```ignore
/// 
/// let a: u64 = 375;
/// let b: u64 = 88372;
///
/// let mut dest_slice = [0u8; 20];
/// OsRng.fill_bytes(&mut dest_slice);
/// // let's say that a and b are numbers we want to embed in a slice, where we reserve 22 bits for a, and 38 bits for b.
/// // if we want the start index of the embedded data to be somewhere vague, we can change it... so long as the length of the slice is enough to hold this embedded data
///
/// insert_ints_into_slice(&[a, b], &mut dest_slice[3..], &[22, 38], 0);
///
/// // as long as `a` can be represented with 22 bits, and `b` can be represented with 38 bits, the numbers can be extracted:
/// let extracted_numbers = extract_ints_from_slice::<2>(&dest_slice[3..], &[22, 38], 0);
///
/// assert_eq!(extracted_numbers[0], a);
/// assert_eq!(extracted_numbers[1], b);
/// ```
#[inline]
pub fn insert_ints_into_slice(
    ints: &[u64],
    mut dest: &mut [u8],
    bits_of_each_int: &[u8],
    mut bits_to_preserve: u8,
) {
    for i in 0..ints.len() {
        (dest, bits_to_preserve) =
            insert_int_bits_v2(ints[i], dest, bits_of_each_int[i], bits_to_preserve)
    }
}

/// Extracts `NUMS` integers from a slice.
///
/// Returns `[num_1, num_2, ..., num_NUMS]`.
///
/// # Arguments
///
/// * `NUMS` - the amount of numbers you are trying to extract
/// * `src` - the slice you are trying to extract numbers from
/// * `num_bits_to_extract` - a slice containing the amount of bits you want
///   each extracted integer to be composed of. Each amount of bits should be
///   less than or equal to 56.
/// * `lower_bits_used` - the amount of bits in the first byte of `dest` that
///   you want to skip
#[inline]
pub fn extract_ints_from_slice<const NUMS: usize>(
    src: &[u8],
    num_bits_to_extract: &[u8],
    mut lower_bits_used: u8,
) -> [u64; NUMS] {
    debug_assert!(
        NUMS == num_bits_to_extract.len(),
        "You must provide the amount of bits for each number you want to extract."
    );

    let mut result: [u64; NUMS] = [0u64; NUMS];
    let mut start_index = 0;
    for (i, num_bits) in num_bits_to_extract.iter().enumerate() {
        result[i] = extract_int_v2(&src[start_index..], *num_bits, lower_bits_used);
        start_index += (lower_bits_used + num_bits) as usize >> 3;
        lower_bits_used = (lower_bits_used + num_bits) & 0b111;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use rand_core::RngCore;
    use std::format;
    use std::string::String;

    /// A function called by another test
    fn test_slices(max_bits: u8) {
        for bits_to_preserve in 0..8 {
            for num_bits in 1..max_bits {
                let mut random_slice = [0u8; 80];
                OsRng.fill_bytes(&mut random_slice);

                // insert the maximum value that can be represented with `num_bits`
                let val_to_insert: u64 = (1 << num_bits) - 1;

                insert_int_bits_v2(val_to_insert, &mut random_slice, max_bits, bits_to_preserve);

                let decoded_int = extract_int_v2(&random_slice, max_bits, bits_to_preserve);

                if decoded_int != val_to_insert {
                    let mut sum: u16 = 0;
                    for i in random_slice.iter() {
                        sum += *i as u16;
                    }
                    let mut first_9_bytes = String::with_capacity(18);
                    for b in random_slice[..9].iter() {
                        first_9_bytes.push_str(&format!("{:x}", b));
                    }

                    panic!(
                        "Correct value = {}\nDecoded value = {}\nbits_to_preserve = {}\nnum_bits \
                         = {}\nslice = {}\nsum = {}",
                        val_to_insert, decoded_int, bits_to_preserve, num_bits, &first_9_bytes, sum
                    )
                }
                assert_eq!(decoded_int, val_to_insert);

                OsRng.fill_bytes(&mut random_slice)
            }
        }
    }

    #[test]
    fn fuzz_compact_encoding_and_decoding() {
        for b in 1..=56 {
            test_slices(b)
        }
    }

    #[test]
    fn fuzz_chained_compact_encoding_and_decoding() {
        for i in 1..56 {
            for j in 1..56 {
                for bits_to_preserve in 0..7 {
                    for _test in 0..12 {
                        let i_bit_number = OsRng.next_u64() & u64_mask(i);
                        let j_bit_number = OsRng.next_u64() & u64_mask(j);

                        let mut random_slice = [0u8; 15];
                        OsRng.fill_bytes(&mut random_slice);

                        let num_bits = &[i as u8, j as u8];

                        insert_ints_into_slice(
                            &[i_bit_number, j_bit_number],
                            &mut random_slice,
                            num_bits,
                            bits_to_preserve,
                        );

                        let decoded_nums =
                            extract_ints_from_slice::<2>(&random_slice, num_bits, bits_to_preserve);

                        if decoded_nums[0] != i_bit_number {
                            let mut first_bytes = String::new();
                            for b in random_slice[..17].iter() {
                                first_bytes.push_str(&format!("{:b}", b));
                            }
                            panic!(
                                "decoded[0] != i_bit_number\n{:b} != {:b}\ni = {}\nj = \
                                 {}\ni_bit_number = {:b}\nj_bit_number = {:b}\nbits_to_preserve = \
                                 {}\ntest #{}\nslice = {}\nd[0] = {:b}\nd[1] = {:b}",
                                decoded_nums[0],
                                i_bit_number,
                                i,
                                j,
                                i_bit_number,
                                j_bit_number,
                                bits_to_preserve,
                                _test,
                                first_bytes,
                                decoded_nums[0],
                                decoded_nums[1]
                            );
                        }

                        if decoded_nums[1] != j_bit_number {
                            let mut first_bytes = String::new();
                            for b in random_slice[..17].iter() {
                                first_bytes.push_str(&format!("{:b}", b));
                            }
                            panic!(
                                "decoded[1] != j_bit_number\n{:b} != {:b}\ni = {}\nj = \
                                 {}\ni_bit_number = {:b}\nj_bit_number = {:b}\nbits_to_preserve = \
                                 {}\ntest #{}\nslice = {}\nd[0] = {:b}\nd[1] = {:b}",
                                decoded_nums[0],
                                j_bit_number,
                                i,
                                j,
                                i_bit_number,
                                j_bit_number,
                                bits_to_preserve,
                                _test,
                                first_bytes,
                                decoded_nums[0],
                                decoded_nums[1]
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    #[should_panic]
    fn insert_panic_dest_has_insufficient_size() {
        let mut arr = [0u8; 4];
        // this should panic because 30 bits to insert + 3 bits to preserve comes out to
        // 33 bits, when a 4 byte slice has 32 bits.
        insert_int_bits_v2(1, &mut arr, 30, 3);
    }

    #[test]
    fn prove_bits_are_preserved() {
        for i in 0..57 {
            for j in 0..57 {
                for bits_to_preserve in 0..8 {
                    let mut test_slice = [0u8; 20];

                    let i_ones = u64_mask(i);
                    let j_ones = u64_mask(j);

                    // writing `i` 1s and `j` 1s to a [0u8; 20] should result in a slice that has
                    // exactly `i + j` 1s
                    insert_ints_into_slice(
                        &[i_ones, j_ones],
                        &mut test_slice,
                        &[i, j],
                        bits_to_preserve,
                    );

                    let [i_decoded, j_decoded] =
                        extract_ints_from_slice(&test_slice, &[i, j], bits_to_preserve);

                    assert_eq!(i_decoded, i_ones);
                    assert_eq!(j_decoded, j_ones);

                    let mut num_ones = 0;
                    for b in test_slice.iter() {
                        for i in 0..8 {
                            num_ones += (b >> i) & 0b1;
                        }
                    }
                    assert_eq!(num_ones, i + j);
                }
            }
        }
    }
}

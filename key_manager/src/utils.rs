//! Some utilities that might come in handy.

/// Offers a method for sanitizing `String`s and `str`s
pub trait StringSanitization {
    fn sanitize_str(&self, alphabet: &str) -> String;
    fn trim_length(&self, len: usize) -> &str;
}

impl StringSanitization for &str {
    /// Sanitizes a string based on the allowed characters
    #[inline]
    fn sanitize_str(&self, allowed_chars: &str) -> String {
        let mut is_valid = [false; 256];
        for c in allowed_chars.chars() {
            is_valid[c as usize] = true;
        }
        self.chars().filter(|&c| is_valid[c as usize]).collect()
    }
    /// Trims a string to a length of characters. Unicode friendly.
    #[inline]
    fn trim_length(&self, len: usize) -> &str {
        match self.char_indices().nth(len) {
            None => self,
            Some((_i, _)) => &self[..len],
        }
    }
}

/// Pads a string with `w`s for base64 decoding.
///
/// The full padding is only used to be able to decode base64, but only up to 6
/// bits will actually be padding after the encoded slice is trimmed.
pub fn padding_trail(str: &str) -> String {
    let len_mod_4 = str.len() & 0b11;
    let next_len = str.len() + (4 - len_mod_4) * (len_mod_4 > 0) as usize;
    let padded = format!("{:w<width$}", str, width = next_len);
    padded
}

/// Calculates the binary length of a base64 encoded string.
#[inline]
pub fn b64_len_to_binary_len(len: usize) -> usize {
    // 6 bits per base64 char
    let bits = (len << 2) + (len << 1);
    (bits >> 3) + (bits & 0b111 > 0) as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padding() {
        let tests = ["ffff", "fffff", "ffffff", "fffffff", "ffffffff"];
        let expected = ["ffff", "fffffwww", "ffffffww", "fffffffw", "ffffffff"];
        for (t, e) in tests.iter().zip(expected.iter()) {
            assert_eq!(&padding_trail(t), e);
        }
    }

    #[test]
    fn base64_to_binary_length_conversions() {
        let test_lens = [
            ("a", 1),
            ("aa", 2),
            ("aaa", 3),
            ("aaaa", 3),
            ("aaaaa", 4),
            ("aaaaaa", 5),
            ("aaaaaaa", 6),
            ("aaaaaaaa", 6),
        ];

        for (test, expected) in test_lens.iter() {
            assert_eq!(b64_len_to_binary_len(test.len()), *expected)
        }
    }
}

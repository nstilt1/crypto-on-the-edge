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

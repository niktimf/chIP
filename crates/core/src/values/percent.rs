use std::num::NonZeroU64;

/// A share of a whole in percent: finite and within `0..=100`.
///
/// Packet loss and the CPU steal share are such shares. A difference between
/// two of them can be negative and is not a `Percent`.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct Percent(f64);

impl Percent {
    pub const ZERO: Self = Self(0.0);
    const MAX: f64 = 100.0;

    /// `part` of `whole` in percent. A `part` above `whole` saturates at 100
    /// percent instead of leaving the range.
    #[expect(
        clippy::cast_precision_loss,
        reason = "a share needs no more than f64 precision; part <= whole \
                  keeps the ratio within 0..=1 after rounding"
    )]
    pub fn saturating_ratio(part: u64, whole: NonZeroU64) -> Self {
        let whole = whole.get();
        let part = part.min(whole);
        Self(part as f64 / whole as f64 * Self::MAX)
    }

    pub const fn get(self) -> f64 {
        self.0
    }
}

impl TryFrom<f64> for Percent {
    type Error = InvalidPercent;

    fn try_from(value: f64) -> Result<Self, Self::Error> {
        if !value.is_finite() {
            return Err(InvalidPercent::NotFinite(value));
        }
        if !(0.0..=Self::MAX).contains(&value) {
            return Err(InvalidPercent::OutOfRange(value));
        }
        Ok(Self(value))
    }
}

/// Why a number is not a [`Percent`], with the rejected value.
#[derive(Debug, Clone, Copy, PartialEq, thiserror::Error)]
pub enum InvalidPercent {
    #[error("percent must be finite, got {0}")]
    NotFinite(f64),
    #[error("percent must be between 0 and 100, got {0}")]
    OutOfRange(f64),
}

impl InvalidPercent {
    pub const fn value(self) -> f64 {
        match self {
            Self::NotFinite(value) | Self::OutOfRange(value) => value,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[rstest::rstest]
    #[case::nan(f64::NAN)]
    #[case::infinite(f64::INFINITY)]
    fn a_non_finite_percent_is_rejected(#[case] value: f64) {
        let error = Percent::try_from(value).unwrap_err();

        assert!(matches!(error, InvalidPercent::NotFinite(_)), "{error:?}");
    }

    #[rstest::rstest]
    #[case::below_zero(-1.0)]
    #[case::above_one_hundred(100.1)]
    fn a_percent_outside_zero_to_one_hundred_is_rejected(#[case] value: f64) {
        let error = Percent::try_from(value).unwrap_err();

        assert!(matches!(error, InvalidPercent::OutOfRange(_)), "{error:?}");
    }

    #[rstest::rstest]
    #[case::zero(0.0)]
    #[case::one_hundred(100.0)]
    fn zero_and_one_hundred_are_valid_percents(#[case] value: f64) {
        let result = Percent::try_from(value);

        assert!(result.is_ok(), "{result:?}");
    }
}

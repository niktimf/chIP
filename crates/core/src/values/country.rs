use std::fmt;
use std::str::FromStr;

use country_code_enum::CountryCode as RegistryCountryCode;

/// A validated, upper-cased country code from the supported country registry.
///
/// It is kept separate from `String` because scan configuration has a `country` and a
/// `city` field of otherwise identical shape sitting next to each other; the
/// type is what makes swapping them at a call site a compile error instead
/// of a silent bug. The private field keeps registry validation on the input
/// boundary without exposing the dependency's type to the rest of the app.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CountryCode(RegistryCountryCode);

impl CountryCode {
    pub const RU: Self = Self(RegistryCountryCode::RU);

    pub fn as_str(&self) -> &str {
        self.0.as_ref()
    }
}

/// Error returned when a country code cannot be parsed.
///
/// This implements `std::error::Error`, as required by CLI parsing.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("'{0}' is not a recognized country code")]
pub struct InvalidCountryCode(String);

impl TryFrom<&str> for CountryCode {
    type Error = InvalidCountryCode;

    #[expect(
        clippy::map_err_ignore,
        reason = "the upstream error is a String that only repeats the input \
                  already kept in InvalidCountryCode"
    )]
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        value
            .parse::<RegistryCountryCode>()
            .map(Self)
            .map_err(|_| InvalidCountryCode(value.to_string()))
    }
}

impl FromStr for CountryCode {
    type Err = InvalidCountryCode;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::try_from(value)
    }
}

impl fmt::Display for CountryCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_two_letter_code_parses_and_upper_cases() {
        let sut: CountryCode = "fi".parse().unwrap();

        assert_eq!(sut.as_str(), "FI");
    }

    #[rstest::rstest]
    #[case::too_long("FIN")]
    #[case::too_short("F")]
    #[case::not_alphabetic("F1")]
    fn malformed_country_codes_are_rejected(#[case] input: &str) {
        let error = CountryCode::try_from(input).unwrap_err();

        assert_eq!(error, InvalidCountryCode(input.to_string()));
    }

    #[test]
    fn an_unassigned_two_letter_code_is_rejected() {
        let error = CountryCode::try_from("ZZ").unwrap_err();

        assert_eq!(error, InvalidCountryCode("ZZ".to_string()));
    }
}

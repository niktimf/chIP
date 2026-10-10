use std::fmt;
use std::str::FromStr;

/// A non-empty city label used for Atlas anchor selection.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CityName(String);

impl CityName {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("city name must not be empty")]
pub struct InvalidCityName;

impl FromStr for CityName {
    type Err = InvalidCityName;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let value = value.trim();
        if value.is_empty() {
            Err(InvalidCityName)
        } else {
            Ok(Self(value.to_string()))
        }
    }
}

impl fmt::Display for CityName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_city_name_is_trimmed_at_the_input_boundary() {
        let sut: CityName = "  Helsinki  ".parse().unwrap();

        assert_eq!(sut.as_str(), "Helsinki");
    }

    #[test]
    fn a_blank_city_name_is_rejected() {
        let error = "   ".parse::<CityName>().unwrap_err();

        assert_eq!(error, InvalidCityName);
    }
}

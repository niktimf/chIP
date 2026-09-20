use secrecy::{ExposeSecret as _, SecretString};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("secret value cannot be empty")]
pub struct EmptySecret;

fn parse_owned_secret(value: String) -> Result<SecretString, EmptySecret> {
    if value.trim().is_empty() {
        Err(EmptySecret)
    } else {
        Ok(SecretString::from(value))
    }
}

macro_rules! secret_type {
    ($name:ident) => {
        #[derive(Clone, Debug)]
        pub struct $name(SecretString);

        impl $name {
            pub(crate) fn expose(&self) -> &str {
                self.0.expose_secret()
            }
        }

        impl TryFrom<String> for $name {
            type Error = EmptySecret;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                parse_owned_secret(value).map(Self)
            }
        }
    };
}

secret_type!(GlobalpingToken);
secret_type!(ProxycheckApiKey);
secret_type!(SshPrivateKey);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_debug_output_never_contains_the_secret() {
        let raw = "credential-that-must-not-leak";
        let debug_outputs = [
            format!("{:?}", GlobalpingToken::try_from(raw.to_owned()).unwrap()),
            format!(
                "{:?}",
                ProxycheckApiKey::try_from(raw.to_owned()).unwrap()
            ),
            format!("{:?}", SshPrivateKey::try_from(raw.to_owned()).unwrap()),
        ];

        assert!(debug_outputs.iter().all(|output| !output.contains(raw)));
    }

    #[rstest::rstest]
    #[case::empty("")]
    #[case::whitespace(" \n\t ")]
    fn blank_credentials_are_rejected(#[case] raw: &str) {
        let error = GlobalpingToken::try_from(raw.to_owned()).unwrap_err();

        assert_eq!(error, EmptySecret);
    }
}

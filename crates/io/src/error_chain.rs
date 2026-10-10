use itertools::Itertools as _;

/// Renders an error with every `source()` below it, joined by `": "`.
///
/// `reqwest::Error` prints only its own layer ("error sending request"), so
/// the cause (refused, timed out, SOCKS failure) is reachable only through
/// the source chain.
pub fn describe_error(error: &dyn std::error::Error) -> String {
    std::iter::successors(Some(error), |current| current.source()).join(": ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, thiserror::Error)]
    #[error("GET https://example.test/ failed")]
    struct Outer(#[source] Middle);

    #[derive(Debug, thiserror::Error)]
    #[error("client error (Connect)")]
    struct Middle(#[source] std::io::Error);

    #[test]
    fn an_error_description_names_every_cause_in_the_chain() {
        let error = Outer(Middle(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "Connection refused",
        )));

        let description = describe_error(&error);

        assert_eq!(
            description,
            "GET https://example.test/ failed: client error (Connect): \
             Connection refused"
        );
    }
}

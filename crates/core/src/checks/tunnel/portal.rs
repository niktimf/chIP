//! Vendor connectivity-check endpoints and the rule that tells a genuine
//! answer from one a captive portal or a middlebox rewrote.
use http::StatusCode;
use itertools::{Either, Itertools as _};
use strum::{Display, IntoStaticStr};
use url::Url;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortalOutcome {
    Ok,
    Altered,
    Unreachable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Display, IntoStaticStr)]
#[strum(serialize_all = "lowercase")]
pub enum Scheme {
    Http,
    Https,
}

/// One vendor-documented endpoint with the answer the vendor promises.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortalEndpoint {
    scheme: Scheme,
    /// Host and path in the form `Url` serializes them, so the URL built
    /// from it compares equal to the URL of the final response.
    host_path: &'static str,
    expected_status: StatusCode,
    /// Compared after trimming whitespace on both sides.
    expected_body: &'static str,
}

impl PortalEndpoint {
    pub const ALL: &[Self] = &[
        Self::new(
            Scheme::Http,
            "connectivitycheck.gstatic.com/generate_204",
            StatusCode::NO_CONTENT,
            "",
        ),
        Self::new(
            Scheme::Http,
            "cp.cloudflare.com/generate_204",
            StatusCode::NO_CONTENT,
            "",
        ),
        Self::new(
            Scheme::Http,
            "captive.apple.com/hotspot-detect.html",
            StatusCode::OK,
            "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>",
        ),
        Self::new(
            Scheme::Http,
            "www.msftconnecttest.com/connecttest.txt",
            StatusCode::OK,
            "Microsoft Connect Test",
        ),
        Self::new(
            Scheme::Http,
            "detectportal.firefox.com/success.txt",
            StatusCode::OK,
            "success",
        ),
        Self::new(
            Scheme::Https,
            "connectivitycheck.gstatic.com/generate_204",
            StatusCode::NO_CONTENT,
            "",
        ),
        Self::new(
            Scheme::Https,
            "cp.cloudflare.com/generate_204",
            StatusCode::NO_CONTENT,
            "",
        ),
    ];

    const fn new(
        scheme: Scheme,
        host_path: &'static str,
        expected_status: StatusCode,
        expected_body: &'static str,
    ) -> Self {
        Self {
            scheme,
            host_path,
            expected_status,
            expected_body,
        }
    }

    pub const fn scheme(&self) -> Scheme {
        self.scheme
    }

    pub fn url(&self) -> String {
        format!("{}://{}", self.scheme, self.host_path)
    }

    /// `Ok` only when the response came from this very URL (no redirect)
    /// with the vendor's status and body; any other answer is `Altered`.
    pub fn classify(
        &self,
        status: StatusCode,
        final_url: &Url,
        body: &str,
    ) -> PortalOutcome {
        let scheme: &str = self.scheme.into();
        let same_url = final_url.as_str().split_once("://")
            == Some((scheme, self.host_path));
        let same_body = body.trim() == self.expected_body.trim();
        if status == self.expected_status && same_url && same_body {
            PortalOutcome::Ok
        } else {
            PortalOutcome::Altered
        }
    }
}

/// Portal outcomes split by the scheme of the endpoint they came from.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PortalChecks {
    pub https: Vec<PortalOutcome>,
    pub http: Vec<PortalOutcome>,
}

impl FromIterator<(Scheme, PortalOutcome)> for PortalChecks {
    fn from_iter<I: IntoIterator<Item = (Scheme, PortalOutcome)>>(
        iter: I,
    ) -> Self {
        let (https, http) =
            iter.into_iter()
                .partition_map(|(scheme, outcome)| match scheme {
                    Scheme::Https => Either::Left(outcome),
                    Scheme::Http => Either::Right(outcome),
                });
        Self { https, http }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use rstest::rstest;

    const HOST_PATH: &str = "detectportal.firefox.com/success.txt";

    fn endpoint(scheme: Scheme) -> PortalEndpoint {
        PortalEndpoint::new(scheme, HOST_PATH, StatusCode::OK, "success")
    }

    fn url(text: &str) -> Url {
        Url::parse(text).unwrap()
    }

    #[test]
    fn the_vendor_answer_from_the_requested_url_is_ok() {
        let sut = endpoint(Scheme::Https);
        let final_url = url("https://detectportal.firefox.com/success.txt");

        let outcome = sut.classify(StatusCode::OK, &final_url, "success\n");

        assert_eq!(outcome, PortalOutcome::Ok);
    }

    #[rstest]
    #[case::wrong_body(
        StatusCode::OK,
        "https://detectportal.firefox.com/success.txt",
        "<html>Log in to the hotel Wi-Fi</html>"
    )]
    #[case::wrong_status(
        StatusCode::FOUND,
        "https://detectportal.firefox.com/success.txt",
        "success"
    )]
    #[case::redirect_to_another_host(
        StatusCode::OK,
        "https://portal.example/success.txt",
        "success"
    )]
    #[case::downgrade_to_plain_http(
        StatusCode::OK,
        "http://detectportal.firefox.com/success.txt",
        "success"
    )]
    fn an_answer_that_differs_from_the_vendor_one_is_altered(
        #[case] status: StatusCode,
        #[case] final_url: &str,
        #[case] body: &str,
    ) {
        let sut = endpoint(Scheme::Https);
        let final_url = url(final_url);

        let outcome = sut.classify(status, &final_url, body);

        assert_eq!(outcome, PortalOutcome::Altered);
    }

    #[test]
    fn every_endpoint_url_is_already_in_the_form_url_serializes() {
        let urls: Vec<String> = PortalEndpoint::ALL
            .iter()
            .map(PortalEndpoint::url)
            .collect();

        let reparsed: Vec<String> =
            urls.iter().map(|text| url(text).into()).collect();

        assert_eq!(reparsed, urls);
    }

    #[test]
    fn outcomes_are_grouped_by_the_scheme_of_their_endpoint() {
        let sut = [
            (Scheme::Http, PortalOutcome::Ok),
            (Scheme::Https, PortalOutcome::Ok),
            (Scheme::Http, PortalOutcome::Altered),
        ];

        let checks: PortalChecks = sut.into_iter().collect();

        assert_eq!(
            checks,
            PortalChecks {
                https: vec![PortalOutcome::Ok],
                http: vec![PortalOutcome::Ok, PortalOutcome::Altered],
            }
        );
    }
}

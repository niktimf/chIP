use crate::Verdict;
use crate::values::CountryCode;

/// One vote per keyless `GeoIP` source, in the order the sources are
/// queried.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeoConsensusFacts {
    pub votes: Vec<GeoVote>,
}

/// What one `GeoIP` source says about the candidate's country.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeoVote {
    /// The source named this country.
    Country(CountryCode),
    /// The source answered, but its answer holds no ISO 3166-1 alpha-2 code:
    /// the field is missing or holds something else, such as a full country
    /// name.
    NoCountryCode,
    /// The source did not answer: timeout, failed request, HTTP error status
    /// or a body that is not JSON.
    NoAnswer,
}

const MIN_ANSWERS: usize = 5;
// The two shares below were set with the first version of the gate and
// have not been tuned against measured scans since.
/// Below this share of answering sources naming the ordered country the
/// address is placed elsewhere: FAIL.
const FAIL_BELOW_SHARE: f64 = 0.5;
/// Below this share the sources disagree too much for OK: WARN.
const WARN_BELOW_SHARE: f64 = 0.8;

#[expect(
    clippy::cast_precision_loss,
    reason = "vote counts are a handful of geo sources, far below 2^52"
)]
pub fn judge_geo(facts: &GeoConsensusFacts, expected: &CountryCode) -> Verdict {
    let total = facts.votes.len();
    let answered: Vec<CountryCode> = facts
        .votes
        .iter()
        .filter_map(|vote| match vote {
            GeoVote::Country(country) => Some(*country),
            GeoVote::NoCountryCode | GeoVote::NoAnswer => None,
        })
        .collect();
    let silent = count(facts, GeoVote::NoAnswer);
    let without_code = count(facts, GeoVote::NoCountryCode);
    if answered.len() < MIN_ANSWERS {
        // "answered" would be false when a source answered without a code.
        let counted = if without_code == 0 {
            "answered"
        } else {
            "named a country"
        };
        return Verdict::error(format!(
            "only {} of {total} geo sources {counted} (need >= {MIN_ANSWERS})",
            answered.len()
        ));
    }
    let russia = CountryCode::RU;
    let matching = answered.iter().filter(|c| *c == expected).count();
    let share = matching as f64 / answered.len() as f64;
    let ru_seen = expected != &russia && answered.contains(&russia);
    let unnamed: Vec<String> = [
        (silent, "did not answer"),
        (without_code, "answered without a country code"),
    ]
    .into_iter()
    .filter(|&(sources, _)| sources > 0)
    .map(|(sources, what)| format!("{sources} of {total} {what}"))
    .collect();
    let detail = format!(
        "{matching}/{} geo sources say {expected}{}",
        answered.len(),
        if unnamed.is_empty() {
            String::new()
        } else {
            format!(" ({})", unnamed.join(", "))
        }
    );
    if share < FAIL_BELOW_SHARE {
        Verdict::fail(detail)
    } else if share < WARN_BELOW_SHARE || ru_seen {
        Verdict::warn(if ru_seen {
            format!("{detail} (at least one source sees RU)")
        } else {
            detail
        })
    } else {
        Verdict::ok(detail)
    }
}

fn count(facts: &GeoConsensusFacts, kind: GeoVote) -> usize {
    facts.votes.iter().filter(|&&vote| vote == kind).count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::Severity;

    fn cc(code: &str) -> CountryCode {
        code.parse().unwrap()
    }

    /// One vote per entry: a country code, or `None` for a silent source.
    fn votes(codes: &[Option<&str>]) -> GeoConsensusFacts {
        GeoConsensusFacts {
            votes: codes
                .iter()
                .map(|code| {
                    code.map_or(GeoVote::NoAnswer, |code| {
                        GeoVote::Country(cc(code))
                    })
                })
                .collect(),
        }
    }

    #[rstest::rstest]
    #[case::unanimous_agreement(
        votes(&[Some("FI"), Some("fi"), Some("FI"), Some("FI"), Some("FI")]),
        Severity::Ok
    )]
    #[case::under_half_agreement(
        votes(&[Some("DE"), Some("DE"), Some("FI"), Some("NL"), Some("US")]),
        Severity::Fail
    )]
    // 3/5 = 60%: inside (0.5, 0.8), away from the 80% boundary.
    #[case::between_half_and_eighty_percent(
        votes(&[Some("FI"), Some("FI"), Some("FI"), Some("DE"), Some("NL")]),
        Severity::Warn
    )]
    #[case::anyone_seeing_russia_even_at_full_agreement_otherwise(
        votes(&[Some("FI"), Some("FI"), Some("FI"), Some("FI"), Some("RU")]),
        Severity::Warn
    )]
    #[case::fewer_than_five_answers_is_an_error(
        votes(&[Some("FI"), None, None, None, None, None, None, None, None]),
        Severity::Error
    )]
    fn the_share_of_sources_naming_the_ordered_country_sets_the_severity(
        #[case] sut: GeoConsensusFacts,
        #[case] expected: Severity,
    ) {
        let verdict = judge_geo(&sut, &cc("FI"));

        assert_eq!(verdict.severity, expected, "{}", verdict.detail);
    }

    #[test]
    fn the_detail_counts_the_sources_that_never_answered() {
        let sut = votes(&[
            Some("FI"),
            Some("FI"),
            Some("FI"),
            Some("FI"),
            Some("FI"),
            Some("DE"),
            None,
            None,
            None,
        ]);

        let verdict = judge_geo(&sut, &cc("FI"));

        assert_eq!(
            verdict.detail,
            "5/6 geo sources say FI (3 of 9 did not answer)"
        );
    }

    #[test]
    fn the_detail_stays_short_when_every_source_answered() {
        let sut = votes(&[
            Some("FI"),
            Some("FI"),
            Some("FI"),
            Some("FI"),
            Some("FI"),
        ]);

        let verdict = judge_geo(&sut, &cc("FI"));

        assert_eq!(verdict.detail, "5/5 geo sources say FI");
    }

    #[test]
    fn the_detail_tells_a_source_without_a_country_code_from_a_silent_one() {
        let sut = GeoConsensusFacts {
            votes: vec![
                GeoVote::Country(cc("FI")),
                GeoVote::Country(cc("FI")),
                GeoVote::Country(cc("FI")),
                GeoVote::Country(cc("FI")),
                GeoVote::Country(cc("FI")),
                GeoVote::NoCountryCode,
                GeoVote::NoAnswer,
                GeoVote::NoAnswer,
            ],
        };

        let verdict = judge_geo(&sut, &cc("FI"));

        assert_eq!(
            verdict.detail,
            "5/5 geo sources say FI (2 of 8 did not answer, 1 of 8 answered \
             without a country code)"
        );
    }

    #[test]
    fn too_few_named_countries_are_not_reported_as_too_few_answers() {
        let sut = GeoConsensusFacts {
            votes: vec![
                GeoVote::Country(cc("FI")),
                GeoVote::Country(cc("FI")),
                GeoVote::Country(cc("FI")),
                GeoVote::Country(cc("FI")),
                GeoVote::NoCountryCode,
                GeoVote::NoAnswer,
            ],
        };

        let verdict = judge_geo(&sut, &cc("FI"));

        assert_eq!(verdict.severity, Severity::Error);
        assert_eq!(
            verdict.detail,
            "only 4 of 6 geo sources named a country (need >= 5)"
        );
    }
}

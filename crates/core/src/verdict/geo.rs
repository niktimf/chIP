use crate::Verdict;
use crate::model::{CountryCode, GeoConsensusFacts};

const MIN_ANSWERS: usize = 5;

#[allow(clippy::cast_precision_loss)]
pub fn judge_geo(facts: &GeoConsensusFacts, expected: &CountryCode) -> Verdict {
    let answered: Vec<CountryCode> =
        facts.votes.iter().flatten().copied().collect();
    if answered.len() < MIN_ANSWERS {
        return Verdict::error(format!(
            "only {} of {} geo sources answered (need >= {MIN_ANSWERS})",
            answered.len(),
            facts.votes.len()
        ));
    }
    let russia =
        CountryCode::try_from("RU").expect("RU is a valid country code");
    let matching = answered.iter().filter(|c| *c == expected).count();
    let share = matching as f64 / answered.len() as f64;
    let ru_seen = expected != &russia && answered.contains(&russia);
    let silent = facts.votes.len() - answered.len();
    let detail = format!(
        "{matching}/{} geo sources say {expected}{}",
        answered.len(),
        if silent == 0 {
            String::new()
        } else {
            format!(" ({silent} of {} did not answer)", facts.votes.len())
        }
    );
    if share < 0.5 {
        Verdict::fail(detail)
    } else if share < 0.8 || ru_seen {
        Verdict::warn(if ru_seen {
            format!("{detail} (at least one source sees RU)")
        } else {
            detail
        })
    } else {
        Verdict::ok(detail)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Severity;

    fn cc(code: &str) -> CountryCode {
        code.parse().unwrap()
    }

    fn votes(codes: &[Option<&str>]) -> GeoConsensusFacts {
        GeoConsensusFacts {
            votes: codes.iter().map(|c| c.map(cc)).collect(),
        }
    }

    #[test]
    fn unanimous_agreement_is_ok() {
        let sut = votes(&[
            Some("FI"),
            Some("fi"),
            Some("FI"),
            Some("FI"),
            Some("FI"),
        ]);

        let verdict = judge_geo(&sut, &cc("FI"));

        assert_eq!(verdict.severity, Severity::Ok, "{}", verdict.detail);
    }

    #[test]
    fn under_half_agreement_fails() {
        let sut = votes(&[
            Some("DE"),
            Some("DE"),
            Some("FI"),
            Some("NL"),
            Some("US"),
        ]);

        assert_eq!(judge_geo(&sut, &cc("FI")).severity, Severity::Fail);
    }

    #[test]
    fn between_half_and_eighty_percent_warns() {
        // 3/5 = 60%: inside (0.5, 0.8), away from the 80% boundary.
        let sut = votes(&[
            Some("FI"),
            Some("FI"),
            Some("FI"),
            Some("DE"),
            Some("NL"),
        ]);

        assert_eq!(judge_geo(&sut, &cc("FI")).severity, Severity::Warn);
    }

    #[test]
    fn anyone_seeing_russia_warns_even_at_full_agreement_otherwise() {
        let sut = votes(&[
            Some("FI"),
            Some("FI"),
            Some("FI"),
            Some("FI"),
            Some("RU"),
        ]);

        assert_eq!(judge_geo(&sut, &cc("FI")).severity, Severity::Warn);
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
    fn fewer_than_five_answers_is_an_error() {
        let sut = votes(&[
            Some("FI"),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        ]);

        assert_eq!(judge_geo(&sut, &cc("FI")).severity, Severity::Error);
    }
}

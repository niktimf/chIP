use super::client::MeasurementId;
use serde::Serialize;
use std::num::NonZeroU8;
use thiserror::Error;

/// How many Russian probes of each network type a measurement runs on.
///
/// A group may be empty, but not both. Globalping requires `limit >= 1` for
/// every location, so an empty group is left out of the request instead of
/// being sent as `"limit": 0`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeSelection {
    eyeball: Option<NonZeroU8>,
    datacenter: Option<NonZeroU8>,
}

/// Both probe counts are zero, so no probe would measure anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("eyeball and datacenter probe counts cannot both be zero")]
pub struct EmptyProbeSelection;

impl ProbeSelection {
    /// # Errors
    ///
    /// Returns `EmptyProbeSelection` when both counts are zero.
    pub const fn new(
        eyeball: u8,
        datacenter: u8,
    ) -> Result<Self, EmptyProbeSelection> {
        match (NonZeroU8::new(eyeball), NonZeroU8::new(datacenter)) {
            (None, None) => Err(EmptyProbeSelection),
            (eyeball, datacenter) => Ok(Self {
                eyeball,
                datacenter,
            }),
        }
    }

    /// Globalping tests that `measurements` measurements on these probes
    /// cost: every measurement is one test per probe. Saturates, so an
    /// absurd plan reads as more than any quota holds.
    pub fn tests_for(self, measurements: u32) -> u32 {
        let probes = [self.eyeball, self.datacenter]
            .into_iter()
            .flatten()
            .map(|count| u32::from(count.get()))
            .sum::<u32>();
        probes.saturating_mul(measurements)
    }

    fn locations(self) -> Vec<ProbeLocation> {
        [
            ("eyeball-network", self.eyeball),
            ("datacenter-network", self.datacenter),
        ]
        .into_iter()
        .filter_map(|(tag, limit)| {
            limit.map(|limit| ProbeLocation::ru(tag, limit))
        })
        .collect()
    }
}

/// Which probes a measurement runs on.
#[derive(Debug)]
pub struct Locations(LocationsInner);

#[derive(Debug)]
enum LocationsInner {
    Ru(ProbeSelection),
    Reuse(String),
}

impl Locations {
    pub const fn ru(probes: ProbeSelection) -> Self {
        Self(LocationsInner::Ru(probes))
    }

    /// Runs on the probe set of an earlier measurement of any kind, so
    /// results of both measurements line up probe by probe.
    pub fn reuse<K>(id: &MeasurementId<K>) -> Self {
        Self(LocationsInner::Reuse(id.as_str().to_owned()))
    }

    pub(super) fn body(&self) -> LocationsBody<'_> {
        match &self.0 {
            LocationsInner::Ru(probes) => {
                LocationsBody::Probes(probes.locations())
            }
            LocationsInner::Reuse(id) => LocationsBody::Reuse(id),
        }
    }
}

/// Either a list of probe filters or, to reuse the probes of an earlier
/// measurement, its id as a bare string.
#[derive(Serialize)]
#[serde(untagged)]
pub(super) enum LocationsBody<'a> {
    Probes(Vec<ProbeLocation>),
    Reuse(&'a str),
}

#[derive(Serialize)]
pub(super) struct ProbeLocation {
    country: &'static str,
    limit: NonZeroU8,
    tags: [&'static str; 1],
}

impl ProbeLocation {
    const fn ru(tag: &'static str, limit: NonZeroU8) -> Self {
        Self {
            country: "RU",
            limit,
            tags: [tag],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_probes_of_both_kinds_make_no_selection() {
        let actual = ProbeSelection::new(0, 0);

        assert_eq!(actual, Err(EmptyProbeSelection));
    }

    #[test]
    fn every_measurement_costs_one_test_per_probe() {
        let sut = ProbeSelection::new(8, 4).unwrap();

        let tests = sut.tests_for(7);

        assert_eq!(tests, 84);
    }
}

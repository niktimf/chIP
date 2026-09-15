//! Guards Global Constraints: `chip-core` must never depend on a networking
//! or process-spawning crate. Reads its own `Cargo.toml` rather than trusting
//! convention, so a future edit that adds one of these breaks CI immediately.
use std::fs;

#[test]
fn core_manifest_has_no_network_dependencies() {
    let manifest = fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"))
        .expect("crates/core/Cargo.toml must exist");
    for forbidden in ["reqwest", "tokio", "openssh"] {
        assert!(
            !manifest.contains(forbidden),
            "chip-core/Cargo.toml must not depend on `{forbidden}` \
             (Global Constraints: core has no network deps)"
        );
    }
}

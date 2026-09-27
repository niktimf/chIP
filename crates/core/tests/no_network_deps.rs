//! Guards Global Constraints: `chip-core` must never pull a networking or
//! process-spawning crate, directly or transitively. Asks cargo for the
//! resolved dependency tree instead of grepping the manifest, so an indirect
//! dependency breaks CI the same way a direct one would, and a name inside
//! a comment cannot false-positive.
use std::collections::HashSet;
use std::process::Command;

#[test]
fn core_dependency_tree_has_no_network_crates() {
    let output = Command::new(env!("CARGO"))
        .args([
            "tree",
            "--package",
            "chip-core",
            "--edges",
            "normal",
            "--prefix",
            "none",
            "--locked",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("cargo tree must run");
    assert!(
        output.status.success(),
        "cargo tree failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let tree = String::from_utf8_lossy(&output.stdout);
    let crates: HashSet<&str> = tree
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .collect();
    for forbidden in ["reqwest", "hyper", "tokio", "async-std", "openssh"] {
        assert!(
            !crates.contains(forbidden),
            "chip-core must not depend on `{forbidden}` \
             (Global Constraints: core has no network deps); tree:\n{tree}"
        );
    }
}

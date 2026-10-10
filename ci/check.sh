#!/usr/bin/env sh
set -eu

# The commands of every CI check. Each job of .github/workflows/ci.yml runs
# one group, `sh ci/check.sh <group>`, so the commands are written only here.
# Without an argument all groups run, which is what to do before a push.
#
# The dependencies group needs cargo-deny and cargo-machete:
#     cargo install --locked cargo-deny cargo-machete

lint_and_test() {
    cargo fmt --all --check
    cargo clippy --locked --workspace --all-targets --all-features \
        -- -D warnings
    cargo test --locked --workspace
}

msrv() {
    cargo +1.88.0 check --locked --workspace --all-targets --all-features
}

dependencies() {
    cargo deny --locked check
    cargo deny --locked --manifest-path crates/core/Cargo.toml \
        --config crates/core/deny.toml check bans
    cargo machete
}

case "${1:-all}" in
    lint-and-test) lint_and_test ;;
    msrv) msrv ;;
    dependencies) dependencies ;;
    all)
        lint_and_test
        msrv
        dependencies
        ;;
    *)
        echo "usage: $0 [lint-and-test | msrv | dependencies | all]" >&2
        exit 2
        ;;
esac

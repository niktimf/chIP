#!/usr/bin/env sh
set -eu
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace
cargo +1.88.0 check --locked --workspace --all-targets --all-features
cargo deny --locked check
cargo machete

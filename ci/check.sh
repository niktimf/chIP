#!/usr/bin/env sh
set -eu

# Needs cargo-deny and cargo-machete:
#     cargo install --locked cargo-deny cargo-machete
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace
cargo +1.88.0 check --locked --workspace --all-targets --all-features
cargo deny --locked check
cargo deny --locked --manifest-path crates/core/Cargo.toml \
    --config crates/core/deny.toml check bans
cargo machete

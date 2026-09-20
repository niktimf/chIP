# chIP

`chip` vets a candidate cloud IPv4 address before it becomes a Remnawave exit
node. It combines public reputation and routing data, measurements from Russian
Globalping probes, service behavior through an SSH SOCKS tunnel, and a gentle
scan of the candidate's `/24`.

## Usage

```sh
chip scan 203.0.113.42 --country FI --city Helsinki
```

Exit codes are designed for automation:

- `0`: no gate failed (warnings are allowed);
- `1`: at least one gate failed, so rotate the candidate IP;
- `2`: no gate failed, but at least one check could not reach a verdict, so
  retry rather than rejecting the IP.

Write the structured verdict to a file with `--json report.json`. When
`GITHUB_STEP_SUMMARY` is set, `chip` also writes a Markdown summary there.

To derive latency thresholds from known-good nodes:

```sh
chip calibrate 192.0.2.10=Helsinki 198.51.100.20=Frankfurt
```

## Checks

The scan covers:

- proxy/VPN/Tor reputation, Spamhaus DROP and FireHOL level 1;
- country consensus across public GeoIP sources and RIPE routing provenance;
- latency relative to RIPE Atlas anchors and HTTPS reachability from Russia;
- ChatGPT, Gemini, YouTube Premium, Netflix, Claude, TikTok and NotebookLM;
- service-observed country, CDN edge country and repeated search CAPTCHA;
- AI API reachability, captive-portal tampering and outbound HTTP blocking;
- CPU steal, candidate PTR and unusual certificate/PTR patterns in its `/24`.

Warnings can be promoted with `--gate <id>`, for example
`--gate service:claude`. A gate can be ignored with `--skip-gate <id>`.

## Requirements

- Local `ssh`, `openssl`, and `dig` executables. `openssl` and `dig` are used
  by the optional neighbor sweep; the remote host also needs `openssl` for the
  temporary reachability listener.
- SSH access to the candidate. Configure `SSH_PRIVATE_KEY` (key contents),
  `SSH_USER` (default `root`), `SSH_PORT` (default `22`) and optionally
  `SSH_KNOWN_HOSTS`. `--no-ssh` records SSH-dependent gates as explicitly
  skipped while still running independent checks.
- `GLOBALPING_TOKEN` is recommended for a larger measurement quota.
- `PROXYCHECK_API_KEY` is optional and raises proxycheck.io limits.

Credential values are environment-only; `chip` intentionally has no command-
line flags for them, so they do not end up in shell history or process
arguments. Without `SSH_KNOWN_HOSTS`, SSH uses trust-on-first-use
(`accept-new`). Supply `SSH_KNOWN_HOSTS` when the host key is known and strict
verification is required.

Run `chip scan --help` for all thresholds, probe counts and opt-out flags.

## Operational behavior

For the reachability check, `chip` starts a temporary TLS listener on the
candidate over SSH, preferring port 443 and falling back to 8443. It removes
the listener, private temporary key directory, and any firewall rule added by
the run after the scan; the remote listener also has a ten-minute lifetime and
self-cleans those resources as a safety net.

The `/24` sweep originates from the machine running `chip`, uses bounded
concurrency, and performs one short TLS/PTR probe per address. `chip` does not
create, rotate, or delete cloud infrastructure.

## Development

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
```

The project requires Rust 1.85 or newer and is licensed under MIT.

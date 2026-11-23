# Contributing

Thanks for your interest in improving SlipperyPickle.

## Ground rules

- **Stay in scope.** SlipperyPickle is a research bench whose techniques feed into [AntiHunter]
  (https://github.com/lukeswitz/AntiHunter). 
- **Passive by default.** Any new *active* technique (one that transmits to or connects to a
  third-party device) must gate on the existing `activeFp` master switch and default to off.
- **Cite your sources.** New fingerprint/correlation signals should reference the research they come
  from; add a row to [docs/PAPERS.md](docs/PAPERS.md).

## Development notes

- The tool is a single `bash` script, `payload.sh`, that runs on the WiFi Pineapple's bash. The embedded
  `awk` programs are written to `/tmp` at startup.
- Runtime environment is **busybox**: busybox `awk` (no `gawk`/`strtonum`), busybox `sort`, etc.
  Avoid GNU-only behavior. There is no `python3`, `tshark`, `gawk`, `xxd`, or `od` on the device.
- Interactive helper functions prefixed in UPPER_CASE (`LOG`, `LED`, `PROMPT`, `LIST_PICKER`,
  `WAIT_FOR_INPUT`, …) are provided by the Pineapple payload framework — do not rename them.
- Everything else uses `camelCase` for functions and variables.
- Keep correlation changes conservative: prefer signals that **split** over-merged clusters to ones
  that risk **false merges**. A false link in a device-correlation tool is worse than a miss.

## Testing

- Syntax-check with `bash -n payload.sh` (needs bash 4+; the WiFi Pineapple has bash 5.2).
- Functional testing is best done on-device against live recon data, since the behavior depends on
  the Pineapple's databases and radios. Stub the framework helper functions
  (`LOG`/`LED`/`PROMPT`/…) to run headless.

## Submitting

- Open an issue describing the change first for anything non-trivial.
- Keep pull requests focused. Update the relevant docs and `CHANGELOG.md`.
- Do not include personal data, credentials, device addresses, or capture files in commits.

# Changelog

All notable changes to this project are documented here. Versions use a date-stamped scheme:
`vYYYYMMDD`, with `-rcN` for release candidates.

## v20261122-rc1 — 2026-11-22

First public release candidate.

### Added
- **Three-stage identity architecture** (passive database enrichment, passive 802.11 fingerprint,
  opt-in active GATT probe). See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
- **PNL (probed-SSID) correlation** — links rotated MACs that share an uncommon SSID set
  (Martin et al., 2017).
- **802.11 IE fingerprint** via passive `tcpdump` on the live monitor interface
  (Vanhoef et al., 2016; Martin et al., 2017).
- **802.11 sequence-number capture**, surfaced in the device-detail view for manual rotation
  analysis (Vanhoef et al., 2016).
- **BLE enrichment** — randomized-address flag (`le_random`) and device-type decoding from
  manufacturer/service data: Apple Continuity, Samsung, Huawei, Xiaomi/Mi (MIoT), Google Fast Pair
  (Becker et al., 2019; Martin et al., 2019; Celosia & Cunche, 2020; Zuo et al., 2019).
- **Expanded BLE company-ID vendor labels** — in addition to the above, devices are now labelled by
  Bluetooth SIG company ID for OnePlus, Oppo, vivo, Realme, Nubia (RedMagic), ZTE, Honor, Meizu,
  Lenovo/Motorola and Transsion (Tecno/Infinix/itel); plus HMD/Nokia, Nothing, LG, HTC, TCL, Alcatel,
  Fairphone, Asus, BlackBerry, Vertu, Yota, Gigaset and a second Google ID — all mapped to Android
  (Jolla → Sailfish). (Redmi = Xiaomi; RedMagic = Nubia.)
- **Active Stage 3 GATT probe** (opt-in) — reads Device Information and enumerates service UUIDs
  (Celosia & Cunche, 2019).
- **Cross-radio Wi-Fi↔BT co-presence** pairing, reported as ranked low-confidence candidates
  (Longo et al., 2018).
- **Master `activeFp` switch** — passive by default; one flag unlocks all active techniques. Startup
  banner shows the current mode.
- Full documentation set: README, architecture, usage, and a research/papers table.

### Notes
- Passive by default; active techniques never run unless `activeFp=true`.
- Sequence numbers are captured and displayed but intentionally **not** auto-merged into the
  correlation engine (single-channel capture would cause false merges). See
  [docs/PAPERS.md](docs/PAPERS.md).
- Techniques requiring an SDR or specialized sniffers (BLE physical-layer fingerprinting,
  AWDL/AirDrop) are documented as out of scope for this hardware in
  [docs/PAPERS.md](docs/PAPERS.md).

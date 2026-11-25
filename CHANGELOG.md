# Changelog

All notable changes to this project are documented here. Versions use a date-stamped scheme:
`vYYYYMMDD`, with `-rcN` for release candidates.

## v20261124-rc1 — 2026-11-24

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

- **Tracker-tag detection** — AirTag, Find My accessories, Samsung SmartTag, Tile, Chipolo,
  Pebblebee, Google Find My Device tags and DULT-standard tags (`0xFCB2`) are recognised from their
  adverts (byte rules from AirGuard, Heinrich et al., arXiv:2202.11813). Compare has a tracker section,
  separated-from-owner tags first, and the alert prioritises them. Service data is now parsed as
  advertising structures instead of substring-matched, and advertised service UUIDs (`svc16`) are used.

- **Dwell time** — the recurring-identities report shows how long each identity was present this
  session (first-seen to last-seen).
- **Known-devices filtering (ignore-list)** — **Learn known here** captures everything currently
  around you (no MAC typing) into `known.txt`; those identities are hidden from Compare. Matching
  is on identity tokens (hostname / BLE name / stable MAC), so it survives MAC rotation.
- **Cross-session history** — identities are remembered across runs in `history.txt` (token +
  first/last seen + session count), shown as the `HIST` column, and auto-expired after `histDays`.
  **Clear saved data** wipes the history or the known list.

- **Single-instance guard** — a lock file prevents a second copy from starting and colliding with
  the running one's shared `/tmp` state; a stale lock from a crashed run is taken over. Cleanup is
  gated so a refused copy can never tear down the running instance.
- **Startup recon.db health check** — a one-time `PRAGMA quick_check` warns if the Wi-Fi database is
  corrupt (its index has been seen damaged), so empty/partial results aren't mistaken for "all clear".

### Fixed
- **AP beacons no longer counted as probed-SSID lists.** Only probe requests feed the PNL, so
  access points with the same SSID (mesh nodes, guest networks) are no longer merged.
- **Access points are labelled `AP …` and excluded from Wi-Fi↔BT pairing** (an AP cannot be the
  Wi-Fi radio of a phone).
- **IE fingerprint is no longer a strong merge key.** It links identities only when rare
  (`fpCommon`), so same-model phones are not merged.
- **Database read failures are no longer silent.** Reads wait for locks, and a failed read is
  shown on screen and listed at the top of the Compare report.

### Notes
- Passive by default; active techniques never run unless `activeFp=true`.
- Sequence numbers are captured and displayed but intentionally **not** auto-merged into the
  correlation engine (single-channel capture would cause false merges). See
  [docs/PAPERS.md](docs/PAPERS.md).
- Techniques requiring an SDR or specialized sniffers (BLE physical-layer fingerprinting,
  AWDL/AirDrop) are documented as out of scope for this hardware in
  [docs/PAPERS.md](docs/PAPERS.md).

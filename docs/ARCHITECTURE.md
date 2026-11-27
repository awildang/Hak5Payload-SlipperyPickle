# Architecture

This document explains how SlipperyPickle works internally: where its data comes from, the three
fingerprinting stages, and how the correlation engine decides that two observations are the same
device.

For the research behind each signal, see [PAPERS.md](PAPERS.md).

SlipperyPickle doubles as a validation bench for [AntiHunter](https://github.com/lukeswitz/AntiHunter),
the open-source ESP32-S3 perimeter-defense firmware: techniques are prototyped and tuned here against
live radio data, then a proven version is implemented in the AntiHunter software. Several design
choices below (busybox-portable, conservative correlation, passive-first) are shaped by that porting
goal — they have to survive on constrained ESP32 firmware, not just on the WiFi Pineapple.

---

## Design principles

1. **Read, don't scan.** The Pineapple already runs recon daemons that own the radios and log every
   device they see. SlipperyPickle reads their SQLite databases instead of running its own scans.
   This means zero radio contention and no extra battery/airtime cost.
2. **Identity, not MAC.** Modern phones randomize their MAC addresses. SlipperyPickle keys
   correlation on signals that *survive* randomization and only falls back to the MAC when a device
   advertises a stable one.
3. **Passive by default.** Nothing transmits to a third-party device unless `activeFp=true`.
4. **Fail honest.** When a device genuinely cannot be tracked (fully randomized and silent), it stays
   a singleton. The tool does not invent links.

---

## Data sources

| Source | Produced by | Fields used |
|--------|-------------|-------------|
| `recon.db` → `wifi_device`, `ssid` | the Wi-Fi recon daemon | MAC, RSSI, frequency, and each client's **probed-SSID list (PNL)** |
| `blue5.db` → `bt_device` | the Bluetooth recon daemon | MAC, RSSI, company ID, name, `le_random` flag, manufacturer data, service data |
| Live monitor interface | `tcpdump` (Stage 2) | raw probe-request frames → IE fingerprint + sequence number |
| `dhcp.leases` | the Pineapple's DHCP server | hostnames of devices that joined *your* access point |
| `known.txt` (loot) | **Learn known here** / you | identity tokens of your own/authorised devices, hidden from results |
| `history.txt` (loot) | written each Compare | per-token first/last-seen + session count, for cross-session memory (auto-expired after `histDays`) |

A single long-lived `awk` co-process loads the OUI vendor table into memory once and decodes both
database feeds on every pass, so the hot path never re-greps a 40k-line file per device.

**Radios & bands.** Wi-Fi (IEEE 802.11) devices are classified as **2.4 / 5 / 6 GHz** from the
frequency recon reports; **Bluetooth** — BLE advertising on 2.4 GHz (channels 37/38/39), plus BT
Classic — is tagged separately. The radar header shows the live per-band split. SlipperyPickle
covers only Wi-Fi and Bluetooth (no cellular, Zigbee, LoRa or sub-GHz) and never tunes frequencies
itself — Stage 2 aside, it reads whatever PineAP Recon captured. See the README's *Radios, bands &
protocols* table for the full breakdown.

---

## The three stages

### Stage 1 — database enrichment (passive, zero-contention)

On every snapshot, each live device is enriched with:

- **PNL / probed-SSID list** — joined from `recon.db`. The strongest passive Wi-Fi identity: a phone
  that probes an uncommon set of SSIDs is recognizable even after it rotates its MAC.
- **Randomized-address flag** — Wi-Fi locally-administered bit; Bluetooth `le_random`. Tells us
  whether the MAC is a stable identity or a throwaway.
- **Device type** — decoded from Bluetooth manufacturer/service data: Apple Continuity message types
  (Find My, Nearby, AirPods, Handoff, AirDrop, iBeacon), Samsung, Huawei, Xiaomi/Mi (MIoT),
  Google Fast Pair, etc.
- **Vendor label** — the BLE company ID (and Wi-Fi OUI) resolves to a vendor name: Apple, Samsung,
  Google, Microsoft, Huawei, Xiaomi, OnePlus, Oppo, vivo, Realme, Nubia (RedMagic), ZTE, Honor,
  Meizu, Lenovo/Motorola, Transsion (Tecno/Infinix/itel), HMD/Nokia, Nothing, LG, HTC, TCL, Alcatel,
  Fairphone, Asus, BlackBerry, and more. Most map to Android for the OS family (Jolla → Sailfish).
  This only **labels/gates** — it is never a match key (all Apple share one ID).
- **DHCP hostname** — for any device that has joined your access point.

### Stage 2 — passive 802.11 fingerprint

A background `tcpdump` on the up monitor interface captures probe-request frames. A busybox-`awk`
parser reconstructs each frame, strips the radiotap + 802.11 headers, and walks the Information
Elements to produce:

- an **IE fingerprint** — the ordered list of IE tag IDs plus the capability bytes
  (HT/VHT/HE/extended-capabilities/supported-rates/vendor). This reflects the chipset/driver/OS and
  stays constant across MAC rotation.
- the **802.11 sequence number** — a per-device counter that keeps incrementing across a MAC change.

The sniff is passive and therefore non-exclusive — it does not contend with the recon daemon. The
interface is parked on the access-point channel and does not hop, so these signals accrue
single-channel over the session.

### Stage 3 — active GATT probe (opt-in, off by default)

When `activeFp=true`, you can select one BLE device and the tool will connect to it and read its
GATT Device Information Service (name / manufacturer / model / firmware) and enumerate its primary
service UUIDs (a GATT-profile fingerprint). This is **active and intrusive**: it opens a connection
to that device, may surface a connection hint on it, and contends with the Bluetooth daemon. That is
why it stays off behind the `activeFp` switch.

## Tag tools (tracker interaction)

The **Tag tools** menu lists the tracker tags in view and offers three per-tag actions. Only the
last two are active (behind `activeFp`); the first is passive:

- **Find (proximity)** — passive. Reads the selected tag's latest RSSI from the collector's `$obs`
  feed (no connection) and renders a getting-warmer/colder meter so the tag can be walked down —
  including a tag whose speaker was physically disabled, where ringing does nothing.
- **Ring** — active. For a tag **separated from its owner**, connects and writes the non-owner
  "play sound" command so the tag chirps (the anti-stalking action AirGuard performs). AirTag:
  service `7DFC9000-…`, characteristic `7DFC9001-…`, write `0xAF` (no handshake). DULT / third-party
  Find My / Pebblebee use their non-owner characteristic via an indication handshake driven through
  `gatttool -I` — **experimental and untested** against those families. Tile / Chipolo / SmartTag
  expose no non-owner sound service and cannot be rung. Only separated tags are connectable to a
  non-owner.
- **Read info** — active. Reads GATT Device Information (manufacturer / model / firmware) and,
  experimentally, DULT non-owner accessory info (model / accessory category / battery) via the
  opcode+indication handshake on the DULT characteristic `8E0C0001-…`. The serial number is **not**
  readable by a non-owner: DULT (`Get_Identifier`, opcode `0x0404`) requires a physical ~10-second
  button hold on the tag to enter "identifier read state" and returns only an encrypted identifier.

---

## Correlation engine (the "Compare" step)

All snapshots are merged, each record tagged with its snapshot index, and fed to a `union-find`
clustering pass. Two records are unioned when they share a **strong identity token**:

| Token | Source | Strength |
|-------|--------|----------|
| hostname | DHCP | strongest (only for devices on your AP) |
| probed-SSID set | PNL rare-SSID union (probe requests only; AP beacons are excluded) | strong when rare, survives Wi-Fi MAC rotation |
| IE fingerprint | Stage 2, rare-fingerprint union | links only when shared by 2..`fpCommon` identities; a fingerprint shared by more is a common phone model, not one device |
| BLE company + advertised name | `blue5.db` | strong (requires a real name, not a generic model, to avoid merging distinct nameless devices) |
| stable MAC | Wi-Fi global bit / BT `le_random=0` | medium |

Vendor and OS family are used only to **label** a cluster and to **gate** cross-radio pairing — never
as a match key, because an identifier shared by every device of a brand would merge them all.

After clustering:

- **Tracker tags** — clusters whose Bluetooth advert decodes as a location-tracker tag (AirTag, Find My
  accessory, SmartTag, Tile, Chipolo, Pebblebee, Google Find My Device, DULT-standard tags; byte rules
  from AirGuard) and that recur in at least `matchThreshold` snapshots get their own section, tags
  reporting "separated from owner" first. Tags never enter cross-radio pairing (they have no Wi-Fi).
  Separated tags keep their address for about a day, so they recur across a session; tags near their
  owner rotate about every 15 minutes, so they mostly will not.
- **Known devices** — clusters matching any token in `known.txt` are hidden from every section
  (a count is shown). Tokens are the same per-device identifiers used for clustering, so a known
  device stays hidden even after it rotates its MAC.
- **Dwell & cross-session history** — each reported cluster carries its dwell (min first-seen to
  max last-seen across its observations) and a session count looked up from `history.txt` by token.
  After the report, the session's tokens are folded back into `history.txt` and old entries expired.
- **Recurring identities** — clusters seen in at least `matchThreshold` snapshots are reported as the
  high-confidence result (the signature of a device that keeps reappearing along your route).
- **Cross-radio candidates** — a separate, clearly-labelled low-confidence pass pairs a Wi-Fi cluster
  with a Bluetooth cluster when they are each other's tightest RSSI match across all shared snapshots
  and their OS families do not conflict. Ranked by signal tightness, capped. These are *leads*, not
  proof: RSSI alone cannot separate two devices standing together.

---

## Why sequence numbers are shown but not auto-merged

The sequence-number continuity attack (Vanhoef et al., 2016) links two MACs when one device's
counter continues across the address change. On a **multi-channel** capture this is strong. On the
WiFi Pineapple we are **single-channel**, so frames sent on other channels leave gaps in the counter we see —
and a gapped counter would cause the union-find to merge devices that are not actually the same.

Rather than risk false merges, SlipperyPickle captures the sequence number and shows it in the
device-detail view, where an operator can confirm a rotation by eye (same IE fingerprint + adjacent
sequence numbers on two MACs = one device). A safe fully-automatic use — a *sequence-consistency
veto* that only **splits** an over-merged fingerprint cluster, never creates a merge — is a planned
enhancement.

---

## File / process layout

- `payload.sh` — the entire tool (bash; the embedded `awk` programs are written out at startup).
- Background processes: the database collector co-process, the list renderer, and (Stage 2) the
  `tcpdump` fingerprint sniffer. All are cleaned up on exit.
- Working files live under `/tmp` and are removed on exit; snapshots and reports are saved under the
  loot directory for the session.

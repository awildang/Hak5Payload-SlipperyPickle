# SlipperyPickle

**Multi-protocol device-identity snapshot & correlation for the Hak5 WiFi Pineapple.**

SlipperyPickle watches the Wi-Fi and Bluetooth device identities around you, lets you snapshot 
the current set on demand, and then finds which *devices* recur across snapshots — keying on 
stable identity that survives MAC randomization, **not** on raw MAC addresses. A device that 
rotates its MAC still collapses to a single identity.

It is **passive by default**: it reads the data the Pineapple's own recon daemons already
collect and passively sniffs the air. It does not transmit to or connect to any nearby
device unless you explicitly enable active mode (see [Passive vs. active](#passive-vs-active)).
It takes up to 10 seconds to start populating identifiers.

> **Version:** `v20261126-rc2` (release candidate)

---

## Relationship to AntiHunter

SlipperyPickle is a **research and validation bench** for the open-source ESP32-S3 
perimeter-defense [AntiHunter](https://github.com/lukeswitz/AntiHunter) firmware (Wi-Fi/BLE
scanning, device fingerprinting across MAC randomization, rogue device detection, LoRa mesh).

The WiFi Pineapple is a convenient platform to prototype and measure these techniques
against live radio data before porting them to constrained ESP32 firmware. Each signal here —
PNL (probed-SSID) linking, 802.11 IE fingerprinting, BLE vendor/service decoding, cross-radio
co-presence — is a functional capability being exercised and tuned here so a proven version can
be implemented in the AntiHunter software. Findings and parameter choices from this bench feed
back into that project.

---

## Purpose & scope

SlipperyPickle is built for **research** into which identity signals survive MAC randomization, 
as groundwork for AntiHunter.

- **Passive by default.** Stages 1–2 only read databases and listen; they emit nothing.
- **Active mode is intrusive and off by default.** When enabled, Stage 3 connects to and
  transmits at a nearby device, is noticeable, may alert that device, and contends with the
  Bluetooth daemon. It stays behind the `activeFp` switch for that reason.

---

## What it does

- **Live radar** — a continuously refreshing list of nearby Wi-Fi + Bluetooth devices with signal
  strength, drawn from the Pineapple's recon databases (no extra scanning of its own).
- **Snapshot** — freezes the current set and enriches every device with stable-identity signals
  (probed-SSID lists, BLE device type, 802.11 fingerprints, …), then clears the list.
- **Compare** — correlates identities across all snapshots and flags the devices that keep
  reappearing (the same device recurring across snapshots), plus low-confidence cross-radio (Wi-Fi↔BT) pairings.
- **Tracker tags** — recognises AirTags, Find My accessories, Samsung SmartTags, Tile, Chipolo,
  Pebblebee, Google Find My Device tags and any tag using the Apple/Google tracker standard. They
  are flagged live on the radar with a **`T`** (instead of `B`) and labelled with the tag type, and
  Compare lists the ones that recur across snapshots (tags away from their owner first). Rules follow
  the AirGuard research app.
- **Tag tools** — pick a tracker in view and act on it:
  - **Find (proximity)** — *passive.* A getting-warmer/colder RSSI meter to physically walk a tag
    down; works even on a tag whose speaker has been disabled, where ringing can't help.
  - **Ring** *(active, opt-in)* — for a tag **separated from its owner** (the state a planted tag is
    in), connect and trigger its non-owner "play sound" so it chirps — the anti-stalking action the
    AirGuard app performs. AirTags are supported; DULT / third-party Find My / Pebblebee are attempted
    experimentally. (Tile, Chipolo and SmartTag expose no non-owner sound and can't be rung.)
  - **Read info** *(active, opt-in)* — reads the tag's GATT device info (and, experimentally, DULT
    accessory info). The **serial number is not obtainable** as a non-owner — DULT gates it behind a
    physical button hold and returns only an encrypted identifier.
  The active actions are intrusive and stay behind the `activeFp` switch.
- **Dwell & history** — Compare shows how long each identity was present this session (dwell) and
  how many sessions it has been seen across (cross-session memory, auto-expiring after `histDays`).
- **Known-device filtering** — mark your own/authorised devices (one menu press captures everything
  currently around you) so they are hidden from results, leaving only the unknowns.
- **Device detail** — per-device identifiers for manual analysis, including the 802.11 sequence
  number for confirming a MAC rotation by eye.

Every correlation signal is drawn from published academic research. See
**[docs/PAPERS.md](docs/PAPERS.md)** for the full table of what is implemented, what is not, and why.

---

## How it works (three stages)

| Stage | Mode | What it does |
|------:|------|--------------|
| **1** | passive, zero-contention | Reads the Pineapple's `recon.db` (Wi-Fi) and `blue5.db` (Bluetooth) and enriches each device: probed-SSID list (PNL), BLE randomized-address flag, device type decoded from manufacturer/service data, DHCP hostname. |
| **2** | passive sniff | A background `tcpdump` on the live monitor interface builds a per-MAC **802.11 Information-Element fingerprint** (stable across MAC rotation) and records the **802.11 sequence number**. |
| **3** | **active, opt-in (off by default)** | Connects to one chosen BLE device and reads its GATT Device Information + enumerates its service UUIDs (a GATT-profile fingerprint). Intrusive — see below. |

Full design details: **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)**.

---

## Radios, bands & protocols

SlipperyPickle is dual-radio. It does not tune or sweep frequencies itself — it reads whatever
**PineAP Recon** captures and classifies each device by the frequency recon reports, plus (Stage 2)
a passive monitor-mode sniff.

| Radio / protocol | Bands | What SlipperyPickle uses |
|------------------|-------|--------------------------|
| **Wi-Fi — IEEE 802.11** | 2.4 GHz, 5 GHz, 6 GHz | From `recon.db`: client MAC, RSSI, frequency/band, and **probed-SSID lists (PNL)**. Stage 2 passively sniffs **probe-request** management frames for the **802.11 Information-Element fingerprint** and **sequence number**. |
| **Bluetooth Low Energy (BLE)** | 2.4 GHz (advertising ch. 37/38/39) | From `blue5.db`: **company ID → vendor** (Apple, Samsung, Google, Microsoft, Huawei, Xiaomi, OnePlus, Oppo, vivo, Realme, Nubia/RedMagic, ZTE, Honor, Meizu, Lenovo/Motorola, Transsion, HMD/Nokia, Nothing, LG, HTC, TCL, Alcatel, Fairphone, Asus, BlackBerry, …), device name, **randomized-vs-public address** flag (`le_random`), **manufacturer-data device types** (Apple Continuity, Samsung, Huawei, Xiaomi/MIoT, Google Fast Pair) and **service UUIDs**. Stage 3 (opt-in) connects over **GATT**. |
| **Bluetooth Classic (BR/EDR)** | 2.4 GHz | From `blue5.db`: device presence, company and name as recorded by the `blue5` daemon. |

The live-radar header shows a per-band breakdown of what's currently in view (e.g. `2.4:60% 5:30%
6:0% BT:10%`). Notes:

- **Band coverage depends on the radios PineAP Recon drives.** The tool recognises and labels
  2.4 / 5 / 6 GHz Wi-Fi, but whether 5/6 GHz devices actually appear depends on the WiFi Pineapple's
  radios and firmware.
- **Stage 2 is single-channel.** The monitor interface is parked on the access-point channel and
  does not hop, so the 802.11 fingerprint/sequence-number capture accrues on one channel over time.
- SlipperyPickle **does not do cellular, Zigbee, LoRa, or sub-GHz** — only Wi-Fi and Bluetooth.

---

## Passive vs. active

A single master switch, `activeFp`, governs everything. Set it in config for the launch default,
or toggle it at runtime from the menu's **Active mode: OFF / ON** item (it asks to confirm and
applies immediately):

```sh
activeFp=false   # default: PASSIVE fingerprinting only
```

- `activeFp=false` (default): Stages 1–2 only. The tool only reads databases and passively
  listens. It does not transmit to or connect to any device. The Stage 3 probe item is hidden.
- `activeFp=true`: unlocks active techniques (today: the Stage 3 GATT probe, and Tag tools' **Ring**
  and **Read info**; the same flag gates any future active module). Active techniques connect to /
  transmit at a nearby device, may alert it, and contend with the Bluetooth daemon. (Tag tools'
  **Find** proximity meter is passive and works without active mode.)

The launch banner shows the mode you start in, and the menu's `Active mode:` item shows the
current state.

---

## Requirements

- Hak5 **WiFi Pineapple** with **PineAP Recon running** (this is what populates the Wi-Fi and
  Bluetooth databases SlipperyPickle reads).
- A monitor-mode Wi-Fi interface that is **up** (for the Stage 2 fingerprint; auto-detected).
- Standard on-device tools: `sqlite3`, `awk` (busybox), `tcpdump`, `iw`. For the optional Stage 3:
  `gatttool`. All ship on the Pineapple firmware.

No `gawk`, `python3`, `tshark`, or similar are required — everything runs in busybox + bash.

---

## Install

Copy `payload.sh` to the payload directory on the WiFi Pineapple:

```
/root/payloads/user/reconnaissance/SlipperyPickle/payload.sh
```

You can do this with the Pineapple's web UI file manager, or over SSH to the device's management
address (set your own credentials — none are shipped in this repo). Then launch it from the
payload menu on the device.

See **[docs/USAGE.md](docs/USAGE.md)** for a step-by-step guide and how to read the output.

---

## Quick usage

1. Launch the payload. It comes up **passive-only** and starts the live radar feed.
2. Walk/drive your route. Press the snapshot control at a few separated points (different places
   or times).
3. Run **Compare**. Devices seen in ≥ N snapshots are flagged as recurring identities — the
   high-confidence recurring-identity result. Cross-radio pairings are shown separately as
   low-confidence leads.
4. Use **device detail** (green on a device) to inspect one device's identifiers, including its
   probed-SSID list and 802.11 sequence number.

---

## Configuration

All knobs live at the top of `payload.sh` with inline comments. The ones you are most likely to
touch:

| Key | Default | Meaning |
|-----|---------|---------|
| `activeFp` | `false` | Master passive/active switch (see above). |
| `matchThreshold` | `2` | Flag an identity seen in ≥ this many snapshots. |
| `stale` | `120` | Seconds a device stays on the live list. |
| `pnlCommon` | `6` | A probed SSID seen for more than this many identities is treated as "public" and ignored as an identity key. |
| `fpCommon` | `4` | An 802.11 IE fingerprint shared by more than this many identities is treated as a common phone model/OS build and does not merge them. |
| `rssiTol` | `10` | dBm tolerance for cross-radio co-presence. |
| `liveIe` | `true` | Enable the Stage 2 passive 802.11 fingerprint sniff. |
| `histDays` | `14` | Cross-session history forgets an identity not seen for this many days (auto-expiry). |

The **known-devices list** and **cross-session history** persist in `loot/slipperypickle/known.txt`
and `history.txt`. Populate the known list with **Learn known here**; wipe either store with
**Clear saved data**. Neither needs a MAC typed by hand.

---

## Limitations (honest)

- **Single-channel Stage 2.** The monitor interface is parked on the access-point channel and does
  not hop, so 802.11 fingerprints and sequence numbers accrue slowly and single-channel.
- **Sequence numbers are shown, not auto-merged.** Single-channel capture leaves gaps in the
  counter, so automatic linking on sequence numbers would cause false merges. They are surfaced in
  the detail view for an operator to confirm a rotation manually.
- **Cross-radio pairing is low-confidence.** Signal strength alone cannot separate two devices
  standing next to each other; cross-radio results are ranked leads, not proof.
- **Fully randomized, silent phones can't be tracked passively** — by design. They correctly stay
  as singletons rather than being force-merged.
- **Hostname / OS-version** are not in the recon databases; they only appear for devices that join
  *your* access point (DHCP).

---

## Documentation

- **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** — data sources, the three stages, and the
  correlation engine in depth.
- **[docs/USAGE.md](docs/USAGE.md)** — install, run, and interpret the report.
- **[docs/PAPERS.md](docs/PAPERS.md)** — the research behind every signal, with a table of what is
  implemented and what is not feasible on this hardware (and why).
- **[CHANGELOG.md](CHANGELOG.md)** — version history.

---

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Bug reports, new vendor/OUI mappings, and additional
(responsibly-scoped) fingerprint signals are welcome.

## License

[MIT](LICENSE).

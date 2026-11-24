# Research & References

SlipperyPickle is built on published academic work on wireless device tracking and
anti–MAC-randomization techniques. This page maps every technique to its source paper and states
honestly which ones are **implemented**, which are **partially** used, and which are **not feasible**
on the WiFi Pineapple (and why).

The guiding principle: the WiFi Pineapple has commodity Wi-Fi/Bluetooth radios and busybox tooling — no
software-defined radio (SDR), no raw-IQ access, no specialized sniffers. Techniques that need that
hardware are documented here for completeness but are out of reach on this platform.

---

## Implemented

| # | Signal / technique | Paper | Venue / year | How SlipperyPickle uses it |
|--:|--------------------|-------|--------------|----------------------------|
| 1 | **PNL (probed-SSID) linking** | Martin et al., *A Study of MAC Address Randomization in Mobile Devices and When It Fails* | PoPETs 2017 · arXiv:1703.02874 | Stage 1. Devices probing the same *uncommon* SSID set are linked into one identity even across rotated MACs. SSIDs seen for too many devices are treated as "public" and ignored. |
| 2 | **802.11 IE fingerprint** | Vanhoef et al., *Why MAC Address Randomization is not Enough* | ACM AsiaCCS 2016 | Stage 2. Per-MAC fingerprint from the ordered Information-Element tag list + HT/VHT/HE/extended-capability/rates/vendor bytes of probe requests. Stable across MAC rotation. |
| 3 | **802.11 sequence number** | Vanhoef et al. (as above) | ACM AsiaCCS 2016 | Stage 2. The sequence counter keeps incrementing across a MAC change. Captured and shown in the device-detail view for **manual** rotation confirmation (see *Partially implemented* for why it is not auto-merged). |
| 4 | **BLE randomized-address flag / stable-MAC identity** | Becker et al., *Tracking Anonymized Bluetooth Devices* | PoPETs 2019 | Stage 1. Uses the Bluetooth daemon's `le_random` flag: address type `0` (public/static) is treated as a stable, trackable identity; `1` (rotating) is not. |
| 5 | **Apple Continuity decoding** | Martin et al., *Handoff All Your Privacy – A Review of Apple's BLE Continuity Protocol* | PoPETs 2019 (popets-2019-0057) | Stage 1. Decodes Apple Continuity manufacturer-data message types (Find My, Nearby, AirPods, Handoff, AirDrop, iBeacon…) into a device type + OS family label. |
| 6 | **Extended Continuity artifacts** | Celosia & Cunche, *Discontinued Privacy: Personal Data Leaks in Apple BLE Continuity Protocols* | PoPETs 2020 (popets-2020-0003) | Stage 1 (partial). Informs the Continuity type decoding. Counters/battery artifacts are documented as a future enrichment (see below). |
| 7 | **GATT service-UUID fingerprint** | Celosia & Cunche, *Fingerprinting BLE Devices Based on the Generic Attribute Profile* | ACM IoT S&P 2019 · DOI 10.1145/3338507.3358617 | Stage 3 (active, opt-in). Enumerates a device's primary GATT service UUIDs — a profile fingerprint that is stable across address rotation. |
| 8 | **Cross-radio Wi-Fi↔BT co-presence** | Longo, Redondi & Cesana, *Pairing Wi-Fi and Bluetooth MAC Addresses Through Passive Packet Capture* | Med-Hoc-Net 2018 · HAL hal-01832528 | Compare step. Mutual-nearest-neighbour RSSI co-presence across snapshots produces low-confidence candidate pairings of one device's two radios. |
| 9 | **Vendor / OS identification** | Bluetooth SIG Assigned Numbers; Huawei CloudCampus & HarmonyOS documentation | — | Stage 1. BLE company IDs and Wi-Fi OUIs label devices (Apple / Samsung / Google / Huawei / Xiaomi / OnePlus / Oppo / vivo / Realme / Nubia (RedMagic) / ZTE / Honor / Meizu / Lenovo-Motorola / Transsion / HMD-Nokia / Nothing / LG / HTC / TCL / Alcatel / Fairphone / Asus / BlackBerry / …). Used only to **label and gate** correlation, never as a match key (e.g. all Apple devices share one company ID). |
| 10 | **Advertisement service-UUID identification** | Zuo, Wen, Lin & Zhang, *Automatic Fingerprinting of Vulnerable BLE IoT Devices with Static UUIDs from Mobile Apps* | ACM CCS 2019 · DOI 10.1145/3319535.3354240 | Stage 1. Advertised service UUIDs identify a device type without a connection. Basis for the **Xiaomi/Mi (Mijia/MIoT)** decode: BLE company ID `0x038F` and MIoT service UUID `0xFE95`, read passively from the Bluetooth daemon's `mfr`/`svcd` fields (same path as Apple/Samsung/Huawei/FastPair). |

---

## Partially implemented / deliberately constrained

| Technique | Paper | Status & reason |
|-----------|-------|-----------------|
| **802.11 sequence-number *linking*** | Vanhoef et al., AsiaCCS 2016 | Sequence numbers are **captured and displayed**, but **not** fed into the automatic union-find. The WiFi Pineapple's monitor interface is single-channel, so frames transmitted on other channels leave gaps in the counter; auto-linking on a gapped counter would produce false merges. Left as an operator-confirmable signal. A safe automated use (a *sequence-consistency veto* that only *splits* over-merged devices, never merges) is a documented future option. |
| **BLE Continuity counters / battery** | Celosia & Cunche, PoPETs 2020 | The raw manufacturer-data blob is stored, so these fields are decodable, but they are not yet parsed into linking artifacts. Low effort, planned. |
| **BLE address carryover (fine timing)** | Becker et al., PoPETs 2019 | Not used. The Bluetooth daemon aggregates per `(scan, mac)` with no per-advertisement timestamps, and the high-volume payloads (e.g. Find My) are shared class broadcasts rather than per-device — so the fine-timing carryover attack has nothing to key on here. |

---

## Not feasible on this hardware (documented for completeness)

| Technique | Paper | Why it can't run on the WiFi Pineapple |
|-----------|-------|-------------------------------|
| **BLE physical-layer RF (CFO) fingerprint** | Givehchian et al., *Evaluating Physical-Layer BLE Location Tracking Attacks on Mobile Devices* | IEEE S&P 2022 — requires a software-defined radio and raw-IQ capture plus signal-processing expertise. The WiFi Pineapple's BLE radio does not expose the physical-layer samples this needs. |
| **802.11 scrambler-seed fingerprint** | Vanhoef et al., AsiaCCS 2016 | A physical-layer artifact not exposed in the radiotap headers available from the WiFi Pineapple's monitor interface. |
| **AWDL / AirDrop identity leaks** | Stute et al., *A Billion Open Interfaces for Eve and Mallory* | USENIX Security 2019 — requires an AWDL channel-hopping sniffer and protocol stack that the WiFi Pineapple does not provide. |
| **Inter-frame-arrival timing attack** | Matte et al., *Defeating MAC Address Randomization Through Timing Attacks* | ACM WiSec 2016 — single-channel capture undermines the timing signature, and later work shows modern devices are largely immune. Low return for a meaningful false-positive risk, so intentionally not implemented. |

---

## Related / active-fingerprinting background

These informed the design of Stage 3 and the active-mode roadmap but are not themselves implemented
as separate modules:

| Technique | Paper | Note |
|-----------|-------|------|
| **Active behavioral 802.11 fingerprinting** | Bratus, Cornelius, Kotz & Peebles, *Active Behavioral Fingerprinting of Wireless Devices* | ACM WiSec 2008 — fingerprint a device by how it responds to crafted/malformed frames. Possible via frame injection but intrusive and unreliable; a candidate future active module (would gate on `activeFp`). |
| **BTLEmap ("Nmap for BLE")** | Heinrich, Stute & Hollick | ACM WiSec 2020 (demo) — active BLE enumeration + GATT discovery; the reference design that Stage 3 mirrors. |
| **Samsung Offline Finding analysis** | Yu, Henderson, Tiu & Haines, *Privacy Analysis of Samsung's Crowd-Sourced Bluetooth Location Tracking System* | USENIX Security 2024 · arXiv:2210.14702 — Samsung's equivalent of Apple Find My; context for recognizing Samsung tracker beacons in Stage 1. |

## Probe-request fingerprinting (refinements to Stage 2)

Recent work extends the 802.11 probe-request fingerprint we use in Stage 2. We do not implement
these techniques (they need multi-channel capture and/or ML), but they bound what the IE signal can
do and their datasets explicitly include Chinese-OEM handsets (OnePlus, Oppo, Redmi, Xiaomi):

| Technique | Paper | Note |
|-----------|-------|------|
| **Compact IE fingerprints** | Pintor & Atzori, *Compact Probe Request Fingerprinting with Asymmetric Pairwise Boosting* | arXiv:2412.10548 (2024) — compresses probe-request IE fingerprints to <1% memory with comparable accuracy; dataset includes OnePlus/Oppo/Redmi/Xiaomi. |
| **Timing-based de-randomization** | *MAC Address De-Randomization using Multi-Channel Sniffers and Two-Stage Clustering* | arXiv:2408.01578 (2024) — the time-frequency pattern of probe-request emission links rotated MACs. Needs multi-channel sniffers (we are single-channel). |
| **State-transition identification** | *Effectively Identifying Wi-Fi Devices through State Transitions* | arXiv:2507.02478 (2025) — notes IE methods are weak when same-vendor devices share identical IEs and that firmware/OS updates shift fields; a caveat for our IE fingerprint. |
| **BLE re-identification** | *Learning to Link: Automatic Re-identification of BLE Devices Under MAC Address Randomisation* | arXiv:2609.26079 (2026) — ML re-id of BLE under randomization; cites a 2025 ACM TOPS allowlist side-channel attack. |

**Note on Chinese OEMs:** no brand-specific Wi-Fi/BT OS-fingerprinting paper exists — the literature
treats OnePlus / Oppo / vivo / Realme / Nubia (RedMagic) / Redmi etc. as generic Android. The
practical lever is therefore the vendor **identifiers** (row 9), not a new technique. Redmi has no
own Bluetooth SIG ID (it is Xiaomi, `0x038F`); RedMagic is Nubia (`0x08CA`).

## Defensive side (context)

| Work | Paper | Relevance |
|------|-------|-----------|
| **BLE PHY-fingerprint obfuscation** | Givehchian et al., *Practical Obfuscation of BLE Physical-Layer Fingerprints on Mobile Devices* | IEEE S&P 2024 — a firmware-only defense that rotates the physical-layer fingerprint with the MAC. If deployed on a device, it defeats the (SDR-only) PHY attack but does **not** affect the PNL / IE / GATT / sequence-number signals SlipperyPickle uses, which operate above the physical layer. |

---

*Citations are provided for identification. Consult the original papers for authoritative detail;
venue/ID strings are best-effort and should be verified against the publisher of record.*

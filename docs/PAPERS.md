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
| 11 | **Tracker-tag detection** | Heinrich, Bittner & Hollick, *AirGuard – Protecting Android Users From Stalking Attacks By Apple Find My Devices* | arXiv:2202.11813 (2022) · [code](https://github.com/seemoo-lab/AirGuard) | Stage 1 + Compare. AirGuard's byte rules classify AirTag and third-party Find My accessories (Apple `0x004C`, type `0x12`, status bits `0x30`; payload length `0x19` = **separated from owner**), Samsung SmartTag (service data `0xFD5A`, first byte `& 0xF8 == 0x10`), Tile (`0xFEED`, `02 00`), Chipolo (`0xFE33`), Pebblebee (`0xFA25`) and Google Find My Device network tags (`0xFEAA`, frame `0x40`; `0x41` = separated). Compare lists tags seen in ≥ `matchThreshold` snapshots, separated ones first — AirGuard's "same tag at several places" heuristic applied to snapshots. |
| 12 | **Standard tracker advertisement** | Ledvina et al. (Apple & Google), *Detecting Unwanted Location Trackers* | IETF DULT Internet-Draft · [draft-ledvina-apple-google-unwanted-trackers](https://datatracker.ietf.org/doc/html/draft-ledvina-apple-google-unwanted-trackers-03) | Stage 1. Any tag implementing the cross-vendor spec advertises service data `0xFCB2`; such devices are labelled `DULT-tag`. (The near-owner bit is not parsed yet.) |
| 13 | **Persistence-based tag detection** | Briggs & Geeng, *BLE-Doubt: Smartphone-Based Detection of Malicious Bluetooth Trackers* | IEEE SafeThings 2022 | Compare (concept). Flags any BLE device that persists with the user across time and place; this is what the recurring-identity and tracker sections do across snapshots. |
| 14 | **Non-owner "play sound" (ring a tag)** | AirGuard (as row 11); Roth, Freyer, Hollick & Classen, *AirTag of the Clones* (WOOT 2022); Apple/Google DULT draft (as row 12) | Stage 3 (active, opt-in). For a tracker **separated from its owner**, connects and writes the non-owner sound-trigger so a planted tag can be located. AirTag: service `7DFC9000-7D1C-4951-86AA-8D9728F8D66C`, characteristic `7DFC9001-…`, write byte `0xAF` (no handshake). This is the DULT-standard non-owner sound action AirGuard performs; the AirTag firmware specifics are analysed in *AirTag of the Clones*. Other tracker families are recognised but use a notify-handshake sound protocol not yet wired up. |

---

## Partially implemented / deliberately constrained

| Technique | Paper | Status & reason |
|-----------|-------|-----------------|
| **802.11 sequence-number *linking*** | Vanhoef et al., AsiaCCS 2016 | Sequence numbers are **captured and displayed**, but **not** fed into the automatic union-find. The WiFi Pineapple's monitor interface is single-channel, so frames transmitted on other channels leave gaps in the counter; auto-linking on a gapped counter would produce false merges. Left as an operator-confirmable signal. A safe automated use (a *sequence-consistency veto* that only *splits* over-merged devices, never merges) is a documented future option. |
| **BLE Continuity counters / battery** | Celosia & Cunche, PoPETs 2020 | The raw manufacturer-data blob is stored, so these fields are decodable, but they are not yet parsed into linking artifacts. Low effort, planned. |
| **IE fingerprint as a merge key** | Baccichet et al., arXiv:2412.10548 / 2408.01578 (2024); *StateFi*, arXiv:2507.02478 | Implemented as a **rarity rule**: these papers show identical IEs across same-model phones, so a fingerprint links identities only when shared by 2..`fpCommon` of them. Their ML / multi-channel methods are not implemented. |
| **Tracker separated-state for SmartTag / Chipolo** | AirGuard source | Separated-from-owner is decoded for Apple Find My and Google FMDN only. AirGuard reads SmartTag and Chipolo state from bit fields whose order its own code comments flag as reversed; not implemented until verified on a real tag. |
| **BLE address carryover (fine timing)** | Becker et al., PoPETs 2019 | Not used. The Bluetooth daemon aggregates per `(scan, mac)` with no per-advertisement timestamps, and the high-volume payloads (e.g. Find My) are shared class broadcasts rather than per-device — so the fine-timing carryover attack has nothing to key on here. |

---

## Not feasible on this hardware (documented for completeness)

| Technique | Paper | Why it can't run on the WiFi Pineapple |
|-----------|-------|-------------------------------|
| **BLE physical-layer RF (CFO) fingerprint** | Givehchian et al., *Evaluating Physical-Layer BLE Location Tracking Attacks on Mobile Devices* | IEEE S&P 2022 — requires a software-defined radio and raw-IQ capture plus signal-processing expertise. The WiFi Pineapple's BLE radio does not expose the physical-layer samples this needs. |
| **802.11 scrambler-seed fingerprint** | Vanhoef et al., AsiaCCS 2016 | A physical-layer artifact not exposed in the radiotap headers available from the WiFi Pineapple's monitor interface. |
| **AWDL / AirDrop identity leaks** | Stute et al., *A Billion Open Interfaces for Eve and Mallory* | USENIX Security 2019 — requires an AWDL channel-hopping sniffer and protocol stack that the WiFi Pineapple does not provide. |
| **Inter-frame-arrival timing attack** | Matte et al., *Defeating MAC Address Randomization Through Timing Attacks* | ACM WiSec 2016 — single-channel capture undermines the timing signature, and later work shows modern devices are largely immune. Low return for a meaningful false-positive risk, so intentionally not implemented. |
| **BLE allowlist side channel** | Zhang & Lin, allowlist-based side channel for BLE address tracking (ACM CCS 2022) | Active attack that spoofs a candidate central's address and watches whether the target answers. **Measured on this unit (Nov 2026):** `LE Set Random Address` (the HCI command needed to spoof the source address) returns `0x0C Command Disallowed` while blue5 is scanning. Running it would require stopping PineAP's BT scanning and seizing the controller — which removes the passive `blue5.db` feed the rest of the tool reads — and the differential response could not be validated without a bonded allowlisted target. Out of scope while the radio is shared with PineAP recon. |

---

## Related / active-fingerprinting background

These informed the design of Stage 3 and the active-mode roadmap but are not themselves implemented
as separate modules:

| Technique | Paper | Note |
|-----------|-------|------|
| **Active behavioral 802.11 fingerprinting** | Bratus, Cornelius, Kotz & Peebles, *Active Behavioral Fingerprinting of Wireless Devices* | ACM WiSec 2008 — fingerprint a device by how it responds to crafted/malformed frames. Possible via frame injection but intrusive and unreliable; a candidate future active module (would gate on `activeFp`). |
| **BTLEmap ("Nmap for BLE")** | Heinrich, Stute & Hollick | ACM WiSec 2020 (demo) — active BLE enumeration + GATT discovery; the reference design that Stage 3 mirrors. |
| **Advanced tag evasion** | *AirCatch: Effectively tracing advanced tag-based trackers* | arXiv:2602.07656 (2026) — tags that rotate or suppress adverts to evade AirGuard-style detection. Not implemented: needs per-advertisement timing the Bluetooth daemon does not keep. |
| **Tracker misuse without cooperation** | Despres, Davis, Dutta & Wagner, *DeTagTive: Linking MACs to Protect Against Malicious BLE Trackers* | ACM SNIP2+ 2023 · DOI 10.1145/3609396.3610544 — links a tag's rotating addresses passively. Not implemented: relies on fine-grained per-advert timing/RSSI that `blue5.db` aggregates away. |
| **AirTag, SmartTag and Tile protocols** | *A Tale of Three Location Trackers: AirTag, SmartTag, and Tile* (arXiv:2501.17452); *Security and Privacy Analysis of Tile's Location Tracking Protocol* (arXiv:2510.00350) | Protocol references behind the Tile `0xFEED` and SmartTag identifiers above. |
| **BLE spec traceability flaws** | Wu et al., *Finding Traceability Attacks in the Bluetooth Low Energy Specification and Its Implementations* | USENIX Security 2024 — IRK / BD_ADDR / CSRK / ID_ADDR reuse enable eight tracking attacks. Not implemented: the passive ones need pairing/bonding traffic that recon does not capture; the rest are active. |
| **Exclusive-use characteristics** | *IDBLEED* | NDSS 2025 — de-anonymizes BLE and Wi-Fi devices via exclusive-use characteristics. Reviewed from its summary only; not implemented. |
| **ML on probe IEs + timing + RSSI** | *Can Machine Learning Break Wi-Fi Privacy? A Study on MAC Address Randomization* | arXiv:2606.25788 (2026) — unsupervised clustering beats randomization. Not implemented (no ML on-device; single-channel timing); supports the IE rarity rule. |
| **Samsung Offline Finding analysis** | Yu, Henderson, Tiu & Haines, *Privacy Analysis of Samsung's Crowd-Sourced Bluetooth Location Tracking System* | USENIX Security 2024 · arXiv:2210.14702 — Samsung's equivalent of Apple Find My; context for recognizing Samsung tracker beacons in Stage 1. |

## Find My / Offline Finding — protocol security & exploits (context)

The tracker-tag detection (row 11) and the opt-in **ring-a-tag** feature (row 14) decode Apple's Find
My / Offline Finding (OF) adverts and its non-owner sound protocol. The papers below reverse-engineered
and attacked that system. They define the threat model SlipperyPickle operates in — what a tag can do
and how advert-based detection is evaded — rather than adding a passive signal of their own. (Most are
offensive/physical-access or network-abuse work, so they are context, not implemented techniques.)

| Work | Paper | Relevance |
|------|-------|-----------|
| **OF protocol reverse-engineering + OpenHaystack** | Heinrich, Stute, Kornhuber & Hollick, *Who Can Find My Devices? Security and Privacy of Apple's Crowd-Sourced Bluetooth Location Tracking System* | PoPETs 2021(3):227–245 · popets-2021-0045 · arXiv:2103.02282 · [OpenHaystack](https://github.com/seemoo-lab/openhaystack) — the first full security/privacy analysis of Offline Finding: recovered the closed OF crypto/protocol, demonstrated a **location-correlation attack** and access to **~7 days of location history** (CVE-2020-9986), and released **OpenHaystack** (build-your-own Find My accessory). Foundational work behind AirGuard (row 11) and the byte-level Find My advert this tool decodes. |
| **AirTag firmware / hardware exploit** | Roth, Freyer, Hollick & Classen, *AirTag of the Clones: Shenanigans with Liberated Item Finders* | WOOT 2022 (IEEE S&P Workshops) — voltage-fault-injects the AirTag's **nRF52832** into debug mode to dump / reflash / clone firmware ("Air Glitcher"), and documents over-the-air AirTag control including **playing sound sequences** and firmware downgrade. Physical-access attack (not a passive signal), but the firmware-level analysis behind the non-owner "play sound" path used by **ring-a-tag** (row 14). |
| **Safety-alert evasion (cloned AirTag)** | *Track You: A Deep Dive into Safety Alerts for Apple AirTags* | PoPETs 2023(4):132–148 · popets-2023-0102 (Northeastern) — a stealthy **cloned AirTag that circumvents Apple's unwanted-tracking alerts**, plus alert-timing flaws (alerts can take 8+ hours by day). Advert-level detection can be defeated by a purpose-built tag. |
| **Anti-tracking evasion + defensive relay** | Hofhammer, Antonioli & Payer, *PRIVACYSHIELD: Relaying BLE Beacons to Counter Unsolicited Tracking* (EPFL / EURECOM / EPFL) | USENIX Security 2026 (**pre-print** — cite with that caveat) — shows attackers bypass the anti-stalking measures of offline-finding networks (Apple Find My, Google Find My Device, Samsung SmartThings Find), and proposes PRIVACYSHIELD, an ESP32-based relay that masks a victim's location by relaying the unauthenticated BLE beacons elsewhere. Reinforces why advert-based detection (ours included) has fundamental limits; pairs with the AirCatch entry above. |
| **Cross-brand anti-stalking evaluation** | Turk & Hutchings, *Stop Following Me! Evaluating the Effectiveness of Anti-Stalking Features of Personal Item Tracking Devices* | arXiv:2312.07157 (submitted 12 Dec 2023) — tested anti-stalking features across five tracker brands and found them insufficient to prevent many unwanted-tracking cases. |
| **Find My as a covert channel** | *Send My* (Positive Security — Bräunlein & Euler, 2021) + the *TagComm* covert-channel work | Abuses the Find My network as a low-rate **data-exfiltration channel** (even from air-gapped hosts via OpenHaystack firmware). Out of scope: not a signal a passive BLE listener can key on. Listed for completeness. |

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

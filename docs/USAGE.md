# Usage

## Prerequisites

- A Hak5 **WiFi Pineapple** with **PineAP Recon enabled and running**. SlipperyPickle reads
  the Wi-Fi and Bluetooth databases that recon populates; with recon off, there is no data to read.
- A monitor-mode Wi-Fi interface that is **up** (for the Stage 2 802.11 fingerprint). It is
  auto-detected; if none is up, Stages 1 and the rest still work and Stage 2 is simply skipped.

## Install

Place `payload.sh` at:

```
/root/payloads/user/reconnaissance/SlipperyPickle/payload.sh
```

Options:

- **Web UI** — use the Pineapple's file manager to upload `payload.sh` into that folder.
- **SSH / SCP** — copy it to the device's management address using the credentials *you* have set on
  your unit. (No credentials or addresses are shipped in this repository.)

Then start it from the payload menu on the device.

## Modes

SlipperyPickle launches **passive-only** (`activeFp=false`). The banner on startup states the mode:

- `MODE: passive only` — reads databases and sniffs passively; does not transmit to any device.
- `MODE: ACTIVE fingerprinting ON` — only when you have set `activeFp=true` in the config.

To enable active mode, edit the config block at the top of `payload.sh` and set `activeFp=true`.

## The menu

The menu is a single scrollable list titled **Main Menu**. If the list is taller than the screen,
**scroll down** to reach the lower items.

| Item | Action |
|------|--------|
| Start scan | Open the live radar (continuously refreshing device list). |
| Take snapshot | Freeze and enrich the current device set, then clear the list. |
| Compare snapshots | Correlate identities across all snapshots and produce the report. |
| Learn known here | Add every device currently around you to the known/authorised list, so they are hidden from Compare. No MAC typing. |
| Clear saved data | Wipe the cross-session history or the known-devices list (pick which). |
| Stop & exit | Clean up and quit. |
| Active mode: OFF / ON | Toggle active (Stage 3) fingerprinting for this session. The label shows the current state; enabling it asks for confirmation. |
| Probe BT device (ACTIVE!) | *Only shown while active mode is ON* — Stage 3 GATT probe. |

In the live radar: the back control returns to the menu; the select control opens the **device
detail** view for a highlighted device.

## A typical run

1. **Launch** the payload and let the radar populate for a few seconds.
2. **Snapshot** at your current location/time.
3. **Move** — change location, or wait a meaningful interval.
4. **Snapshot** again. Repeat for several separated snapshots (more snapshots = stronger signal).
5. **Compare.** Read the report.

## Reading the report

The recurring-identities table has two extra columns: **DWELL** (how long the device was present
this session) and **HIST** (`new` = first time ever, `x2`/`x3`… = also seen in that many prior
sessions). A line near the top reports how many **known/authorised** devices were hidden. To build
that known list, stand where your own devices are and press **Learn known here**; to reset the
stored data, use **Clear saved data**.

- **Tracker tags** (first section) — location-tracker tags (AirTag, SmartTag, Tile, …) seen in at
  least `matchThreshold` snapshots. `[separated]` means the tag reports it is away from its owner; a
  separated tag that recurs across snapshots taken at different places is what tracker-detection apps
  such as AirGuard alert on. Open its device detail to watch its live signal and locate it. Tags near
  their owner (for example, other people's keys nearby) are normal.
- **Recurring identities** — the main result. Each line is a device that appeared in at least
  `matchThreshold` of your snapshots, with its best identity label (hostname, BLE name, device type,
  vendor, or a probed-SSID), its OS family, radio, and a representative MAC. A device that recurs
  across several separated snapshots is exactly what this list surfaces.
- **Cross-radio candidates** — low-confidence pairings of a Wi-Fi identity and a Bluetooth identity
  that behaved like two radios of one device (co-present at matching signal). Treat these as leads to
  investigate, not conclusions.

## The device-detail view

Select a device in the radar to see its identifiers:

- vendor / likely OS
- BLE company + name, decoded device type, and whether its address is stable or rotating
- Wi-Fi IE fingerprint
- **Wi-Fi sequence number** — if you see two different MACs with the same IE fingerprint and
  adjacent sequence numbers, that is strong manual evidence they are one device that rotated its MAC
- probed-SSID list (PNL)
- DHCP hostname (if the device is on your access point)

## Stage 3 (active) — if you enable it

With `activeFp=true`, the "Probe BT device (ACTIVE!)" menu item appears. It connects to one BLE
device you select and reads its GATT information and service UUIDs. This is intrusive: it opens a
connection to that device, may be noticeable to it, and contends with the Bluetooth daemon. That is
why it stays off behind the `activeFp` switch.

## Tuning

See the configuration table in the [README](../README.md#configuration) and the inline comments at
the top of `payload.sh`.

## Cleanup

"Stop & exit" terminates the background processes and removes the tool's temporary files. Snapshots
and the correlation report for the session are retained under the loot directory so you can review
them later.

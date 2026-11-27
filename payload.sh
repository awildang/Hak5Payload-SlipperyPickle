#!/bin/bash
# Title: SlipperyPickle
# Author: SlipperyPickle contributors
# Version: 20261126-rc2
# Category: reconnaissance/fingerprinting
# Platform: WiFi Pineapple
#
# PURPOSE
#   Watch every nearby device identity (WiFi + Bluetooth) on a live radar, snapshot
#   the current set on demand, then find which *devices* recur across snapshots -
#   keying on stable identity that survives MAC randomization, NOT on raw MACs.
#   That's how a device that rotates its MAC still collapses to one identity.
#
# RELATIONSHIP TO ANTIHUNTER
#   This is a research/validation bench for AntiHunter, the open-source ESP32-S3 perimeter-defense 
#   firmware (github.com/lukeswitz/AntiHunter). The WiFi Pineapple is a convenient place to prototype 
#   and tune these detection techniques (PNL linking, 802.11 IE fingerprint, BLE vendor/service decode, 
#   cross-radio co-presence) against live radio data before implementing a proven version in the 
#   AntiHunter software. Results and parameter choices here feed back into that project.
#
# DATA SOURCES (we READ PineAP's own daemons; the radar never runs its own scan)
#   WiFi   : recon.db  wifi_device + ssid  (pineapd --recon)   -> MAC, RSSI, freq, PNL
#   BT/BLE : blue5.db  bt_device           (blue5 daemon)      -> MAC, RSSI, company,
#            name, le_random, mfr (Apple Continuity / Samsung / Huawei / Xiaomi), svcd (service UUIDs)
#   A persistent awk coprocess loads the OUI table once and decodes both feeds into $obs.
#   Requires PineAP Recon running.
#
# IDENTITY SIGNALS used by "Compare snapshots" (strongest -> weakest, all passive):
#   - Hostname (DHCP, only devices on OUR AP)            H: token
#   - Probed-SSID list / PNL (recon.db ssid)            rare-SSID union  [Martin'17]
#   - 802.11 IE fingerprint (Stage 2, live wlan0mon)    rare-fp union    [Vanhoef'16/Martin'17]
#   - 802.11 sequence number (Stage 2, detail view)     manual rotation  [Vanhoef'16]
#   - BLE company+name / Continuity device-type         B: token         [Martin'19/Celosia'20]
#   - Stable MAC (WiFi global bit; BT le_random=0)      M: token         [Becker'19]
#   - Cross-radio WiFi<->BT co-presence + RSSI          low-conf candidates [Longo'18]
#   OS/vendor (Apple/Samsung/Huawei via company+mfr) ENRICHES labels + gates cross-radio;
#   it is never a match key (all Apple share company 76). hostname/OS-version need Tier-2.
#
# RESEARCH IMPLEMENTED (signal -> source paper)
#   PNL rare-SSID linking ........ Martin 2017, "...MAC Randomization...When it Fails" (arXiv 1703.02874)
#   802.11 IE fingerprint ........ Vanhoef 2016, "Why MAC Randomization is not Enough" (AsiaCCS) + Martin'17
#   802.11 sequence number ....... Vanhoef 2016 (AsiaCCS) - counter continues across a MAC flip;
#                                   captured in Stage 2, shown in the device detail view for MANUAL
#                                   rotation analysis (NOT auto-merged: single-channel = false-merge risk)
#   BLE le_random / stable-MAC ... Becker 2019, "Tracking Anonymized BT Devices" (PoPETs 2019)
#   Apple Continuity mfr decode .. Martin 2019, "Handoff All Your Privacy" (PoPETs 2019-0057)
#                                   + Celosia 2020, "Discontinued Privacy" (PoPETs 2020-0003)
#   GATT service-UUID fingerprint  Celosia 2019, "Fingerprinting BLE Devices...GATT Profile" (ACM IoT S&P) [Stage 3]
#   Advertisement service-UUID ID  Zuo, Wen, Lin & Zhang 2019, "Automatic Fingerprinting of
#                                   Vulnerable BLE IoT Devices with Static UUIDs from Mobile Apps"
#                                   (ACM CCS) - advertised service UUIDs identify a device; basis for
#                                   the Xiaomi MIoT UUID (0xFE95) + company (0x038F) decode in Stage 1
#   Cross-radio WiFi<->BT pairing  Longo 2018, passive co-presence (IEEE 8407082)
#   Huawei / HarmonyOS vendor IDs  Huawei CloudCampus + HarmonyOS whitepaper
#   Xiaomi / Mi (MIoT) vendor IDs  Bluetooth SIG company 0x038F + MIoT service UUID 0xFE95
#   Tracker-tag detection ........ Heinrich 2022, "AirGuard" (arXiv 2202.11813) - AirTag/FindMy/SmartTag/Tile/
#                                   Chipolo/Pebblebee/Google FMDN byte rules; Apple+Google IETF DULT
#                                   draft (service data 0xFCB2); BLE-Doubt 2022 persistence idea
#   IE fingerprint rarity rule ... Baccichet 2024 (arXiv 2412.10548/2408.01578) + StateFi 2025: same-
#                                   model phones share IEs, so a fingerprint links only when rare
#   NOT implemented (hardware limit, documented for completeness):
#     - BLE PHY-layer RF fingerprint ... Givehchian 2022 (IEEE S&P) - needs an SDR, not commodity radios
#     - AWDL / AirDrop identity leaks .. Stute 2019 (USENIX Sec) - needs an AWDL channel-hopping sniff
#     - BLE allowlist side channel ..... Zhang & Lin 2022 (CCS) - active; needs to spoof our own
#                                         BLE address, but LE Set Random Address is Command-Disallowed
#                                         while blue5 owns the radio for recon. Would require seizing
#                                         the controller from PineAP (kills the passive BT feed).
#
# THREE-STAGE IDENTITY ARCHITECTURE (strongest/safest first)
#   Each stage adds identity signal while staying as passive as the hardware allows.
#   Stages 1 and 2 run automatically and contend with nothing; stage 3 is opt-in.
#
#   STAGE 1 - DB-only, passive, zero contention  (the high-confidence core)
#     We read PineAP's own databases, never scan, so there is no radio contention
#     with pineapd or blue5. Each snapshot ENRICHES every live MAC with:
#       * PNL / probed-SSID list (recon.db ssid)  - the real anti-randomization win:
#         two devices that probe the same *uncommon* SSID set are linked even across
#         rotated MACs (Martin 2017). An SSID probed by > pnlCommon identities is
#         treated as "public" and ignored as an identity key.
#       * le_random trackability flag  - blue5's own le_random (0 = public/stable addr,
#         trackable by MAC: beacons/accessories/wearables; 1 = random/rotating). [Becker 2019]
#       * device TYPE from mfr/svcd  - Apple Continuity msg-type (0x12 FindMy, 0x10
#         Nearby, 0x07 AirPods, 0x0C Handoff, 0x05 AirDrop, 0x02 iBeacon), Samsung
#         (7500), Huawei (027D), Xiaomi/Mi (mfr 8F03 or MIoT svc UUID FE95),
#         FastPair (FE2C)... decoded to a label + OS family.
#         [Martin 2019 / Celosia 2020 reverse-engineered these Continuity message types;
#         they also carry counters/battery that could be decoded from the stored mfr blob.]
#       * DHCP hostname  - for anything that has joined OUR AP.
#     Correlation keys on hostname > PNL > IE-fingerprint > BLE name > stable MAC.
#     OS/vendor only LABEL and GATE (never match - all Apple share company 76).
#
#   STAGE 2 - passive 802.11 fingerprint  (Vanhoef 2016 / Martin 2017)
#     A background tcpdump on the live monitor iface (wlan0mon - the one that is UP,
#     reports txpower) builds a per-MAC fingerprint from the ordered IE tag list +
#     HT/VHT/HE/ext/rates/vendor capability bytes of probe-requests ($iefp). This is
#     stable across MAC rotation. It ALSO extracts the 802.11 sequence number ($seqf):
#     the counter keeps incrementing across a MAC change, so near-consecutive seqnos
#     from two different MACs = one rotating device (Vanhoef 2016). We only CAPTURE and
#     DISPLAY the seqno (device detail view) - we do NOT auto-merge on it, because the
#     iface is single-channel (frames on other channels leave gaps in the counter), so
#     an automatic seq-union would false-merge. It is an operator-confirmable signal.
#     The sniff is passive => non-exclusive => no contention with PineAP. Caveat: the
#     iface is parked on the AP channel and does NOT hop, so signal accrues single-channel.
#     Toggle: liveIe.
#
#   STAGE 3 - ACTIVE GATT "BT handshake"  (Celosia 2019) - OFF, OPT-IN
#     Manually connect to ONE chosen BLE device and read its GATT Device Information
#     Service (name/model/manufacturer/firmware) AND enumerate its primary service
#     UUIDs - the GATT-profile fingerprint that is stable across address rotation
#     (Celosia 2019). This is ACTIVE and INTRUSIVE: it connects to that device, can alert
#     it, and contends with blue5 for hci0. It is gated behind the master activeFp switch
#     (default false = passive only); the "Probe BT device" item only appears while ACTIVE
#     mode is on.
#
#   PASSIVE vs ACTIVE: the master switch is  activeFp . It defaults to false, so out of the
#   box SlipperyPickle is PASSIVE-ONLY (Stages 1-2: read DBs + sniff, never transmit). Flip it
#   two ways: edit activeFp=true in config for an active-by-default launch, OR toggle it at
#   runtime from the menu's "Active mode: OFF/ON" item (asks to confirm, effective immediately).
#   Either way it unlocks every active technique (today the Stage 3 GATT probe; future
#   LL-version/SDP/802.11 active probes gate on the same flag).
#
# CONTROLS (pop-up menu + live radar)
#   Main Menu (one scrollable list - scroll down for items below the screen):
#     Start scan | Take snapshot | Compare snapshots | Learn known here | Clear saved data |
#     Stop & exit | Active mode: OFF/ON (toggle) | Probe BT device (ACTIVE, only when active mode is on)
#   In the live radar:  RED = back to menu    GREEN = device identifiers for a picked MAC
#
# LED: Blue=idle  Amber=processing/compare  Green=ok/snapshot  Red=recurring-device hit/err
#

# ============================================================
# CONFIG
# ============================================================
version="20261126-rc2"               # shown on the radar's top line so you can see which build is live
baseDir="/root/loot/slipperypickle"
# --- Live radar (read recon.db + blue5.db) ---
liveWifi=true              # include WiFi devices from recon.db (needs PineAP Recon running)
liveBle=true               # include BT/BLE from blue5.db (PineAP's BT daemon; we never scan)
scanEvery=2                # seconds between background DB-read passes
renderEvery=2              # loop tick: how often the radar re-checks the live set (seconds)
heartbeat=4                # force a refresh at least this often even if nothing changed, so the
                           #   view keeps auto-scrolling (higher=less log growth, raise if it
                           #   ever gets sluggish over a long session; the payload log is append-only)
stale=120                   # keep a device shown for 2 min (longer than one scan pass)
maxRows=12                  # device rows shown
# --- Compare / correlation (used by "Compare snapshots") ---
matchThreshold=2           # flag identities seen in >= N snapshots
rssiTol=10                 # dBm: max signal gap to call a WiFi & BT device "co-located"
xcorrMin=2                 # min shared snapshots for a WiFi+BT pairing to be flagged
pnlCommon=6                # PNL: an SSID probed by > this many identities is "public" (not an identity key)
fpCommon=4                 # IE fingerprint: one shared by > this many identities is a common phone
                           #   model/OS build, not one device, so it does not merge them. Raise it
                           #   to link heavy MAC-rotators more; lower it to avoid merging look-alikes.
xcorrCap=8                 # max cross-radio candidate pairs reported (ranked tightest-RSSI first)
histDays=14                # cross-session history: forget an identity not seen for this many days
                           #   (auto-expiry keeps the store bounded + old bystander data from lingering)
liveIe=true                # Stage 2: passive 802.11 IE fingerprint from the live monitor iface (anti-randomization)
# --- MASTER passive/active switch ---------------------------------------------------
# activeFp=false  => PASSIVE fingerprinting ONLY (default). We only READ PineAP's DBs +
#                    passively sniff; we do not transmit to or connect to any nearby device.
# activeFp=true   => ALLOW ACTIVE fingerprinting. Unlocks every active technique (today:
#                    the Stage 3 GATT probe; any future LL-version / SDP / 802.11 active
#                    probe gates on THIS SAME flag). Active = connects to / transmits at a
#                    nearby device, is noticeable, may alert it, and contends with blue5 -
#                    which is why it is off by default.
activeFp=false             # <-- flip to true to enable ACTIVE fingerprinting (default: passive only)

# ============================================================
# ENV / PATHS
# ============================================================
sessionTs="$(date +%Y%m%d-%H%M%S)"
sessionDir="$baseDir/session_$sessionTs"
snapCount=0
mkdir -p "$sessionDir"

ouiFile="/lib/hak5/oui.txt"; [ -f "$ouiFile" ] || ouiFile="/rom/lib/hak5/oui.txt"

isRandomMac() { printf '%s' "$1" | grep -qiE '^[0-9A-F][2367ABEF]:'; }

# Read-only sqlite query: dbQuery <db> <sql>. The recon daemons write their DBs live, so a
# read can hit "database is locked" - wait up to 3 s for the lock. Returns non-zero on any
# failure (locked, damaged, timeout) so callers can WARN instead of silently using no data.
dbQuery() { timeout 10 sqlite3 -cmd ".timeout 3000" -separator '|' "$1" "$2" 2>/dev/null; }

# recon.db query with one retry. Output is buffered, so a failed attempt never leaks partial rows.
reconQuery() {
    local out
    out=$(dbQuery "$reconDb" "$1") || { sleep 1; out=$(dbQuery "$reconDb" "$1") || return 1; }
    [ -n "$out" ] && printf '%s\n' "$out"
    return 0
}

vibrate() { local n="${1:-1}" i=0; while [ "$i" -lt "$n" ]; do
    echo 1 >/sys/class/gpio/vibrator/value 2>/dev/null; sleep 0.15
    echo 0 >/sys/class/gpio/vibrator/value 2>/dev/null; sleep 0.1; i=$((i+1)); done; }

cleanup() {
    # Only tear down if WE own the lock. A second copy that refused to start must not kill the
    # running instance's tcpdump/etc or clear its state when its own EXIT trap fires.
    [ "$weOwnLock" = 1 ] || return 0
    killall tcpdump 2>/dev/null
    killall btmgmt 2>/dev/null
    killall hcitool 2>/dev/null
    killall bluetoothctl 2>/dev/null
    echo 0 >/sys/class/gpio/vibrator/value 2>/dev/null
    LED OFF
}
trap cleanup EXIT INT TERM

# RSSI (dBm) -> 10-char signal bar, like the RECON view. -30=strong .. -90=weak
makeBar() {
    local sig=$1 s r
    case "$sig" in ''|*[!0-9-]*) echo "----------"; return ;; esac
    s=$(( (sig + 90) / 6 )); [ "$s" -lt 1 ] && s=1; [ "$s" -gt 10 ] && s=10
    r=$((10 - s))
    # width 0 still prints one '0', so only emit each segment when its count > 0
    [ "$s" -gt 0 ] && printf '%0*d' "$s" 0 | tr '0' '#'
    [ "$r" -gt 0 ] && printf '%0*d' "$r" 0 | tr '0' '.'
}

# ============================================================
# LIVE RADAR  (continuous scan + auto-refreshing device list)
# ============================================================
obs="/tmp/slipperypickle_obs"        # EPOCH|MAC|RSSI|SRC|VENDOR|BLECO|BLENAME|FREQ
# Bluetooth source: PineAP's blue5 daemon owns the radio and writes decoded devices
# (mac/rssi/company/name) here. We READ it - never scan - so there is no adapter contention.
blue5Db="/mmc/root/recon/blue5.db"
[ -f "$blue5Db" ] || blue5Db="/root/recon/blue5.db"
pause="/tmp/slipperypickle_pause"
reconDb="/mmc/root/recon/recon.db"; [ -f "$reconDb" ] || reconDb="/root/recon/recon.db"  # pineapd's WiFi results
collectorAwk="/tmp/slipperypickle_collector.awk"   # OUI-resident transform (written at startup)
fpcapAwk="/tmp/slipperypickle_fp.awk"              # 802.11 IE-fingerprint parser (Stage 2)
snapAwk="/tmp/slipperypickle_snap.awk"             # snapshot enrichment merge (PNL/le_random/mfr/host/fp)
cmpAwk="/tmp/slipperypickle_cmp.awk"               # identity correlation (union-find + PNL + cross-radio)
iefp="/tmp/slipperypickle_iefp"                     # MAC|FP accumulated from the live monitor iface
seqf="/tmp/slipperypickle_seq"                      # MAC|seqno (802.11 sequence number, Stage 2 / Vanhoef'16)
leases="/tmp/dhcp.leases"                           # DHCP hostnames (devices on OUR AP only)
knownFile="$baseDir/known.txt"                      # identity tokens of YOUR own/authorized devices (persist)
histFile="$baseDir/history.txt"                     # token<TAB>firstSeen<TAB>lastSeen<TAB>sessions (persist)
lockFile="/tmp/slipperypickle.lock"                 # single-instance guard (holds our PID)
weOwnLock=""                                        # set to 1 once we acquire the lock; gates cleanup
ieIface=""                                         # chosen at startup: the monitor iface that is UP
colPid=""; renPid=""; scanloopPid=""; fpcapPid=""

# Background: feed WiFi (recon.db) + BT (blue5.db) observations into $obs.
# Both radios are read from the two recon daemons' own sqlite DBs - we never scan.
# A naive shell OUI lookup (grep a 40k-line file per device, every pass) was far too slow on
# the WiFi Pineapple CPU. Instead a single PERSISTENT awk coprocess loads the OUI table into
# memory ONCE, then transforms each pass's sqlite rows from its stdin in-memory (no per-device
# forks). We just pipe "W|time|mac|signal|freq" and "B|last_seen|mac|rssi|company|name" lines
# to it and it appends decoded rows to $obs. See $collectorAwk (written at startup).
bgCollector() {
    local now cut w b wfail=0 bfail=0
    coproc awkCo { awk -v OUIFILE="$ouiFile" -v OBS="$obs" -f "$collectorAwk"; }
    while :; do
        now=$(date +%s); cut=$((now - stale)); w=""; b=""
        # A failed read (DB locked / damaged) must not pass silently: after 5 failed passes in
        # a row, say so once on the radar. The counter resets on the next good read.
        if [ "$liveWifi" = true ]; then
            if w=$(dbQuery "$reconDb" "SELECT 'W', max(time), mac, signal, freq FROM wifi_device WHERE time>=$cut GROUP BY mac;"); then wfail=0
            else wfail=$((wfail+1)); [ "$wfail" -eq 5 ] && LOG yellow "WARNING: recon.db unreadable (locked or damaged) - WiFi list is stale."; fi
        fi
        if [ "$liveBle" = true ] && [ -f "$blue5Db" ]; then
            if b=$(dbQuery "$blue5Db" "SELECT 'B', max(last_seen), mac, rssi, company, replace(replace(replace(CAST(name AS TEXT),char(10),' '),char(13),' '),'|','/'), hex(mfr), hex(svcd), ifnull(svc16,'') FROM bt_device WHERE last_seen>=$cut GROUP BY mac;"); then bfail=0
            else bfail=$((bfail+1)); [ "$bfail" -eq 5 ] && LOG yellow "WARNING: blue5.db unreadable (locked or damaged) - Bluetooth list is stale."; fi
        fi
        {
          [ -n "$w" ] && printf '%s\n' "$w"
          [ -n "$b" ] && printf '%s\n' "$b"
          echo "FLUSH|$now"
        } >&"${awkCo[1]}"
        sleep "$scanEvery"
    done
}

# Background (Stage 2): passively sniff probe-request 802.11 Information Elements on the
# already-live monitor interface (wlan0mon) and accumulate a per-MAC IE fingerprint in $iefp.
# The fingerprint (ordered tag list + HT/VHT/HE/ext/rates/vendor cap bytes) reflects the
# chipset/driver/OS stack, so it stays constant even when the device rotates its MAC
# (Vanhoef 2016 / Martin 2017). Passive monitor capture is non-exclusive - it does NOT contend
# with pineapd. Single-channel (the iface is parked on the AP channel), so it accrues over time.
# The parser ALSO writes the 802.11 sequence number per MAC to $seqf (passed as -v SEQF): the
# counter keeps running across a MAC flip, so it corroborates a rotation for the operator in the
# device detail view (Vanhoef 2016). Not auto-merged (single-channel gaps -> false-merge risk).
bgFpcap() {
    [ "$liveIe" = true ] || return
    [ -n "$ieIface" ] || return
    command -v tcpdump >/dev/null 2>&1 || return
    tcpdump -i "$ieIface" -e -xx -s 0 -l 'type mgt subtype probe-req' 2>/dev/null \
      | awk -v SEQF="$seqf" -f "$fpcapAwk" >> "$iefp" 2>/dev/null
}

# Current live set: latest per MAC within stale secs, strongest first -> RSSI|MAC|LABEL
bandStats() {
    local now cutoff; now=$(date +%s); cutoff=$((now - stale))
    awk -F'|' -v cut="$cutoff" '$1+0 >= cut && $2!="" {print}' "$obs" \
      | sort -t'|' -k2,2 -k1,1nr \
      | awk -F'|' '!seen[$2]++ { s=$4; f=$8+0; t++; if(s=="BLE"||s=="BTC")b++; else if(f>=5925)g6++; else if(f>=5000)g5++; else g24++ } END{ if(t==0){printf "0 dev"} else {printf "%d dev  2.4:%d%% 5:%d%% 6:%d%% BT:%d%%", t, g24*100/t, g5*100/t, g6*100/t, b*100/t} }'
}

liveSnapshotRows() {
    local now cutoff; now=$(date +%s); cutoff=$((now - stale))
    # busybox-safe: filter fresh -> dedup latest-per-MAC -> sort strongest first.
    # Uses a fixed-width key so plain 'sort -r' orders numerically (busybox 'sort -n' on
    # variable-length negatives sorts lexically = jumbled).
    awk -F'|' -v cut="$cutoff" '$1+0 >= cut && $2!="" {print}' "$obs" \
      | sort -t'|' -k2,2 -k1,1nr \
      | awk -F'|' '!seen[$2]++ {
            r=$3; if(r !~ /^-[0-9]+$/) r=-120;
            k=200+r; if(k<0)k=0; if(k>200)k=200;
            lbl=$5; if($6!="")lbl=$6; if($7!="")lbl=$7; if(lbl==""||lbl=="?")lbl="Unknown";
            src=$4; if($9!=""){ src="TAG"; lbl=$9 }   # tracker tag (obs field 9) -> src TAG, label = tag type
            printf "%03d|%s|%s|%s|%s\n", k, r, $2, src, lbl }' \
      | sort -r \
      | awk -F'|' '{ print $2"|"$3"|"$4"|"$5 }'
}

# Background: redraw the list every renderEvery seconds
bgRenderer() {
    local rows sig mac src lbl bar disp tag rb sigkey lastSig="__init__" lastEmit=0 now
    while :; do
        if [ -f "$pause" ]; then sleep 0.4; continue; fi
        rows=$(liveSnapshotRows | head -n "$maxRows")
        # The payload LOG is an append-only log with NO screen-clear, and every LOG call forks
        # hak5cmd, so repainting a full frame every tick floods the log and pins the CPU (that is
        # what made it go sluggish over time). We repaint when the VISIBLE list changes OR once per
        # heartbeat (so the view keeps auto-scrolling when idle). The change-signature buckets RSSI
        # to ~10 dB (integer divide, no subprocess) so ordinary signal jitter is not a change.
        sigkey=""
        while IFS='|' read -r sig mac src lbl; do
            [ -z "$mac" ] && continue
            if [ "$sig" -gt -200 ] 2>/dev/null; then rb=$(( sig / 10 )); else rb="x"; fi
            case "$src" in WIFI*|PINEAP*) tag=W;; TAG*) tag=T;; BLE*|BTC*) tag=B;; *) tag="?";; esac
            sigkey="$sigkey$rb$tag${mac: -8}${lbl:0:10};"
        done <<RENDEREOF
$rows
RENDEREOF
        now=$(date +%s)
        if [ "$sigkey" = "$lastSig" ] && [ $(( now - lastEmit )) -lt "$heartbeat" ]; then
            sleep "$renderEvery"; continue
        fi
        lastSig="$sigkey"; lastEmit="$now"
        # Emit one compact frame: header (delimits frames) + rows, NO blank-line padding
        # (padding only adds lines to an append-only log, it clears nothing).
        LOG cyan "v$version $(bandStats)"
        while IFS='|' read -r sig mac src lbl; do
            [ -z "$mac" ] && continue
            if [ "$sig" -gt -200 ] 2>/dev/null; then bar=$(makeBar "$sig"); disp="$sig"; else bar="----------"; disp="--"; fi
            case "$src" in WIFI*|PINEAP*) tag=W;; TAG*) tag=T;; BLE*|BTC*) tag=B;; *) tag="?";; esac
            LOG "$(printf '%4s %s %s %s %s' "$disp" "$bar" "$tag" "${mac: -8}" "${lbl:0:10}")"
        done <<RENDEREOF2
$rows
RENDEREOF2
        sleep "$renderEvery"
    done
}

# GREEN: save current live set as an ENRICHED snapshot, then wipe the list.
# Record = SRC|MAC|RND|VENDOR|FP|PROBES|BLECO|BLENAME|MODEL|HOST|OS|RSSI|AP|FIRSTSEEN|LASTSEEN
# Enrichment (all best-effort, snapshot-time only - never in the hot radar loop):
#   PROBES = probed-SSID set (PNL) joined from recon.db  -> survives WiFi MAC rotation
#   RND    = randomized? (WiFi: locally-administered bit; BT: blue5 le_random flag)
#   MODEL  = device type decoded from blue5 mfr/svcd (Apple Continuity type, FastPair, ...)
#   HOST   = DHCP hostname (only devices on OUR AP)
#   FP     = 802.11 IE fingerprint from $iefp (WiFi, Stage 2)
# Build enriched records for the current live set into $1. Sets GLOBAL `warn` to any enrichment
# reads that failed. Shared by snapshotAndClear and learnKnown (does not clear obs or snapCount).
buildRecords() {
    local out="$1" now cutoff base pnl bt lease ie
    now=$(date +%s); cutoff=$((now - stale)); warn=""
    base="/tmp/sp_b.$$"; pnl="/tmp/sp_p.$$"; bt="/tmp/sp_t.$$"; lease="/tmp/sp_l.$$"; ie="/tmp/sp_i.$$"
    : > "$pnl"; : > "$bt"; : > "$lease"; : > "$ie"
    # base: live set per mac -> tagged "D". Keeps the strongest-RSSI row's fields, and also the
    # first/last observation epoch per mac (obs field 1) so Compare can compute dwell time.
    awk -F'|' -v cut="$cutoff" '$1+0>=cut && $2!="" {
        e=$1+0; m=$2; r=$3+0
        if(!(m in f) || e<f[m]) f[m]=e
        if(!(m in l) || e>l[m]) l[m]=e
        if(!(m in rs) || r>rs[m]){ rs[m]=r; src[m]=$4; ven[m]=$5; co[m]=$6; nm[m]=$7 }
      } END{ for(m in rs){ k=toupper(m); gsub(/:/,"",k)
        print "D\t" k "\t" src[m] "\t" m "\t" rs[m] "\t" ven[m] "\t" co[m] "\t" nm[m] "\t" f[m] "\t" l[m] } }' "$obs" > "$base"
    # PNL (probed-SSID set per client MAC) and the AP list, from recon.db.
    # ssid.type: 4/5 = probe request (a client asking for a network), 8 = beacon (an AP
    # announcing its own). Only PROBES are a PNL - counting beacons made every AP look like a
    # client "probing" its own SSID and merged same-SSID APs (mesh / guest nets) into one device.
    # A MAC that beacons is emitted as "A" (access point) so Compare can label it and keep it
    # out of the WiFi<->BT pairing. The AP list reads ssid.bssid directly (no join).
    # Each enrichment read can fail (DB locked / damaged). A failure is recorded in $warn, shown
    # on screen and written to warnings.txt so the Compare report can say what was missing.
    local q
    if [ "$liveWifi" = true ]; then
        if q=$(reconQuery "SELECT upper(w.mac), replace(group_concat(DISTINCT CAST(s.ssid AS TEXT)),'|','/') FROM ssid s CROSS JOIN wifi_device w ON s.wifi_device=w.hash WHERE s.type IN (4,5) AND CAST(s.ssid AS TEXT)<>'' GROUP BY w.mac;"); then
            printf '%s\n' "$q" | awk -F'|' '{k=toupper($1); gsub(/:/,"",k); g=$2; gsub(/,/,";",g); if(g!="") print "P\t" k "\t" g}' > "$pnl"
        else warn="$warn probed-SSID lists;"; fi
        if q=$(reconQuery "SELECT DISTINCT upper(replace(bssid,':','')) FROM ssid WHERE type=8 AND bssid IS NOT NULL AND bssid<>'';"); then
            printf '%s\n' "$q" | awk '$1!=""{print "A\t" $1}' >> "$pnl"
        else warn="$warn access-point flags;"; fi
    fi
    # BT enrich (le_random + raw mfr/svcd) from blue5.db
    if [ "$liveBle" = true ] && [ -f "$blue5Db" ]; then
        if q=$(dbQuery "$blue5Db" "SELECT upper(mac), max(le_random), hex(mfr), hex(svcd), ifnull(svc16,'') FROM bt_device WHERE last_seen>=$cutoff GROUP BY mac;"); then
            printf '%s\n' "$q" | awk -F'|' '{k=$1; gsub(/:/,"",k); if(k!="") print "B\t" toupper(k) "\t" $2 "\t" $3 "\t" $4 "\t" $5}' > "$bt"
        else warn="$warn Bluetooth device types;"; fi
    fi
    # DHCP hostnames (devices that joined our AP)
    [ -f "$leases" ] && awk '{m=$2; gsub(/:/,"",m); h=$4; if(h=="*")h=""; if(m!="")print "H\t" toupper(m) "\t" h}' "$leases" > "$lease"
    # IE fingerprints (dedup latest per mac)
    [ -f "$iefp" ] && awk -F'|' '{fp[$1]=$2} END{for(m in fp) print "F\t" m "\t" fp[m]}' "$iefp" > "$ie"
    # merge: maps first (fill arrays), then "D" rows emit the full record
    cat "$pnl" "$bt" "$lease" "$ie" "$base" | awk -f "$snapAwk" > "$out"
    rm -f "$base" "$pnl" "$bt" "$lease" "$ie"
}

snapshotAndClear() {
    snapCount=$((snapCount+1))
    out=$(printf '%s/snap_%02d.raw' "$sessionDir" "$snapCount")
    buildRecords "$out"
    local c; c=$(wc -l < "$out")
    : > "$obs"
    LED GREEN; vibrate 1
    LOG green ">>> Snapshot #$snapCount saved ($c devices). List cleared."
    if [ -n "$warn" ]; then
        echo "Snapshot #$snapCount is missing:$warn (database locked or damaged at the time)" >> "$sessionDir/warnings.txt"
        LOG yellow "WARNING: snapshot #$snapCount is missing:$warn"
    fi
}

# Add every currently-present device's strong identity tokens (hostname / BLE name / stable MAC)
# to the known-devices file so they are hidden from Compare. Pointer-driven - no MAC typing - and
# does NOT take a snapshot or clear the live list. Token format matches the correlation engine.
learnKnown() {
    LED AMBER; LOG blue "Learning current devices as known/authorized..."
    local tmp="/tmp/sp_learn.$$" before after
    before=$([ -f "$knownFile" ] && wc -l < "$knownFile" || echo 0)
    buildRecords "$tmp"
    awk -F'|' '{ mac=$2; rnd=$3; bleco=$7; blen=$8; host=$10
        if(host!="" && host!="*") print "H:" tolower(host)
        if(bleco!="" && blen!="")  print "B:" bleco ":" tolower(blen)
        if(mac!="" && rnd=="0")     print "M:" mac }' "$tmp" >> "$knownFile" 2>/dev/null
    rm -f "$tmp"
    [ -f "$knownFile" ] && sort -u "$knownFile" -o "$knownFile" 2>/dev/null
    after=$(wc -l < "$knownFile" 2>/dev/null)
    LED GREEN; vibrate 1
    PROMPT "Known devices: ${before:-0} -> ${after:-0} identities.
They are now hidden from Compare results.
(Only devices with a stable identity - hostname, BLE name, or non-random MAC - can be learned.)"
}

# Clear persistent data (pointer-driven, with confirm). Covers both the cross-session history
# and the known-devices list - this is how you reset the stored data without a keyboard.
clearHistory() {
    local c
    c=$(LIST_PICKER "Clear saved data?" "Cross-session history" "Known-devices list" "Cancel" "Cancel")
    case "$c" in
        "Cross-session history") rm -f "$histFile"; LOG green "Cross-session history cleared." ;;
        "Known-devices list")    rm -f "$knownFile"; LOG green "Known-devices list cleared." ;;
        *)                       LOG green "Nothing cleared." ;;
    esac
}

doCompare() {
    if [ "$snapCount" -lt 2 ]; then
        LED RED; ERROR_DIALOG "Need >=2 snapshots (have $snapCount). Move, press GREEN again."
        sleep 1; LED BLUE; return
    fi
    LED AMBER; LOG blue "Correlating identities across $snapCount snapshots..."
    local report="$sessionDir/identities_$(date +%H%M%S).txt"

    # Merge all snapshots, tag each record with its snapshot index.
    local master="/tmp/slipperypickle_master.$$"; : >"$master"
    local f idx
    for f in "$sessionDir"/snap_*.raw; do
        idx=$(basename "$f" | grep -oE '[0-9]+')
        sed "s/^/${idx}|/" "$f" >> "$master"
    done

    # Correlation runs in $cmpAwk (written at startup). Union-find over STRONG identity
    # tokens that survive MAC rotation: H:hostname  B:company:name
    # M:stable-MAC (WiFi global bit / BT le_random=0), plus two RARE-value unions: devices
    # that probe the same uncommon SSID set (PNL, Martin 2017) or share an uncommon IE
    # fingerprint are linked even across rotated MACs. Then a mutual-nearest-neighbour
    # cross-radio pass (Longo 2018) that skips access points. See $cmpAwk.
    awk -F'|' -v TH="$matchThreshold" -v NS="$snapCount" -v TOL="$rssiTol" \
        -v XMIN="$xcorrMin" -v CMN="$pnlCommon" -v FCM="$fpCommon" -v XCAP="$xcorrCap" \
        -v KNOWN="$knownFile" -v HIST="$histFile" -v NOW="$(date +%s)" \
        -f "$cmpAwk" "$master" > "${master}.out"

    local flagged xcount tcount tsep kcount TAB; TAB=$(printf '\t')
    flagged=$(grep -m1 '^FLAGGED' "${master}.out" | awk '{print $2}')
    xcount=$(grep -m1 '^CROSS' "${master}.out" | awk '{print $2}')
    tcount=$(grep -m1 '^TRACKERS' "${master}.out" | awk '{print $2}')
    tsep=$(grep -m1 '^TRACKERS' "${master}.out" | awk '{print $3}')
    kcount=$(grep -m1 '^KNOWN' "${master}.out" | awk '{print $2}')
    {
        echo "=== SlipperyPickle identity correlation ==="
        echo "Session   : $sessionDir"
        echo "Date      : $(date)"
        echo "Snapshots : $snapCount   Thresh: $matchThreshold   RSSI tol: ${rssiTol}dBm"
        if [ -s "$sessionDir/warnings.txt" ]; then
            echo
            echo "!! INCOMPLETE DATA - some links may be missing:"
            sed 's/^/   /' "$sessionDir/warnings.txt"
        fi
        [ "${kcount:-0}" -gt 0 ] && echo "Known/authorized devices hidden: $kcount  (add: 'Learn known here'; reset: 'Clear saved data')"
        echo
        echo "-- Tracker tags seen in >= $matchThreshold snapshots (AirTag/SmartTag/Tile/...) --"
        if [ "${tcount:-0}" -gt 0 ]; then
            printf '%-7s %-28s %s\n' "SEEN" "TAG" "MAC"
            echo "---------------------------------------------------------------------"
            grep '^t' "${master}.out" | cut -f2- | while IFS="$TAB" read -r sn tg mc; do
                printf '%-7s %-28s %s\n' "$sn" "$tg" "$mc"
            done
            echo "[separated] = the tag reports it is away from its owner. A separated tag that"
            echo "recurs across snapshots taken at different places is what AirGuard flags as"
            echo "an unwanted tracker. The device-detail view shows its live signal to locate it."
        else
            echo "(none)"
        fi
        echo
        echo "-- Recurring identities (same radio, >= $matchThreshold snaps) --"
        echo "   DWELL = time present this session; HIST = sessions seen (x2 = also a prior run)"
        printf '%-6s %-20s %-6s %-4s %-6s %-4s %s\n' "SEEN" "IDENTITY" "OS" "RAD" "DWELL" "HIST" "MAC"
        echo "---------------------------------------------------------------------"
        grep '^f' "${master}.out" | cut -f2- | while IFS="$TAB" read -r sn lbl os rd mc dw ss; do
            if [ "${dw:-0}" -lt 60 ] 2>/dev/null; then dwm="<1m"; else dwm="$(( dw / 60 ))m"; fi
            if [ "${ss:-1}" -gt 1 ] 2>/dev/null; then hist="x$ss"; else hist="new"; fi
            printf '%-6s %-20s %-6s %-4s %-6s %-4s %s\n' "$sn" "${lbl:0:20}" "${os:0:6}" "$rd" "$dwm" "$hist" "$mc"
        done
        echo
        echo "-- Cross-radio candidates (WiFi+BT co-present - LOW confidence) --"
        if [ "${xcount:-0}" -gt 0 ]; then
            printf '%-7s %-5s %-18s %-18s %s\n' "CO-SEEN" "~dB" "WiFi-id" "BT-id" "MAC w / b"
            echo "---------------------------------------------------------------------"
            grep '^x' "${master}.out" | cut -f2- | while IFS="$TAB" read -r sn dl wl bl wm bm; do
                printf '%-7s %-5s %-18s %-18s %s / %s\n' "$sn" "$dl" "${wl:0:18}" "${bl:0:18}" "$wm" "$bm"
            done
        else
            echo "(none - no WiFi/BT pair was a mutual RSSI match in >= $xcorrMin snaps)"
        fi
        echo
        echo "NOTE: cross-radio links a WiFi and a Bluetooth identity co-present across"
        echo "      snapshots at near-equal signal - the two radios of ONE device under MAC"
        echo "      randomization (passive co-presence, Longo 2018). These are RANKED"
        echo "      CANDIDATES (mutual nearest-neighbour, tightest |dRSSI| first): RSSI alone"
        echo "      cannot separate two devices standing together, so treat as leads, not"
        echo "      proof. Strongest when the BT side has a stable MAC (le_random=0): watch /"
        echo "      earbuds / tracker / car. The recurring-identity list above (PNL / IE-FP /"
        echo "      stable MAC) is the high-confidence result."
    } > "$report"

    # Fold this session's identity tokens into the cross-session history store, then expire
    # anything not seen in histDays. Store line = token<TAB>firstSeen<TAB>lastSeen<TAB>sessions.
    awk -F'\t' '$1=="k"{print $2}' "${master}.out" | sort -u > "${master}.tok"
    # Read the existing history in BEGIN (robust to an empty/missing file - the FNR==NR idiom
    # breaks when the first file is empty), fold in this session's tokens, expire old entries.
    awk -v NOW="$(date +%s)" -v DAYS="$histDays" -v HF="$histFile" '
        BEGIN{ while((getline L < HF)>0){ n=split(L,A,"\t"); if(n>=4 && A[1]!=""){
                 f[A[1]]=A[2]; l[A[1]]=A[3]; s[A[1]]=A[4] } } close(HF) }
        { t=$0; if(t==""){next} if(t in f){ l[t]=NOW; s[t]=s[t]+1 }
          else { f[t]=NOW; l[t]=NOW; s[t]=1 } }
        END{ cut=NOW-DAYS*86400
          for(t in f){ if(l[t]+0>=cut) printf "%s\t%s\t%s\t%s\n", t, f[t], l[t], s[t] } }
    ' "${master}.tok" > "${histFile}.new" 2>/dev/null && mv "${histFile}.new" "$histFile"
    rm -f "$master" "${master}.out" "${master}.tok"

    if [ "${tsep:-0}" -gt 0 ]; then
        LED RED; vibrate 3
        ALERT "SlipperyPickle: $tsep tracker tag(s) away from owner, recurring" "$(head -n 30 "$report")"
    elif [ "${tcount:-0}" -gt 0 ]; then
        LED RED; vibrate 2
        ALERT "SlipperyPickle: $tcount tracker tag(s) recurring" "$(head -n 30 "$report")"
    elif [ -n "$flagged" ] && [ "$flagged" -gt 0 ]; then
        LED RED; vibrate 2
        ALERT "SlipperyPickle: $flagged recurring device(s)${xcount:+  (+$xcount x-radio cand.)}" "$(head -n 30 "$report")"
    elif [ "${xcount:-0}" -gt 0 ]; then
        LED AMBER; vibrate 1
        ALERT "SlipperyPickle: $xcount cross-radio candidate(s)" "$(head -n 30 "$report")"
    else
        LED GREEN; vibrate 1
        ALERT "SlipperyPickle" "Nothing recurred across $matchThreshold+ of $snapCount snapshots.
$report"
    fi
    LOG green "Report: $report"
    PROMPT "$(cat "$report")"
    sleep 1; LED BLUE
}

# ============================================================
# DEVICE IDENTIFIERS (GREEN from radar)
# ============================================================
# Detail for one MAC, read from the live observation buffer ($obs:
#   EPOCH|MAC|RSSI|SRC|VENDOR|BLECO|BLENAME)
showDeviceDetailLive() {
    local mac="$1" rnd info wifiExtra chunk pkts freq band ssids
    local nkey pnl2 fp2 seq2 host2 btrow lerand2 dtype2 xtra
    nkey=$(printf '%s' "$mac" | tr -d ':' | tr 'a-f' 'A-F')
    if isRandomMac "$mac"; then rnd="randomized/private"; else rnd="global (real)"; fi
    info=$(awk -F'|' -v M="$mac" '
        $2==M {
            if($5!=""&&$5!="?")ven=$5;
            if($6!="")bleco=$6; if($7!="")blen=$7;
            if($3!=""&&$3!="-99"&&$3!="")rssi=$3;
            if(index(src,$4)==0) src=src (src==""?"":"+") $4;
        }
        END{
            guess="";
            if(bleco=="Apple"  || ven ~ /Apple/)              guess="Apple / iOS-macOS";
            if(bleco=="Huawei" || ven ~ /[Hh]uawei|HONOR/)    guess="Huawei / HarmonyOS";
            if(bleco=="Samsung"|| ven ~ /Samsung/)            guess="Samsung / Android";
            if(bleco=="Google" || ven ~ /Google/)             guess="Google / Android";
            if(bleco ~ /Xiaomi/|| ven ~ /Xiaomi|Mijia|Huami|Amazfit/) guess="Xiaomi / Android";
            if(bleco ~ /OnePlus|Oppo|Vivo|Realme|Nubia|ZTE|Honor|Meizu|Lenovo|Motorola|Transsion/) guess=bleco " / Android";
            else if(bleco ~ /Nothing|Nokia|LG|HTC|TCL|Alcatel|Fairphone|Asus|BlackBerry|Vertu|Yota|Gigaset/) guess=bleco " / Android";
            else if(bleco ~ /Jolla/) guess="Jolla / Sailfish";
            else if(ven ~ /OnePlus|Oppo|Vivo|Realme|Nubia|ZTE|HONOR|Meizu|Lenovo|Motorola|Nothing|Fairphone|Alcatel|BlackBerry|Gigaset|Vertu|Asustek|HTC|TCL/) guess="Android (OEM)";
            if(ven!="")   printf "Vendor: %s\n", ven;
            if(guess!="") printf "Likely: %s\n", guess;
            if(bleco!=""||blen!="") printf "BLE: %s %s\n", bleco, blen;
            if(rssi!="")  printf "Signal: %s dBm\n", rssi;
            if(src!="")   printf "Seen via: %s\n", src;
        }' "$obs")
    # --- identity enrichment for this one MAC (best-effort, read-only) ---
    # Probed-SSID list (PNL) - the anti-randomization WiFi identity
    pnl2=$(reconQuery "SELECT group_concat(DISTINCT CAST(ssid AS TEXT)) FROM ssid WHERE type IN (4,5) AND CAST(ssid AS TEXT)<>'' AND wifi_device IN (SELECT hash FROM wifi_device NOT INDEXED WHERE upper(replace(mac,':',''))='$nkey');")
    # BT: le_random (trackable?) + device type from Continuity/service data
    btrow=$(dbQuery "$blue5Db" "SELECT max(le_random), upper(hex(mfr)), upper(hex(svcd)), ifnull(svc16,'') FROM bt_device WHERE upper(replace(mac,':',''))='$nkey' ORDER BY last_seen DESC LIMIT 1;")
    if [ -n "$btrow" ]; then
        lerand2=$(printf '%s' "$btrow" | cut -d'|' -f1)
        # same decoder as the snapshot (incl. tracker tags): feed one B + one D row to $snapAwk
        # and take the MODEL field (9) of the record it prints
        dtype2=$(printf '%s' "$btrow" | awk -F'|' -v K="$nkey" '{print "B\t" K "\t" $1 "\t" $2 "\t" $3 "\t" $4; print "D\t" K "\tBLE\t" K "\t\t\t\t"}' \
                 | awk -f "$snapAwk" | cut -d'|' -f9)
        case "$dtype2" in *separated*) dtype2="$dtype2  << tracker tag, away from its owner";; esac
    fi
    # 802.11 IE fingerprint (stable across MAC rotation)
    [ -f "$iefp" ] && fp2=$(grep -i "^$nkey|" "$iefp" 2>/dev/null | tail -1 | cut -d'|' -f2)
    # 802.11 sequence number (Vanhoef'16): continuity across MACs confirms a rotation by hand
    [ -f "$seqf" ] && seq2=$(grep -i "^$nkey|" "$seqf" 2>/dev/null | tail -1 | cut -d'|' -f2)
    # DHCP hostname (only if on our AP)
    [ -f "$leases" ] && host2=$(awk -v M="$nkey" '{m=$2;gsub(/:/,"",m); if(toupper(m)==M && $4!="*" && $4!="")print $4}' "$leases" 2>/dev/null | tail -1)
    xtra=""
    [ -n "$dtype2" ]  && xtra="$xtra
Type: $dtype2"
    [ "$lerand2" = "0" ] && xtra="$xtra
BT-addr: PUBLIC (stable - trackable)"
    [ "$lerand2" = "1" ] && xtra="$xtra
BT-addr: random (rotates)"
    [ -n "$host2" ]   && xtra="$xtra
Hostname: $host2"
    [ -n "$fp2" ]     && xtra="$xtra
WiFi-FP: ${fp2:0:46}"
    [ -n "$seq2" ]    && xtra="$xtra
WiFi-seq: $seq2 (802.11 seqno; adjacent seq on another MAC = same device)"
    [ -n "$pnl2" ]    && xtra="$xtra
Probed(PNL): $pnl2"
    # Live Wi-Fi recon detail for this MAC: band, packets, probed SSIDs
    chunk=$(_pineap RECON CLIENTS limit=200 format=json 2>/dev/null | sed 's/{"freq":/\
{"freq":/g' | grep -i "$mac")
    if [ -n "$chunk" ]; then
        pkts=$(printf '%s' "$chunk" | grep -oE '"packets":[0-9]+' | head -1 | sed 's/.*://')
        freq=$(printf '%s' "$chunk" | grep -oE '"freq":[0-9]+' | head -1 | sed 's/.*://')
        ssids=$(printf '%s' "$chunk" | grep -oE '"ssid":"[^"]+"' | sed 's/.*"ssid":"//;s/"$//' | sort -u | tr '
' ' ')
        band="2.4GHz"
        [ "${freq:-0}" -ge 5000 ] 2>/dev/null && band="5GHz"
        [ "${freq:-0}" -ge 5925 ] 2>/dev/null && band="6GHz"
        [ -n "$freq" ] && wifiExtra="$wifiExtra
Band: $band"
        [ -n "$pkts" ] && wifiExtra="$wifiExtra
Packets: $pkts"
        [ -n "$ssids" ] && wifiExtra="$wifiExtra
Probed: $ssids"
    fi
    PROMPT "== Device identifiers ==
MAC: $mac
($rnd)
$info$xtra$wifiExtra"
}

# Device picker (pop-up list). GREEN opens identifiers, RED backs out.
deviceBrowser() {
    local rows=() macs=() sig mac src lbl pick tag i selMac
    while IFS='|' read -r sig mac src lbl; do
        [ -z "$mac" ] && continue
        [ "$sig" -gt -200 ] 2>/dev/null || sig="--"
        case "$src" in WIFI*|PINEAP*) tag=W;; TAG*) tag=T;; BLE*|BTC*) tag=B;; *) tag="?";; esac
        macs+=("$mac")                          # keep full MAC for the detail lookup
        rows+=("$(printf '%4s %s %s %s' "$sig" "$tag" "${mac: -8}" "${lbl:0:12}")")
    done < <(liveSnapshotRows)
    if [ ${#rows[@]} -eq 0 ]; then PROMPT "No devices seen yet.
Let it scan a few seconds, then try again."; return; fi
    while true; do
        pick=$(LIST_PICKER "Devices (GREEN=view RED=back)" "${rows[@]}" "${rows[0]}") || return
        # map the chosen compact row back to its full MAC
        selMac=""; i=0
        while [ $i -lt ${#rows[@]} ]; do
            [ "${rows[$i]}" = "$pick" ] && { selMac="${macs[$i]}"; break; }
            i=$((i+1))
        done
        [ -n "$selMac" ] && showDeviceDetailLive "$selMac"
    done
}

# ============================================================
# LIVE RADAR mode:  RED = menu,  GREEN = device identifiers
# ============================================================
radar() {
    rm -f "$pause"
    bgRenderer & renPid=$!
    local btn
    while true; do
        btn=$(WAIT_FOR_INPUT)
        case "$btn" in
            B|BACK)              # RED -> back to menu (scanning keeps running)
                kill "$renPid" 2>/dev/null; renPid=""; touch "$pause"; return ;;
            A|RIGHT)             # GREEN -> view device identifiers, then resume radar
                kill "$renPid" 2>/dev/null; renPid=""; touch "$pause"
                deviceBrowser
                rm -f "$pause"; bgRenderer & renPid=$! ;;
        esac
    done
}

# ============================================================
# STAGE 3 (ACTIVE / INTRUSIVE, opt-in) - GATT model read
# ============================================================
# Connect to ONE chosen BLE device and read its GATT Device Information Service
# (manufacturer / model / firmware) AND enumerate its primary service
# UUIDs - the GATT-profile fingerprint that is stable across BLE address rotation
# (Celosia 2019, "Fingerprinting BLE Devices Based on the GATT Profile"). This is NOT
# passive: it opens a connection to a nearby device, contends with blue5 for hci0,
# and may surface a connection hint on that device. Experimental, UNTESTED against
# third parties, and only reachable when the master activeFp=true. Default off (passive only).
gattRead() {  # mac uuid16 -> ascii value (hex->printable via busybox-safe lookup)
    timeout 8 gatttool -b "$1" --char-read -u "0x$2" 2>/dev/null \
      | sed -n 's/.*value: *//p' | head -1 \
      | awk 'function hx(c){return index("0123456789abcdef",tolower(c))-1}
             {v=""; for(i=1;i<=NF;i++){c=hx(substr($i,1,1))*16+hx(substr($i,2,1)); if(c>=32&&c<127)v=v sprintf("%c",c)} print v}'
}
gattServices() {  # mac -> space-joined primary service UUIDs (GATT fingerprint, Celosia 2019)
    timeout 10 gatttool -b "$1" --primary 2>/dev/null \
      | sed -n 's/.*uuid: *//p' | tr 'A-F' 'a-f' | tr '\n' ' '
}
gattProbe() {
    [ "$activeFp" = true ] || { PROMPT "ACTIVE fingerprinting is OFF (passive-only mode).
Set activeFp=true in config to enable.
(ACTIVE: connects to that device, may alert it, contends with blue5.)"; return; }
    command -v gatttool >/dev/null 2>&1 || { PROMPT "gatttool not present."; return; }
    local rows=() macs=() sig mac src lbl pick i selMac name man mod fw svc
    while IFS='|' read -r sig mac src lbl; do
        case "$src" in BLE*|BTC*|TAG*) ;; *) continue;; esac
        [ -z "$mac" ] && continue
        macs+=("$mac"); rows+=("$(printf '%4s B %s %s' "$sig" "${mac: -8}" "${lbl:0:12}")")
    done < <(liveSnapshotRows)
    [ ${#rows[@]} -eq 0 ] && { PROMPT "No BLE devices in view."; return; }
    pick=$(LIST_PICKER "ACTIVE probe - CONNECTS. GREEN=go RED=back" "${rows[@]}" "${rows[0]}") || return
    selMac=""; i=0; while [ $i -lt ${#rows[@]} ]; do [ "${rows[$i]}" = "$pick" ] && { selMac="${macs[$i]}"; break; }; i=$((i+1)); done
    [ -n "$selMac" ] || return
    LED AMBER; LOG yellow "ACTIVE: connecting $selMac (intrusive)..."
    name=$(gattRead "$selMac" 2a00); man=$(gattRead "$selMac" 2a29)
    mod=$(gattRead "$selMac" 2a24);  fw=$(gattRead "$selMac" 2a26)
    svc=$(gattServices "$selMac")
    PROMPT "== GATT probe $selMac ==
Name: ${name:-?}
Manufacturer: ${man:-?}
Model: ${mod:-?}
Firmware: ${fw:-?}
Services(GATT-fp): ${svc:-?}
(blank = refused connection / not readable)"
    LED BLUE
}

# ============================================================
# STAGE 3 (ACTIVE / INTRUSIVE, opt-in) - RING / PAGE a tracker tag
# ============================================================
# A location tag that is SEPARATED from its owner advertises connectable and exposes a
# non-owner GATT "play sound" path (the Apple/Google DULT standard; the AirGuard anti-stalking
# app connects and triggers it the same way). We connect and write the sound trigger so a
# planted/following tag chirps and you can physically find it. This is ACTIVE and intrusive -
# it opens a connection, transmits, may surface a hint on the tag, and contends with blue5 for
# the radio - so it is gated on the master activeFp switch, exactly like the GATT probe.
# Only tags in the SEPARATED state are connectable to a non-owner, so only those can be rung.
# Byte rules from the AirGuard app (github.com/seemoo-lab/AirGuard):
#   AirTag : service 7DFC9000-7D1C-4951-86AA-8D9728F8D66C,
#            characteristic 7DFC9001-7D1C-4951-86AA-8D9728F8D66C, write one byte 0xAF, no handshake.
# DULT / third-party Find My / Pebblebee use a notify + timed-stop handshake that gatttool's
# one-shot mode can't drive cleanly; those are recognised but not yet wired to ring here.
ringAirTag() {   # mac -> 0 on success; discover the sound-char value handle, then write 0xAF
    local mac="$1" line vh
    # AirTags use a random advertising address; try random first, then public as a fallback.
    line=$(timeout 12 gatttool -b "$mac" -t random --characteristics 2>/dev/null \
           | grep -i '7dfc9001-7d1c-4951-86aa-8d9728f8d66c' | head -1)
    [ -n "$line" ] || line=$(timeout 12 gatttool -b "$mac" --characteristics 2>/dev/null \
           | grep -i '7dfc9001-7d1c-4951-86aa-8d9728f8d66c' | head -1)
    vh=$(printf '%s' "$line" | sed -n 's/.*char value handle = \(0x[0-9a-fA-F]*\).*/\1/p')
    [ -n "$vh" ] || return 1
    timeout 10 gatttool -b "$mac" -t random --char-write-req -a "$vh" -n af 2>/dev/null | grep -qi 'written successfully' && return 0
    timeout 10 gatttool -b "$mac" --char-write-req -a "$vh" -n af 2>/dev/null | grep -qi 'written successfully' && return 0
    return 1
}
# --- shared interactive-GATT helpers for the handshake-based tag actions --------------------
# The device has no expect/python, so we drive `gatttool -I` by feeding it timed commands on
# stdin (sleeps pace connect -> enable-indications -> write -> listen -> disconnect). This is
# inherently fragile and is UNTESTED against real DULT / third-party Find My / Pebblebee tags
# (none were in view to validate on) - experimental, and gated behind activeFp like all active work.

# Resolve a characteristic's value handle + its CCCD (0x2902) handle for a UUID (one connection).
# Prints "<valueHandle> <cccdHandle>" (cccd empty if the characteristic has none).
gattHandles() {   # mac uuid(lowercase, full 128-bit)
    timeout 15 gatttool -b "$1" -t random --char-desc 2>/dev/null | awk -v U="$2" '
        { h=""; if(match($0,/0x[0-9a-fA-F]+/)) h=substr($0,RSTART,RLENGTH)
          u=""; if(match(tolower($0),/uuid[ :=]+[0-9a-f-]+/)){ u=substr(tolower($0),RSTART,RLENGTH); sub(/.*[ :=]/,"",u) } }
        u==U && vh=="" { vh=h; found=1; next }
        found && cc=="" && u ~ /^0000?2902/ { cc=h }
        END{ print vh" "cc }'
}

# One interactive gatttool session: connect, optionally enable CCCD indications, write <value> to
# the value handle, listen for an indication/notification, disconnect. Echoes gatttool output.
gattSession() {   # mac valueHandle cccdHandle valueHex [listenSecs]
    local mac="$1" vh="$2" cc="$3" val="$4" listen="${5:-6}"
    { printf 'connect\n'; sleep 3
      [ -n "$cc" ] && { printf 'char-write-req %s 0200\n' "$cc"; sleep 1; }
      printf 'char-write-req %s %s\n' "$vh" "$val"; sleep "$listen"
      printf 'disconnect\nexit\n'
    } | timeout $((listen + 12)) gatttool -b "$mac" -t random -I 2>&1
}

# DIS read for a tag (random address). uuid16 -> printable ASCII value.
gattReadTag() {   # mac uuid16
    timeout 8 gatttool -b "$1" -t random --char-read -u "0x$2" 2>/dev/null \
      | sed -n 's/.*value: *//p' | head -1 \
      | awk 'function hx(c){return index("0123456789abcdef",tolower(c))-1}
             {v=""; for(i=1;i<=NF;i++){c=hx(substr($i,1,1))*16+hx(substr($i,2,1)); if(c>=32&&c<127)v=v sprintf("%c",c)} print v}'
}

activeOffMsg() { PROMPT "ACTIVE mode is OFF (passive-only).
Enable it from the menu (Active mode) to connect to the tag.
(ACTIVE: connects to the tag, transmits, and contends with blue5.)"; }

# #3 - ring/page the selected tag. AirTag = one-byte 0xAF (no handshake). DULT / third-party Find
# My / Pebblebee = write the start opcode to their non-owner characteristic via the indication
# handshake (experimental). Tile/Chipolo/SmartTag expose no non-owner sound service (per AirGuard).
ringSelected() {   # mac lbl
    local mac="$1" lbl="$2" char val vh cc out
    LED AMBER; LOG yellow "ACTIVE: ringing $mac ($lbl) - intrusive..."
    case "$lbl" in
        *AirTag*)
            if ringAirTag "$mac"; then
                LOG green "Sound triggered on $mac - listen for the tag."
                PROMPT "Ring sent to $mac ($lbl).
If it is separated from its owner it should be chirping now.
(Silence = owner nearby, out of range, or it refused the connection.)"
            else
                LOG red "Could not ring $mac."
                PROMPT "Couldn't ring $mac. Tags ring only while SEPARATED from their owner;
it may be near its owner, out of range, or blue5 is holding the radio."
            fi
            LED BLUE; return ;;
        *FindMy*)    char="4f860003-943b-49ef-bed4-2f730304427a"; val="010003" ;;  # AirGuard fd44 path
        *DULT*)      char="8e0c0001-1d68-fb92-bf61-48377421680e"; val="0003"   ;;  # DULT Sound_Start 0x0300 (LE)
        *Pebblebee*) char="00002c02-0000-1000-8000-00805f9b34fb"; val="01"     ;;  # AirGuard Pebblebee
        *) PROMPT "Ringing isn't available for '$lbl'.
(Tile, Chipolo and Samsung SmartTag expose no non-owner sound service.)"; LED BLUE; return ;;
    esac
    set -- $(gattHandles "$mac" "$char"); vh="$1"; cc="$2"
    if [ -z "$vh" ]; then
        PROMPT "No non-owner sound characteristic for '$lbl' found on $mac.
It may not implement that profile, or is not connectable (near its owner / out of range)."
        LED BLUE; return
    fi
    out=$(gattSession "$mac" "$vh" "$cc" "$val" 7)
    if printf '%s' "$out" | grep -qi 'written successfully\|Indication\|Notification'; then
        LOG green "Sound command sent to $mac."
        PROMPT "Sound command sent to $mac ($lbl).
EXPERIMENTAL (untested against a real $lbl). If it is separated it should chirp (~5-30 s)."
    else
        LOG red "Ring failed on $mac."
        PROMPT "Ring failed on $mac - no write/indication confirmation.
It may be near its owner, out of range, not implement non-owner sound, or blue5 holds the radio."
    fi
    LED BLUE
}

# #1 - read a tag's identity. DIS (manufacturer/model/firmware) is a plain read; the DULT
# non-owner accessory info (model/category/battery) uses the opcode+indication handshake and is
# experimental. NOTE: a non-owner CANNOT read the serial - DULT gates it behind a physical 10 s
# button hold and returns only an encrypted identifier.
readTagInfoDult() {   # mac -> decoded lines (or empty)
    local mac="$1" vh cc out
    set -- $(gattHandles "$mac" "8e0c0001-1d68-fb92-bf61-48377421680e"); vh="$1"; cc="$2"
    [ -z "$vh" ] && return 0
    out=$({ printf 'connect\n'; sleep 3
            [ -n "$cc" ] && { printf 'char-write-req %s 0200\n' "$cc"; sleep 1; }
            printf 'char-write-req %s 0500\n' "$vh"; sleep 2   # Model Name   (resp 0x0805)
            printf 'char-write-req %s 0600\n' "$vh"; sleep 2   # Accessory Cat (resp 0x0806)
            printf 'char-write-req %s 0c00\n' "$vh"; sleep 2   # Battery Level (resp 0x080c)
            printf 'disconnect\nexit\n'
          } | timeout 30 gatttool -b "$mac" -t random -I 2>&1)
    printf '%s' "$out" | awk '
      function hx(c){return index("0123456789abcdef",tolower(c))-1}
      /value:/ { line=$0; sub(/.*value: */,"",line); n=split(line,b," "); if(n<2) next
         op=b[2] b[1]; txt=""
         for(i=3;i<=n;i++){ c=hx(substr(b[i],1,1))*16+hx(substr(b[i],2,1)); if(c>=32&&c<127) txt=txt sprintf("%c",c) }
         v1=(n>=3)? hx(substr(b[3],1,1))*16+hx(substr(b[3],2,1)) : -1
         if(op=="0805") printf "Model: %s\n", txt
         else if(op=="0806") printf "Accessory category: %d\n", v1
         else if(op=="080c"){ split("Full Medium Low Critical",bn," "); printf "Battery: %s\n", (v1>=0&&v1<=3)?bn[v1+1]:v1 } }'
}
readTagInfo() {   # mac lbl
    local mac="$1" lbl="$2" name man mod fw dult info
    LED AMBER; LOG yellow "ACTIVE: reading $mac ($lbl) - intrusive..."
    name=$(gattReadTag "$mac" 2a00); man=$(gattReadTag "$mac" 2a29)
    mod=$(gattReadTag "$mac" 2a24);  fw=$(gattReadTag "$mac" 2a26)
    info="== Tag info $mac ==
$lbl
Name: ${name:-?}
Manufacturer: ${man:-?}
Model: ${mod:-?}
Firmware: ${fw:-?}"
    dult=$(readTagInfoDult "$mac")
    [ -n "$dult" ] && info="$info
-- DULT non-owner (experimental) --
$dult"
    LED BLUE
    PROMPT "$info
(No serial: a non-owner can't read it - DULT needs a physical 10 s button hold and returns only
an encrypted identifier. Blank fields = tag refused the connection / not separated.)"
}

# #2 - passive proximity "hot/cold" finder for one tag. Reads the tag's latest RSSI from the
# collector's $obs feed (no connection, fully passive) and shows a getting-warmer/colder meter.
# Works even on a tag whose speaker was disabled (where Ring can't help). RED stops it.
bgFinder() {   # mac lbl
    local mac="$1" lbl="$2" r last="" bar arrow rb lastrb="__" now lastEmit=0
    while :; do
        [ -f "$pause" ] && { sleep 0.4; continue; }
        r=$(awk -F'|' -v M="$mac" '$2==M && $3 ~ /^-[0-9]+$/ {v=$3} END{print v}' "$obs" 2>/dev/null)
        now=$(date +%s)
        if [ -n "$r" ]; then
            bar=$(makeBar "$r"); rb=$(( r / 5 ))
            if [ -n "$last" ]; then
                if   [ "$r" -gt "$last" ] 2>/dev/null; then arrow="<<< WARMER (closer)"
                elif [ "$r" -lt "$last" ] 2>/dev/null; then arrow=">>> colder (farther)"
                else arrow="= steady"; fi
            else arrow="(move to compare)"; fi
            # repaint only when the RSSI bucket changes or once per heartbeat (append-only log)
            if [ "$rb" != "$lastrb" ] || [ $(( now - lastEmit )) -ge "$heartbeat" ]; then
                LOG cyan "FIND $lbl  ${mac: -8}   (RED=stop)"
                LOG "$(printf '%5s dBm  %s  %s' "$r" "$bar" "$arrow")"
                lastrb="$rb"; lastEmit="$now"
            fi
            last="$r"
        else
            if [ $(( now - lastEmit )) -ge "$heartbeat" ]; then
                LOG cyan "FIND $lbl  ${mac: -8}   (RED=stop)"
                LOG "   -- no recent advert (tag silent / out of range) --"; lastEmit="$now"
            fi
        fi
        sleep 2
    done
}
findTag() {   # mac lbl
    local mac="$1" lbl="$2" btn fpid
    rm -f "$pause"
    LOG cyan "Proximity finder: $lbl  ${mac: -8}   RED = stop"
    bgFinder "$mac" "$lbl" & fpid=$!
    while true; do
        btn=$(WAIT_FOR_INPUT)
        case "$btn" in B|BACK) kill "$fpid" 2>/dev/null; return;; esac
    done
}

# Tag tools hub: pick a tag in view, then act on it (passive Find, or active Ring / Read info).
tagTools() {
    local rows=() macs=() lbls=() sig mac src lbl pick i selMac selLbl act
    while IFS='|' read -r sig mac src lbl; do
        [ "$src" = "TAG" ] || continue
        [ -z "$mac" ] && continue
        macs+=("$mac"); lbls+=("$lbl")
        rows+=("$(printf '%4s %s %s' "$sig" "${mac: -8}" "${lbl:0:16}")")
    done < <(liveSnapshotRows)
    if [ ${#rows[@]} -eq 0 ]; then PROMPT "No tracker tags in view.
Let the radar run a few seconds so tags appear, then try again."; return; fi
    while true; do
        pick=$(LIST_PICKER "Tag tools - pick a tag (RED=back)" "${rows[@]}" "${rows[0]}") || return
        selMac=""; selLbl=""; i=0
        while [ $i -lt ${#rows[@]} ]; do [ "${rows[$i]}" = "$pick" ] && { selMac="${macs[$i]}"; selLbl="${lbls[$i]}"; break; }; i=$((i+1)); done
        [ -n "$selMac" ] || continue
        while true; do
            act=$(LIST_PICKER "$selLbl ${selMac: -8}" "Find (proximity, passive)" "Ring (ACTIVE)" "Read info (ACTIVE)" "Back to tag list" "Find (proximity, passive)") || break
            case "$act" in
                "Find (proximity, passive)") findTag "$selMac" "$selLbl" ;;
                "Ring (ACTIVE)")      [ "$activeFp" = true ] && ringSelected "$selMac" "$selLbl" || activeOffMsg ;;
                "Read info (ACTIVE)") [ "$activeFp" = true ] && readTagInfo "$selMac" "$selLbl" || activeOffMsg ;;
                "Back to tag list")   break ;;
            esac
        done
    done
}

# ============================================================
# MENU HUB (pop-up list; shown on launch and when RED pressed in radar)
# ============================================================
# LIST_PICKER signature:  LIST_PICKER <title> <opt1> <opt2> ... <optN> <default>
# The LAST arg is the DEFAULT (pre-selected option, shown with a filled circle) and MUST repeat
# one of the options. If it is OMITTED, the binary eats the last REAL option as the default and
# that option vanishes from the list (this looked like "the menu is truncated / no More item").
# So every LIST_PICKER call ends with an explicit default. The list scrolls when it is long.

# Turn ACTIVE mode ON from the menu, with a confirmation (it is intrusive). Mutates the global
# activeFp so the change persists for the rest of the session.
enableActive() {
    local c
    c=$(LIST_PICKER "Enable ACTIVE mode?" "Yes - connect to devices (ACTIVE)" "No - stay passive" "No - stay passive")
    [ "$c" = "Yes - connect to devices (ACTIVE)" ] || { LOG green "Stayed passive (Stages 1-2 only)."; return; }
    activeFp=true
    LOG red "ACTIVE mode ON - 'Probe BT device' added; Tag tools' Ring/Read info now enabled."
}

menu() {
    local choice modeItem extra
    while true; do
        if [ "$activeFp" = true ]; then
            modeItem="Active mode: ON (disable)"; extra="Probe BT device (ACTIVE!)"
        else
            modeItem="Active mode: OFF (enable)"; extra=""
        fi
        # Flat, titled, SCROLLABLE list - scroll down to reach items below the screen.
        if [ -n "$extra" ]; then
            choice=$(LIST_PICKER "Main Menu" "Start scan" "Take snapshot" "Compare snapshots" "Tag tools (find/ring/info)" "Learn known here" "Clear saved data" "Stop & exit" "$modeItem" "$extra" "Start scan")
        else
            choice=$(LIST_PICKER "Main Menu" "Start scan" "Take snapshot" "Compare snapshots" "Tag tools (find/ring/info)" "Learn known here" "Clear saved data" "Stop & exit" "$modeItem" "Start scan")
        fi
        [ $? -ne 0 ] && continue
        case "$choice" in
            "Start scan")                 radar ;;
            "Take snapshot")              snapshotAndClear ;;
            "Compare snapshots")          doCompare ;;
            "Tag tools (find/ring/info)") tagTools ;;
            "Learn known here")           learnKnown ;;
            "Clear saved data")           clearHistory ;;
            "Active mode: OFF (enable)")  enableActive ;;
            "Active mode: ON (disable)")  activeFp=false; LOG green "ACTIVE mode OFF - passive only (Stages 1-2)." ;;
            "Probe BT device (ACTIVE!)")  gattProbe ;;
            "Stop & exit")                LOG green "Stopping SlipperyPickle."; cleanupLive; cleanup; exit 0 ;;
        esac
    done
}

# ============================================================
# MAIN
# ============================================================
# Bluetooth needs no scanner of our own: PineAP Recon's blue5 daemon owns the radio and
# writes decoded devices to blue5.db, which bgCollector reads each pass. If the DB isn't
# there yet, blue5 (PineAP Recon) simply isn't running - warn, same as we do for WiFi.
if [ "$liveBle" = true ] && [ ! -f "$blue5Db" ]; then
    LOG yellow "Bluetooth needs PineAP Recon (blue5) running - blue5.db not found yet."
fi
# Single-instance guard: a second copy would collide with this one on the shared /tmp files
# (collector/parser awks, $obs). Refuse to start if another live instance holds the lock; a
# stale lock from a crashed run (its PID no longer alive) is taken over. Must run BEFORE we
# touch any shared state, and cleanup() / cleanupLive() are gated on weOwnLock so this refusal
# path never disturbs the instance that is actually running.
if [ -f "$lockFile" ] && kill -0 "$(cat "$lockFile" 2>/dev/null)" 2>/dev/null; then
    LOG red "Already running (pid $(cat "$lockFile" 2>/dev/null)) - not starting a second copy."
    ERROR_DIALOG "SlipperyPickle is already running. Close the other copy first."
    exit 1
fi
echo $$ > "$lockFile"; weOwnLock=1

: > "$obs"; rm -f "$pause"

cleanupLive() {
    # Only our own instance may tear down the shared /tmp state (a refused second copy must not
    # delete the running instance's collector/parser awk files - that was the two-copy foot-gun).
    [ "$weOwnLock" = 1 ] || return 0
    kill "$colPid" "$renPid" "$scanloopPid" "$fpcapPid" 2>/dev/null
    # stop the resident collector + fp-parser awks (killing the parent closes their stdin so
    # they EOF, but match by name too so a stray never leaks an OUI/parser awk across relaunches).
    for p in $(ps w 2>/dev/null | grep -E '[s]lipperypickle_(collector|fp).awk' | awk '{print $1}'); do
        kill "$p" 2>/dev/null
    done
    killall tcpdump 2>/dev/null           # the Stage-2 IE sniffer
    rm -f "$pause" "$obs" "$obs.t" "$collectorAwk" "$fpcapAwk" "$snapAwk" "$cmpAwk" "$iefp" "$seqf" \
          "$lockFile" /tmp/sp_b.* /tmp/sp_p.* /tmp/sp_t.* /tmp/sp_l.* /tmp/sp_i.* 2>/dev/null
}
trap 'cleanupLive; cleanup' EXIT INT TERM

# Write the resident OUI-transform awk program the collector coprocess runs.
# Loads the OUI table once (BEGIN), then for each "W|..."/"B|..." line on stdin appends a
# decoded "EPOCH|MAC|RSSI|SRC|VENDOR|BLECO|BLENAME|FREQ" row to $obs; "FLUSH|t" flushes.
cat > "$collectorAwk" <<'AWKEOF'
function normmac(s,  u){
  gsub(/[ \t\r]/,"",s); u=toupper(s)
  if(u ~ /^[0-9A-F][0-9A-F]:[0-9A-F][0-9A-F]:[0-9A-F][0-9A-F]:[0-9A-F][0-9A-F]:[0-9A-F][0-9A-F]:[0-9A-F][0-9A-F]$/) return u
  if(u ~ /^[0-9A-F][0-9A-F][0-9A-F][0-9A-F][0-9A-F][0-9A-F][0-9A-F][0-9A-F][0-9A-F][0-9A-F][0-9A-F][0-9A-F]$/)
     return substr(u,1,2)":"substr(u,3,2)":"substr(u,5,2)":"substr(u,7,2)":"substr(u,9,2)":"substr(u,11,2)
  return ""
}
# --- tracker-tag detector (radar "T" label only) -----------------------------------------
# KEEP IN SYNC with tracker()/sdata()/has16()/hb() in $snapAwk - these are the identical
# AirGuard byte rules, duplicated here so the live collector can tag trackers "T" without a
# per-frame sqlite+awk decode (that would re-introduce the render sluggishness we fixed). The
# authoritative decode for the Compare report still lives in $snapAwk; this is a display hint.
function hb(s,  a,bb){ a=index("0123456789ABCDEF",substr(s,1,1)); bb=index("0123456789ABCDEF",substr(s,2,1))
  if(a==0||bb==0) return -1; return (a-1)*16+(bb-1) }
function sdata(svcd,u,  p,n,len,uu){ p=1; n=length(svcd)
  while(p+5<=n){ len=hb(substr(svcd,p,2)); if(len<1) break
    if(substr(svcd,p+2,2)=="16" && len>=3){ uu=substr(svcd,p+6,2) substr(svcd,p+4,2)
      if(uu==u) return substr(svcd,p+8,(len-3)*2) }
    p=p+2+len*2 }
  return "NONE" }
function has16(svc16,u){ return index("," svc16 ",", "," u ",")>0 }
function tracker(mfr,svcd,svc16,  ln,st,dt,sep,d,b0){
  if(substr(mfr,1,6)=="4C0012" && length(mfr)>=10){
    ln=substr(mfr,7,2); st=hb(substr(mfr,9,2)); if(st<0) return ""
    dt=int(st/16)%4; sep=(ln=="19")
    if(dt==1) return "AirTag" (sep?" [separated]":"")
    if(dt==2) return "FindMy-tag" (sep?" [separated]":"")
    return "" }
  d=sdata(svcd,"FD5A"); if(d!="NONE"){ b0=hb(substr(d,1,2)); if(b0>=0 && int(b0/8)==2) return "SmartTag" }
  d=sdata(svcd,"FEED"); if(substr(d,1,4)=="0200") return "Tile"
  if(has16(svc16,"FE33")) return "Chipolo"
  if(has16(svc16,"FA25") || sdata(svcd,"FA25")!="NONE") return "Pebblebee"
  d=sdata(svcd,"FEAA")
  if(substr(d,1,2)=="40") return "Google-FMDN"
  if(substr(d,1,2)=="41") return "Google-FMDN [separated]"
  if(sdata(svcd,"FCB2")!="NONE") return "DULT-tag"
  return "" }
BEGIN{
  while((getline L < OUIFILE) > 0){
     n=split(L,a,/[ \t]+/); if(n<2) continue
     k=toupper(substr(a[1],1,8)); if(!(k in oui)){ g=a[2]; sub(/[.,]+$/,"",g); oui[k]=g }
  }
  close(OUIFILE)
  comp["76"]="Apple"; comp["117"]="Samsung"; comp["224"]="Google"; comp["6"]="Microsoft"
  comp["637"]="Huawei"; comp["343"]="Xiaomi/Huami"; comp["911"]="Xiaomi"; comp["301"]="Sony"; comp["89"]="Nordic"
  # Chinese Android OEM BLE company IDs (Bluetooth SIG assigned numbers). RedMagic = Nubia;
  # Redmi has no own ID (it is Xiaomi, 911). Tecno/Infinix/itel share Transsion.
  comp["1839"]="OnePlus"; comp["1946"]="Oppo"; comp["2103"]="Vivo"; comp["2212"]="Realme"
  comp["2250"]="Nubia"; comp["2392"]="ZTE"; comp["2502"]="Honor"; comp["3790"]="Honor"
  comp["939"]="Meizu"; comp["709"]="Lenovo"; comp["1260"]="Motorola"; comp["8"]="Motorola"; comp["2370"]="Transsion"
  # Other handset makers (SIG company IDs). Mostly Android; Jolla = Sailfish; legacy IDs kept too.
  comp["3275"]="Nothing"; comp["3267"]="HMD/Nokia"; comp["1"]="Nokia"; comp["196"]="LG"; comp["749"]="HTC"
  comp["3014"]="TCL"; comp["36"]="Alcatel"; comp["4298"]="Fairphone"; comp["3649"]="Asus"; comp["60"]="BlackBerry"
  comp["481"]="Jolla"; comp["86"]="SonyEricsson"; comp["162"]="Vertu"; comp["982"]="Yota"; comp["384"]="Gigaset"
  comp["398"]="Google"
  FS="|"; lc=0
}
$1=="FLUSH"{
  if(lc>=1500){ close(OBS); system("tail -n 1000 " OBS " > " OBS ".t 2>/dev/null && mv " OBS ".t " OBS); lc=0 }
  else close(OBS)
  next
}
$1=="W"{ m=normmac($3); if(m==""){next} v=oui[substr(m,1,8)]; s=($4==""?"-99":$4); print $2"|"m"|"s"|WIFI|"v"|||"$5 >> OBS; lc++; next }
$1=="B"{ m=normmac($3); if(m==""){next} v=oui[substr(m,1,8)]; s=($4==""?"-99":$4); co=($5 in comp)?comp[$5]:""; nm=$6; gsub(/\|/,"",nm);
  tg=tracker(toupper($7),toupper($8),toupper($9));    # field 9 = tracker type (empty if not a tag) -> radar "T"
  print $2"|"m"|"s"|BLE|"v"|"co"|"nm"||"tg >> OBS; lc++; next }
AWKEOF

# Stage 2 IE-fingerprint parser: reconstruct each probe-request frame from tcpdump -xx,
# strip radiotap + 24-byte 802.11 header, walk the IEs, emit "MAC|O:<tagorder>#<capbytes>".
# Pure busybox-awk hex (no strtonum). Prints only when a MAC's fingerprint first appears
# or changes, so $iefp stays small. Validated against live wlan0mon probe-reqs.
cat > "$fpcapAwk" <<'FPEOF'
function hx(c){ return index("0123456789abcdef", tolower(c)) - 1 }
function b(H,p,  s){ s=substr(H,p*2+1,2); if(length(s)<2) return -1; return hx(substr(s,1,1))*16 + hx(substr(s,2,1)) }
function finish(  rtl,p,total,tag,len,order,caps,fp,lo,hi,seq){
  if(sa=="" || H=="") return
  rtl=b(H,2)+b(H,3)*256; p=rtl+24; total=int(length(H)/2); order=""; caps=""
  # 802.11 sequence number: Sequence Control is 2 bytes at header offset 22-23 (LE);
  # the top 12 bits are the frame seqno, which keeps incrementing across a MAC change
  # (Vanhoef 2016). Written per-MAC to SEQF (latest wins) for manual rotation analysis.
  lo=b(H,rtl+22); hi=b(H,rtl+23)
  if(lo>=0 && hi>=0 && SEQF!=""){ seq=int((lo + hi*256)/16); print toupper(sa) "|" seq >> SEQF; seqn++
    # SEQF is append-only (one line per probe-request); bound it so it can't fill tmpfs/RAM.
    # Only the latest line per MAC is ever read, so keeping the last 300 is plenty.
    if(seqn>=800){ close(SEQF); system("tail -n 300 " SEQF " > " SEQF ".t 2>/dev/null && mv " SEQF ".t " SEQF); seqn=0 }
    else fflush(SEQF) }
  while(p+2<=total){ tag=b(H,p); len=b(H,p+1); if(tag<0||len<0) break; if(p+2+len>total) break
    if(tag!=0) order=order tag ","
    if(tag==1||tag==45||tag==50||tag==127||tag==191||tag==255||tag==221) caps=caps tag ":" substr(H,(p+2)*2+1,len*2) ";"
    p=p+2+len }
  if(order=="") return
  fp="O:" order "#" caps
  if(seenfp[sa]==fp) return
  seenfp[sa]=fp; print toupper(sa) "|" fp; fflush()
}
/Probe Request/ && /SA:/ { finish(); sa=""; H=""; if(match($0,/SA:[0-9a-fA-F:]+/)){ s=substr($0,RSTART+3,RLENGTH-3); gsub(/:/,"",s); sa=s } next }
/0x[0-9a-fA-F]+:/ { line=$0; sub(/^.*0x[0-9a-fA-F]+:[ \t]*/,"",line); gsub(/[^0-9a-fA-F]/,"",line); H=H tolower(line); next }
END{ finish() }
FPEOF

# Snapshot enrichment merge: maps (P=PNL, B=BT le_random/mfr/svcd, H=hostname, F=IE-fp) are
# read first, then each live device row "D" emits the 15-field snapshot record.
cat > "$snapAwk" <<'SNEOF'
# one hex byte "A7" -> 167 (busybox awk has no strtonum); -1 if not hex
function hb(s,  a,b){ a=index("0123456789ABCDEF",substr(s,1,1)); b=index("0123456789ABCDEF",substr(s,2,1))
  if(a==0||b==0) return -1; return (a-1)*16+(b-1) }
# blue5 stores svcd as raw advertising structures: <len><0x16><uuid LE><data>... Return the
# data of the structure for 16-bit service UUID u (e.g. "FD5A"), or "NONE" if absent.
function sdata(svcd,u,  p,n,len,uu){ p=1; n=length(svcd)
  while(p+5<=n){ len=hb(substr(svcd,p,2)); if(len<1) break
    if(substr(svcd,p+2,2)=="16" && len>=3){ uu=substr(svcd,p+6,2) substr(svcd,p+4,2)
      if(uu==u) return substr(svcd,p+8,(len-3)*2) }
    p=p+2+len*2 }
  return "NONE" }
# svc16 is a comma list of advertised 16-bit service UUIDs, e.g. "FEF3" or "1105,110A"
function has16(svc16,u){ return index("," svc16 ",", "," u ",")>0 }
# Location-tracker tags. Byte rules follow the AirGuard app (Heinrich et al., arXiv 2202.11813;
# github.com/seemoo-lab/AirGuard) and the Apple/Google DULT draft (service data 0xFCB2).
# "[separated]" = the tag reports it is away from its owner - the state a planted tag is in.
function tracker(mfr,svcd,svc16,  ln,st,dt,sep,d,b0){
  if(substr(mfr,1,6)=="4C0012" && length(mfr)>=10){        # Apple Find My (offline finding)
    ln=substr(mfr,7,2); st=hb(substr(mfr,9,2)); if(st<0) return ""
    dt=int(st/16)%4; sep=(ln=="19")                       # (status & 0x30)>>4; len 0x19 = separated
    if(dt==1) return "AirTag" (sep?" [separated]":"")
    if(dt==2) return "FindMy-tag" (sep?" [separated]":"") # third-party Find My accessory
    return "" }                                           # 0 = iPhone/Mac, 3 = AirPods: not tags
  d=sdata(svcd,"FD5A")                                    # Samsung SmartTag: data[0] & 0xF8 == 0x10
  if(d!="NONE"){ b0=hb(substr(d,1,2)); if(b0>=0 && int(b0/8)==2) return "SmartTag" }
  d=sdata(svcd,"FEED"); if(substr(d,1,4)=="0200") return "Tile"
  if(has16(svc16,"FE33")) return "Chipolo"
  if(has16(svc16,"FA25") || sdata(svcd,"FA25")!="NONE") return "Pebblebee"
  d=sdata(svcd,"FEAA")                                    # Google Find My Device network frames
  if(substr(d,1,2)=="40") return "Google-FMDN"
  if(substr(d,1,2)=="41") return "Google-FMDN [separated]"
  if(sdata(svcd,"FCB2")!="NONE") return "DULT-tag"
  return "" }
function devtype(mfr,svcd,svc16,  t){
  mfr=toupper(mfr); svcd=toupper(svcd); svc16=toupper(svc16)
  t=tracker(mfr,svcd,svc16); if(t!="") return t
  if(substr(mfr,1,4)=="4C00"){ t=substr(mfr,5,2)
    if(t=="02")return "AppleBeacon"; if(t=="05")return "AirDrop"; if(t=="07")return "AirPods"
    if(t=="09"||t=="0A")return "AirPlay"; if(t=="0C")return "Handoff"
    if(t=="0F")return "NearbyAction"; if(t=="10")return "iPhone/Nearby"; if(t=="12")return "iDevice/FindMy"
    return "Apple" }
  if(substr(mfr,1,4)=="7500") return "Samsung"
  if(substr(mfr,1,4)=="0600") return "Microsoft"
  if(substr(mfr,1,4)=="027D"||substr(mfr,1,4)=="7D02") return "Huawei"
  if(substr(mfr,1,4)=="8F03"||substr(mfr,1,4)=="038F") return "Xiaomi"
  if(sdata(svcd,"FE95")!="NONE" || has16(svc16,"FE95")) return "Xiaomi/Mi"
  if(sdata(svcd,"FE2C")!="NONE" || has16(svc16,"FE2C")) return "FastPair"
  if(sdata(svcd,"FD6F")!="NONE" || has16(svc16,"FD6F")) return "ExposureNotif"
  if(sdata(svcd,"FEAA")!="NONE") return "Eddystone"
  if(sdata(svcd,"FD69")!="NONE" || has16(svc16,"FD69")) return "Samsung-OfflineFind"
  if(sdata(svcd,"FD5A")!="NONE" || has16(svc16,"FD5A")) return "Samsung"
  return ""
}
function osfam(ven,bleco,model){
  if(model ~ /AirTag|FindMy-tag|SmartTag|Tile|Chipolo|Pebblebee|Google-FMDN|DULT-tag/) return "tag"
  if(bleco=="Apple"||ven~/Apple/||model~/Apple|AirP|iPhone|iDevice|Handoff|AirDrop|AirPlay|Nearby/) return "iOS/macOS"
  if(bleco=="Samsung"||ven~/Samsung/||model~/Samsung/) return "Android(Sam)"
  if(bleco=="Google"||ven~/Google/||model~/FastPair/) return "Android"
  if(bleco=="Huawei"||ven~/[Hh]uawei|HONOR/||model~/Huawei/) return "HarmonyOS"
  if(bleco~/Xiaomi/||ven~/Xiaomi|Mijia|Huami|Amazfit/||model~/Xiaomi/) return "Android(Xia)"
  if(bleco~/OnePlus|Oppo|Vivo|Realme|Nubia|ZTE|Honor|Meizu|Lenovo|Motorola|Transsion/||ven~/OnePlus|Oppo|Vivo|Realme|Nubia|ZTE|Meizu|Lenovo|Motorola/) return "Android"
  if(bleco~/Nothing|Nokia|LG|HTC|TCL|Alcatel|Fairphone|Asus|BlackBerry|Vertu|Yota|Gigaset/||ven~/Nothing|Nokia|Fairphone|Alcatel|BlackBerry|Gigaset|Vertu|Yota|Asustek|HTC|TCL/) return "Android"
  if(bleco~/Jolla/||ven~/Jolla/) return "Sailfish"
  return ""
}
BEGIN{FS="\t"}
$1=="P"{ pnl[$2]=$3; next }
$1=="A"{ ap[$2]=1; next }
$1=="B"{ ler[$2]=$3; mfrm[$2]=$4; svcm[$2]=$5; s16[$2]=$6; next }
$1=="H"{ if($3!="") host[$2]=$3; next }
$1=="F"{ fpm[$2]=$3; next }
$1=="D"{
  key=$2; src=$3; mac=$4; rssi=$5; ven=$6; bleco=$7; blen=$8; first=$9; last=$10
  isble=(src ~ /BLE|BTC/)
  if(isble){ rnd=(ler[key]==""?0:(ler[key]+0)) } else { rnd=(substr(toupper(mac),2,1) ~ /[2367ABEF]/)?1:0 }
  model=devtype(mfrm[key],svcm[key],s16[key]); os=osfam(ven,bleco,model)
  fp=(isble?"":fpm[key])
  isap=((!isble && (key in ap))?1:0)
  printf "%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s\n", src, mac, rnd, ven, fp, pnl[key], bleco, blen, model, host[key], os, rssi, isap, first, last
}
SNEOF

# Identity correlation (union-find + PNL rare-SSID union + mutual-NN cross-radio).
cat > "$cmpAwk" <<'CMEOF'
BEGIN{ FS="|"
  # KNOWN: one identity token per line = your own/authorized devices (see $knownFile).
  if(KNOWN!=""){ while((getline L < KNOWN)>0){ if(L!="") kn[L]=1 } close(KNOWN) }
  # HIST: token<TAB>firstSeen<TAB>lastSeen<TAB>sessions, from prior runs (see $histFile).
  if(HIST!=""){ while((getline L < HIST)>0){ nf=split(L,HH,"\t"); if(nf>=4 && HH[1]!=""){
       h_first[HH[1]]=HH[2]+0; h_sess[HH[1]]=HH[4]+0 } } close(HIST) }
}
function find(x,  r){ r=x; while(par[r]!=r && par[r]!="") r=par[r];
                      while(par[x]!=r && par[x]!=""){ n=par[x]; par[x]=r; x=n } return r }
function uni(a,b,  ra,rb){ if(a==""||b=="")return; if(!(a in par))par[a]=a;
                      if(!(b in par))par[b]=b; ra=find(a); rb=find(b); if(ra!=rb)par[rb]=ra }
function tok(x){ if(x==""||x=="?")return ""; if(!(x in par))par[x]=x; return x }
# Past-session history for a cluster = the best (max sessions / earliest first-seen) over its
# strong identity tokens. Tokens are per-device (hostname / BLE name / stable MAC), so they
# persist across MAC rotation and across sessions.
function rhist(r,  i,TT,nn){ Rsess[r]=0; Rfseen[r]=0
  nn=split(Rtoks[r],TT,SUBSEP)
  for(i=1;i<=nn;i++){ if(TT[i]=="")continue
    if((TT[i] in h_sess) && h_sess[TT[i]]>Rsess[r]) Rsess[r]=h_sess[TT[i]]
    if((TT[i] in h_first) && (Rfseen[r]==0 || h_first[TT[i]]<Rfseen[r])) Rfseen[r]=h_first[TT[i]] } }
{
  snap=$1+0; src=$2; mac=$3; rnd=$4; ven=$5; fp=$6; probes=$7;
  bleco=$8; blen=$9; model=$10; host=$11; os=$12; rssi=$13; isap=$14; first=$15; last=$16;
  radio="WIFI"; if(src ~ /BLE|BTC/) radio="BLE";
  delete T; nt=0;
  if(host!=""  && host!="*")                 T[++nt]="H:" tolower(host);
  if(bleco!="" && blen!="")                   T[++nt]="B:" bleco ":" tolower(blen);
  if(mac!="" && rnd=="0")                      T[++nt]="M:" mac;
  for(i=1;i<=nt;i++){ tok(T[i]); if(i>1) uni(T[1],T[i]) }
  if(nt>0) anchor=T[1];
  else { anchor="W:" src ":" mac; tok(anchor) }
  # Per-key: strong identity tokens (for known-list + history), known flag, and dwell epochs.
  for(i=1;i<=nt;i++){ if(!((anchor SUBSEP T[i]) in ktseen)){ ktseen[anchor SUBSEP T[i]]=1;
        keytoks[anchor]=keytoks[anchor] SUBSEP T[i] } if(T[i] in kn) key_known[anchor]=1 }
  if(first ~ /^[0-9]+$/){ fv=first+0; if(fv>0 && (!(anchor in kfirst)||fv<kfirst[anchor])) kfirst[anchor]=fv }
  if(last  ~ /^[0-9]+$/){ lv=last+0;  if(lv>0 && (!(anchor in klast)||lv>klast[anchor]))  klast[anchor]=lv }
  # The IE fingerprint is NOT unique: every phone of the same model + OS build sends the same
  # IEs. So it is not a strong token; like the PNL it only links identities when it is RARE
  # (shared by 2..FCM identities) - decided in END once all snapshots are read.
  if(fp!="" && !((fp SUBSEP anchor) in faseen)){ faseen[fp SUBSEP anchor]=1;
     fanch[fp]=fanch[fp] SUBSEP anchor; fcount[fp]++ }
  if(probes!=""){ np=split(probes, PP, ";");
     for(i=1;i<=np;i++){ s=PP[i]; if(s=="")continue; sl=tolower(s);
        if(!((sl SUBSEP anchor) in saseen)){ saseen[sl SUBSEP anchor]=1;
           sanch[sl]=sanch[sl] SUBSEP anchor; scount[sl]++ } } }
  key=anchor;
  seen[key SUBSEP snap]=1;
  if(rssi ~ /^-?[0-9]+$/){ rv=rssi+0;
      if(rv>-99 && (!((key SUBSEP snap) in krs) || rv>krs[key SUBSEP snap])) krs[key SUBSEP snap]=rv }
  if(!(key in krad)) krad[key]=radio; else if(krad[key]!=radio) krad[key]="MIX";
  if(host!="" && host!="*") ev_host[key]=host;
  if(os!="")   ev_os[key]=os;
  if(model!="") ev_model[key]=model;
  if(bleco!="") ev_bleco[key]=bleco;
  if(blen!="")  ev_blen[key]=blen;
  if(ven!="" && ven!="?") ev_ven[key]=ven;
  if(fp!="")   ev_fp[key]=fp;
  if(isap=="1") ev_ap[key]=1;
  if(model ~ /AirTag|FindMy-tag|SmartTag|Tile|Chipolo|Pebblebee|Google-FMDN|DULT-tag/){
     if(!(key in ev_trk) || model ~ /separated/) ev_trk[key]=model }
  if(probes!="" && !(key in ev_pnl)) ev_pnl[key]=probes;
  if(mac!="")  ev_macs[key]=ev_macs[key] (index(" " ev_macs[key] " ", " " mac " ")?"":(ev_macs[key]==""?"":" ") mac);
  allkeys[key]=1;
}
END{
  for(s in scount){ if(scount[s]>=2 && scount[s]<=CMN){
     n=split(sanch[s], AA, SUBSEP); base="";
     for(i=1;i<=n;i++){ if(AA[i]=="")continue; if(base=="")base=AA[i]; else uni(base,AA[i]) } } }
  for(f in fcount){ if(fcount[f]>=2 && fcount[f]<=FCM){
     n=split(fanch[f], AA, SUBSEP); base="";
     for(i=1;i<=n;i++){ if(AA[i]=="")continue; if(base=="")base=AA[i]; else uni(base,AA[i]) } } }
  for(k in allkeys){ r=find(k); root[k]=r; roots[r]=1 }
  for(sk in seen){ split(sk,sa,SUBSEP); kk=sa[1]; sn=sa[2]; r=root[kk];
                   if(!((r SUBSEP sn) in rs)){ rs[r SUBSEP sn]=1; cnt[r]++ } }
  for(k in allkeys){ r=root[k];
     for(s=1;s<=NS;s++){ if((k SUBSEP s) in krs){ v=krs[k SUBSEP s];
        if(!((r SUBSEP s) in Rrs) || v>Rrs[r SUBSEP s]) Rrs[r SUBSEP s]=v } } }
  for(k in allkeys){ r=root[k];
    if(!(r in Rrad)) Rrad[r]=krad[k]; else if(Rrad[r]!=krad[k]) Rrad[r]="MIX";
    if(ev_host[k]!="")  R_host[r]=ev_host[k];
    if(ev_os[k]!="")    R_os[r]=ev_os[k];
    if(ev_model[k]!="") R_model[r]=ev_model[k];
    if(ev_bleco[k]!="") R_bleco[r]=ev_bleco[k];
    if(ev_blen[k]!="")  R_blen[r]=ev_blen[k];
    if(ev_ven[k]!="")   R_ven[r]=ev_ven[k];
    if(ev_fp[k]!="")    R_fp[r]=ev_fp[k];
    if(k in ev_ap)      R_ap[r]=1;
    if(k in ev_trk){ if(!(r in R_trk) || ev_trk[k] ~ /separated/) R_trk[r]=ev_trk[k] }
    if(ev_pnl[k]!="" && !(r in R_pnl)) R_pnl[r]=ev_pnl[k];
    if(ev_macs[k]!="")  R_macs[r]=R_macs[r] (R_macs[r]==""?"":" ") ev_macs[k];
    if(k in key_known) R_known[r]=1;
    if(k in kfirst){ if(!(r in Rfirst)||kfirst[k]<Rfirst[r]) Rfirst[r]=kfirst[k] }
    if(k in klast){  if(!(r in Rlast) ||klast[k] >Rlast[r])  Rlast[r] =klast[k] }
    nn=split(keytoks[k],TT,SUBSEP); for(ti=1;ti<=nn;ti++){ if(TT[ti]=="")continue
       if(!((r SUBSEP TT[ti]) in rtseen)){ rtseen[r SUBSEP TT[ti]]=1; Rtoks[r]=Rtoks[r] SUBSEP TT[ti] } }
  }
  for(r in roots){
    lbl=R_host[r];
    if(lbl=="") lbl=(R_bleco[r]!=""? R_bleco[r] " " R_blen[r] : "");
    if(lbl=="" && R_model[r]!="") lbl=R_model[r];
    if(lbl=="") lbl=(R_ven[r]!=""? R_ven[r] (R_os[r]!=""? " "R_os[r]:"") : "");
    if(lbl=="" && R_pnl[r]!=""){ split(R_pnl[r],QQ,";"); lbl="PNL:" QQ[1] }
    if(lbl=="" && R_fp[r]!="") lbl="fp-dev";
    m=R_macs[r]; sub(/^ +/,"",m); split(m,mm," ");
    if(lbl=="") lbl=mm[1];
    # Access points (anything that beacons) are infrastructure: say so in the label.
    if(r in R_ap) lbl="AP " (R_ven[r]!=""? R_ven[r] : mm[1]);
    # Tracker tags: the tag type says more than the vendor ("Apple") does.
    if(r in R_trk) lbl="TAG " R_trk[r];
    R_lbl[r]=lbl; R_m1[r]=mm[1];
  }
  # Known/authorized devices (on the ignore-list) are hidden from every result section.
  nk=0; for(r in roots){ if(r in R_known) nk++ }
  n=0; for(r in roots){ if(cnt[r]>=TH && !(r in R_known)) ord[++n]=r }
  for(i=1;i<=n;i++)for(j=i+1;j<=n;j++) if(cnt[ord[j]]>cnt[ord[i]]){t=ord[i];ord[i]=ord[j];ord[j]=t}
  # Tracker tags that recur across separated snapshots = the AirGuard / BLE-Doubt signal:
  # the same tag keeps showing up wherever you are. Tags away from their owner rank first.
  nt=0; for(r in roots){ if((r in R_trk) && cnt[r]>=TH && !(r in R_known)) tr[++nt]=r }
  for(i=1;i<=nt;i++)for(j=i+1;j<=nt;j++){
     si=(R_trk[tr[i]] ~ /separated/); sj=(R_trk[tr[j]] ~ /separated/)
     if(sj>si || (sj==si && cnt[tr[j]]>cnt[tr[i]])){t=tr[i];tr[i]=tr[j];tr[j]=t} }
  ns=0; for(i=1;i<=nt;i++) if(R_trk[tr[i]] ~ /separated/) ns++
  printf("TRACKERS %d %d\n", nt, ns);
  for(i=1;i<=nt;i++){ r=tr[i]; printf("t\t%d/%d\t%s\t%s\n", cnt[r], NS, R_trk[r], R_m1[r]) }
  printf("KNOWN %d\n", nk);
  printf("FLAGGED %d\n", n);
  for(i=1;i<=n;i++){ r=ord[i]; rhist(r)
    dw=((r in Rlast)&&(r in Rfirst))?(Rlast[r]-Rfirst[r]):0; if(dw<0)dw=0
    printf("f\t%d/%d\t%s\t%s\t%s\t%s\t%d\t%d\n", cnt[r], NS, R_lbl[r],
           (R_os[r]!=""?R_os[r]:"-"), (Rrad[r]!=""?Rrad[r]:"-"), R_m1[r], dw, Rsess[r]+1);
  }
  nw=0; nb=0;
  for(r in roots){ if(cnt[r]<XMIN || (r in R_known)) continue;
     # an AP cannot be the WiFi radio of a phone/wearable, so APs never enter the pairing
     if(Rrad[r]=="WIFI"){ if(!(r in R_ap)) warr[++nw]=r }
     else if(Rrad[r]=="BLE"){ if(!(r in R_trk)) barr[++nb]=r } }   # a tag has no WiFi radio
  for(iw=1;iw<=nw;iw++){ a=warr[iw]; bestsc[a]=9999; bestb[a]="" }
  for(ib=1;ib<=nb;ib++){ b=barr[ib]; bbestsc[b]=9999; bbesta[b]="" }
  for(iw=1;iw<=nw;iw++){ a=warr[iw];
    for(ib=1;ib<=nb;ib++){ b=barr[ib];
      if(R_os[a]!="" && R_os[b]!="" && R_os[a]!=R_os[b]) continue;
      shared=0; hits=0; dsum=0;
      for(s=1;s<=NS;s++){
        if((a SUBSEP s) in Rrs && (b SUBSEP s) in Rrs){ shared++;
           d=Rrs[a SUBSEP s]-Rrs[b SUBSEP s]; if(d<0)d=-d;
           if(d<=TOL){ hits++; dsum+=d } } }
      if(shared>=XMIN && hits==shared){ sc=dsum/hits;
         hitsAB[a SUBSEP b]=hits;
         if(sc<bestsc[a]){ bestsc[a]=sc; bestb[a]=b }
         if(sc<bbestsc[b]){ bbestsc[b]=sc; bbesta[b]=a } } } }
  nx=0;
  for(iw=1;iw<=nw;iw++){ a=warr[iw]; b=bestb[a];
     if(b==""||bbesta[b]!=a) continue;
     if(bestsc[a]>TOL) continue;
     nx++; XA[nx]=a; XB[nx]=b; XH[nx]=hitsAB[a SUBSEP b]; XD[nx]=bestsc[a] }
  for(i=1;i<=nx;i++)for(j=i+1;j<=nx;j++) if(XD[j]<XD[i]){
      t=XA[i];XA[i]=XA[j];XA[j]=t; t=XB[i];XB[i]=XB[j];XB[j]=t;
      t=XH[i];XH[i]=XH[j];XH[j]=t; t=XD[i];XD[i]=XD[j];XD[j]=t }
  if(XCAP>0 && nx>XCAP) nx=XCAP;
  printf("CROSS %d\n", nx);
  for(i=1;i<=nx;i++){ a=XA[i]; b=XB[i];
      wl=R_lbl[a]; if(wl=="")wl=R_m1[a]; bl=R_lbl[b]; if(bl=="")bl=R_m1[b];
      printf("x\t%d/%d\t%d\t%s\t%s\t%s\t%s\n", XH[i], NS, XD[i], wl, bl, R_m1[a], R_m1[b]) }
  # Emit this session's identity tokens (non-known) so the shell can fold them into the
  # cross-session history store. One "k<TAB>token" line per distinct strong token seen.
  for(r in roots){ if(r in R_known) continue
     nn=split(Rtoks[r],TT,SUBSEP); for(i=1;i<=nn;i++){ if(TT[i]!="") print "k\t" TT[i] } }
}
CMEOF

# Stage 2: pick the monitor interface that is actually UP (an up mon iface reports txpower).
if [ "$liveIe" = true ]; then
    for i in wlan0mon wlan1mon wlan2mon; do
        if iw dev "$i" info 2>/dev/null | grep -q txpower; then ieIface="$i"; break; fi
    done
fi

LED BLUE
LOG green "=== SlipperyPickle v$version ready ==="
LOG "RED=menu   GREEN=device info"
[ "$liveWifi" = true ] && LOG yellow "WiFi+BT need PineAP Recon running."
# One-time recon.db health check. Its index has been seen corrupt ("database disk image is
# malformed"), which makes WiFi reads fail. Warn once (non-fatal, time-bounded); the per-read
# guards still catch failures later.
if [ "$liveWifi" = true ] && [ -f "$reconDb" ]; then
    rchk=$(timeout 10 sqlite3 "$reconDb" "PRAGMA quick_check;" 2>&1 | head -1)
    [ "$rchk" = "ok" ] || LOG red "WARNING: recon.db failed its integrity check ($rchk) - WiFi results may be incomplete. Reset recon data in the Pineapple UI."
fi
[ "$liveIe" = true ] && [ -n "$ieIface" ] && LOG "IE fingerprint: $ieIface"
if [ "$activeFp" = true ]; then LOG red "MODE: ACTIVE fingerprinting ON (will connect to nearby devices)"; else LOG green "MODE: passive only (activeFp=false)"; fi

bgCollector & colPid=$!
[ "$liveIe" = true ] && [ -n "$ieIface" ] && { bgFpcap & fpcapPid=$!; }
menu

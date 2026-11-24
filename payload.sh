#!/bin/bash
# Title: SlipperyPickle
# Author: SlipperyPickle contributors
# Version: 20261122-rc1
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
#   - 802.11 IE fingerprint (Stage 2, live wlan0mon)    F: token         [Vanhoef'16/Martin'17]
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
#   NOT implemented (hardware limit, documented for completeness):
#     - BLE PHY-layer RF fingerprint ... Givehchian 2022 (IEEE S&P) - needs an SDR, not commodity radios
#     - AWDL / AirDrop identity leaks .. Stute 2019 (USENIX Sec) - needs an AWDL channel-hopping sniff
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
#     Start scan | Take snapshot | Compare snapshots | Stop & exit |
#     Active mode: OFF/ON (toggle) | Probe BT device (ACTIVE, only when active mode is on)
#   In the live radar:  RED = back to menu    GREEN = device identifiers for a picked MAC
#
# LED: Blue=idle  Amber=processing/compare  Green=ok/snapshot  Red=recurring-device hit/err
#

# ============================================================
# CONFIG
# ============================================================
version="20261122-rc1"               # shown on the radar's top line so you can see which build is live
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
xcorrCap=8                 # max cross-radio candidate pairs reported (ranked tightest-RSSI first)
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

vibrate() { local n="${1:-1}" i=0; while [ "$i" -lt "$n" ]; do
    echo 1 >/sys/class/gpio/vibrator/value 2>/dev/null; sleep 0.15
    echo 0 >/sys/class/gpio/vibrator/value 2>/dev/null; sleep 0.1; i=$((i+1)); done; }

cleanup() {
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
ieIface=""                                         # chosen at startup: the monitor iface that is UP
colPid=""; renPid=""; scanloopPid=""; fpcapPid=""

# Background: feed WiFi (recon.db) + BT (blue5.db) observations into $obs.
# Both radios are read from the two recon daemons' own sqlite DBs - we never scan. The heavy
# A naive shell OUI lookup (grep a 40k-line file per device, every pass) was far too slow on
# the WiFi Pineapple CPU. Instead a single PERSISTENT awk coprocess loads the OUI table into
# memory ONCE, then transforms each pass's sqlite rows from its stdin in-memory (no per-device
# forks). We just pipe "W|time|mac|signal|freq" and "B|last_seen|mac|rssi|company|name" lines
# to it and it appends decoded rows to $obs. See $collectorAwk (written at startup).
bgCollector() {
    local now cut
    coproc awkCo { awk -v OUIFILE="$ouiFile" -v OBS="$obs" -f "$collectorAwk"; }
    while :; do
        now=$(date +%s); cut=$((now - stale))
        {
          [ "$liveWifi" = true ] && timeout 5 sqlite3 -separator '|' "$reconDb" \
            "SELECT 'W', max(time), mac, signal, freq FROM wifi_device WHERE time>=$cut GROUP BY mac;" 2>/dev/null
          [ "$liveBle" = true ] && [ -f "$blue5Db" ] && timeout 5 sqlite3 -separator '|' "$blue5Db" \
            "SELECT 'B', max(last_seen), mac, rssi, company, replace(replace(replace(CAST(name AS TEXT),char(10),' '),char(13),' '),'|','/') FROM bt_device WHERE last_seen>=$cut GROUP BY mac;" 2>/dev/null
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
            printf "%03d|%s|%s|%s|%s\n", k, r, $2, $4, lbl }' \
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
            case "$src" in WIFI*|PINEAP*) tag=W;; BLE*|BTC*) tag=B;; *) tag="?";; esac
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
            case "$src" in WIFI*|PINEAP*) tag=W;; BLE*|BTC*) tag=B;; *) tag="?";; esac
            LOG "$(printf '%4s %s %s %s %s' "$disp" "$bar" "$tag" "${mac: -8}" "${lbl:0:10}")"
        done <<RENDEREOF2
$rows
RENDEREOF2
        sleep "$renderEvery"
    done
}

# GREEN: save current live set as an ENRICHED snapshot, then wipe the list.
# Record = SRC|MAC|RND|VENDOR|FP|PROBES|BLECO|BLENAME|MODEL|HOST|OS|RSSI
# Enrichment (all best-effort, snapshot-time only - never in the hot radar loop):
#   PROBES = probed-SSID set (PNL) joined from recon.db  -> survives WiFi MAC rotation
#   RND    = randomized? (WiFi: locally-administered bit; BT: blue5 le_random flag)
#   MODEL  = device type decoded from blue5 mfr/svcd (Apple Continuity type, FastPair, ...)
#   HOST   = DHCP hostname (only devices on OUR AP)
#   FP     = 802.11 IE fingerprint from $iefp (WiFi, Stage 2)
snapshotAndClear() {
    snapCount=$((snapCount+1))
    out=$(printf '%s/snap_%02d.raw' "$sessionDir" "$snapCount")
    local now cutoff base pnl bt lease ie
    now=$(date +%s); cutoff=$((now - stale))
    base="/tmp/sp_b.$$"; pnl="/tmp/sp_p.$$"; bt="/tmp/sp_t.$$"; lease="/tmp/sp_l.$$"; ie="/tmp/sp_i.$$"
    : > "$pnl"; : > "$bt"; : > "$lease"; : > "$ie"
    # base: live set deduped (latest per mac) -> tagged "D"
    awk -F'|' -v cut="$cutoff" '$1+0>=cut && $2!="" {print}' "$obs" \
      | sort -t'|' -k2,2 -k1,1nr \
      | awk -F'|' '!seen[$2]++ { k=toupper($2); gsub(/:/,"",k); print "D\t" k "\t" $4 "\t" $2 "\t" $3 "\t" $5 "\t" $6 "\t" $7 }' > "$base"
    # PNL (probed-SSID set per client MAC) from recon.db
    [ "$liveWifi" = true ] && timeout 8 sqlite3 -separator '|' "$reconDb" \
      "SELECT upper(w.mac), replace(group_concat(DISTINCT CAST(s.ssid AS TEXT)),'|','/') FROM ssid s JOIN wifi_device w ON s.wifi_device=w.hash WHERE CAST(s.ssid AS TEXT)<>'' GROUP BY w.mac;" 2>/dev/null \
      | awk -F'|' '{k=$1; gsub(/:/,"",k); g=$2; gsub(/,/,";",g); print "P\t" toupper(k) "\t" g}' > "$pnl"
    # BT enrich (le_random + raw mfr/svcd) from blue5.db
    [ "$liveBle" = true ] && [ -f "$blue5Db" ] && timeout 8 sqlite3 -separator '|' "$blue5Db" \
      "SELECT upper(mac), max(le_random), hex(mfr), hex(svcd) FROM bt_device WHERE last_seen>=$cutoff GROUP BY mac;" 2>/dev/null \
      | awk -F'|' '{k=$1; gsub(/:/,"",k); print "B\t" toupper(k) "\t" $2 "\t" $3 "\t" $4}' > "$bt"
    # DHCP hostnames (devices that joined our AP)
    [ -f "$leases" ] && awk '{m=$2; gsub(/:/,"",m); h=$4; if(h=="*")h=""; if(m!="")print "H\t" toupper(m) "\t" h}' "$leases" > "$lease"
    # IE fingerprints (dedup latest per mac)
    [ -f "$iefp" ] && awk -F'|' '{fp[$1]=$2} END{for(m in fp) print "F\t" m "\t" fp[m]}' "$iefp" > "$ie"
    # merge: maps first (fill arrays), then "D" rows emit the 12-field record
    cat "$pnl" "$bt" "$lease" "$ie" "$base" | awk -f "$snapAwk" > "$out"
    rm -f "$base" "$pnl" "$bt" "$lease" "$ie"
    local c; c=$(wc -l < "$out")
    : > "$obs"
    LED GREEN; vibrate 1
    LOG green ">>> Snapshot #$snapCount saved ($c devices). List cleared."
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
    # tokens that survive MAC rotation: H:hostname  B:company:name  F:IE-fingerprint
    # M:stable-MAC (WiFi global bit / BT le_random=0), plus PNL rare-SSID union (devices
    # that probe the same uncommon SSID set are linked even across rotated MACs - Martin
    # 2017) and a mutual-nearest-neighbour cross-radio pass (Longo 2018). See $cmpAwk.
    awk -F'|' -v TH="$matchThreshold" -v NS="$snapCount" -v TOL="$rssiTol" \
        -v XMIN="$xcorrMin" -v CMN="$pnlCommon" -v XCAP="$xcorrCap" \
        -f "$cmpAwk" "$master" > "${master}.out"

    local flagged xcount TAB; TAB=$(printf '\t')
    flagged=$(grep -m1 '^FLAGGED' "${master}.out" | awk '{print $2}')
    xcount=$(grep -m1 '^CROSS' "${master}.out" | awk '{print $2}')
    {
        echo "=== SlipperyPickle identity correlation ==="
        echo "Session   : $sessionDir"
        echo "Date      : $(date)"
        echo "Snapshots : $snapCount   Thresh: $matchThreshold   RSSI tol: ${rssiTol}dBm"
        echo
        echo "-- Recurring identities (same radio, >= $matchThreshold snaps) --"
        printf '%-7s %-24s %-7s %-5s %s\n' "SEEN" "IDENTITY" "OS" "RADIO" "MAC"
        echo "---------------------------------------------------------------------"
        grep '^f' "${master}.out" | cut -f2- | while IFS="$TAB" read -r sn lbl os rd mc; do
            printf '%-7s %-24s %-7s %-5s %s\n' "$sn" "${lbl:0:24}" "${os:0:7}" "$rd" "$mc"
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
    rm -f "$master" "${master}.out"

    if [ -n "$flagged" ] && [ "$flagged" -gt 0 ]; then
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
    pnl2=$(timeout 6 sqlite3 "$reconDb" "SELECT group_concat(DISTINCT CAST(s.ssid AS TEXT)) FROM ssid s JOIN wifi_device w ON s.wifi_device=w.hash WHERE upper(replace(w.mac,':',''))='$nkey' AND CAST(s.ssid AS TEXT)<>'';" 2>/dev/null)
    # BT: le_random (trackable?) + device type from Continuity/service data
    btrow=$(timeout 6 sqlite3 -separator '|' "$blue5Db" "SELECT max(le_random), upper(hex(mfr)), upper(hex(svcd)) FROM bt_device WHERE upper(mac)='$nkey';" 2>/dev/null)
    if [ -n "$btrow" ]; then
        lerand2=$(printf '%s' "$btrow" | cut -d'|' -f1)
        dtype2=$(printf '%s' "$btrow" | awk -F'|' '{m=$2;s=$3;
            if(substr(m,1,4)=="4C00"){t=substr(m,5,2);
              if(t=="07")print "AirPods/accessory"; else if(t=="10")print "iPhone/Nearby";
              else if(t=="12")print "iDevice/FindMy"; else if(t=="0C")print "Handoff";
              else if(t=="05")print "AirDrop"; else if(t=="02")print "iBeacon"; else print "Apple"}
            else if(substr(m,1,4)=="7500")print "Samsung";
            else if(substr(m,1,4)=="027D")print "Huawei";
            else if(substr(m,1,4)=="8F03")print "Xiaomi";
            else if(s ~ /FE95|95FE/)print "Xiaomi/Mi (MIoT)";
            else if(s ~ /FE2C|2CFE/)print "Google FastPair";
            else if(s ~ /FD5A|5AFD/)print "Samsung svc"; }')
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
        case "$src" in WIFI*|PINEAP*) tag=W;; BLE*|BTC*) tag=B;; *) tag="?";; esac
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
        case "$src" in BLE*|BTC*) ;; *) continue;; esac
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
    LOG red "ACTIVE mode ON - 'Probe BT device' is now in the menu."
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
            choice=$(LIST_PICKER "Main Menu" "Start scan" "Take snapshot" "Compare snapshots" "Stop & exit" "$modeItem" "$extra" "Start scan")
        else
            choice=$(LIST_PICKER "Main Menu" "Start scan" "Take snapshot" "Compare snapshots" "Stop & exit" "$modeItem" "Start scan")
        fi
        [ $? -ne 0 ] && continue
        case "$choice" in
            "Start scan")                 radar ;;
            "Take snapshot")              snapshotAndClear ;;
            "Compare snapshots")          doCompare ;;
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
: > "$obs"; rm -f "$pause"

cleanupLive() {
    kill "$colPid" "$renPid" "$scanloopPid" "$fpcapPid" 2>/dev/null
    # stop the resident collector + fp-parser awks (killing the parent closes their stdin so
    # they EOF, but match by name too so a stray never leaks an OUI/parser awk across relaunches).
    for p in $(ps w 2>/dev/null | grep -E '[s]lipperypickle_(collector|fp).awk' | awk '{print $1}'); do
        kill "$p" 2>/dev/null
    done
    killall tcpdump 2>/dev/null           # the Stage-2 IE sniffer
    rm -f "$pause" "$obs" "$obs.t" "$collectorAwk" "$fpcapAwk" "$snapAwk" "$cmpAwk" "$iefp" "$seqf" \
          /tmp/sp_b.* /tmp/sp_p.* /tmp/sp_t.* /tmp/sp_l.* /tmp/sp_i.* 2>/dev/null
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
$1=="B"{ m=normmac($3); if(m==""){next} v=oui[substr(m,1,8)]; s=($4==""?"-99":$4); co=($5 in comp)?comp[$5]:""; nm=$6; gsub(/\|/,"",nm); print $2"|"m"|"s"|BLE|"v"|"co"|"nm"|" >> OBS; lc++; next }
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
# read first, then each live device row "D" emits the 12-field snapshot record.
cat > "$snapAwk" <<'SNEOF'
function devtype(mfr,svcd,  t){
  mfr=toupper(mfr); svcd=toupper(svcd)
  if(substr(mfr,1,4)=="4C00"){ t=substr(mfr,5,2)
    if(t=="02")return "AppleBeacon"; if(t=="05")return "AirDrop"; if(t=="07")return "AirPods"
    if(t=="09"||t=="0A")return "AirPlay"; if(t=="0C")return "Handoff"
    if(t=="0F")return "NearbyAction"; if(t=="10")return "iPhone/Nearby"; if(t=="12")return "iDevice/FindMy"
    return "Apple" }
  if(substr(mfr,1,4)=="7500") return "Samsung"
  if(substr(mfr,1,4)=="0600") return "Microsoft"
  if(substr(mfr,1,4)=="027D"||substr(mfr,1,4)=="7D02") return "Huawei"
  if(substr(mfr,1,4)=="8F03"||substr(mfr,1,4)=="038F") return "Xiaomi"
  if(svcd ~ /FE95/ || svcd ~ /95FE/) return "Xiaomi/Mi"
  if(svcd ~ /2CFE/ || svcd ~ /FE2C/) return "FastPair"
  if(svcd ~ /6FFD/ || svcd ~ /FD6F/) return "ExposureNotif"
  if(svcd ~ /AAFE/ || svcd ~ /FEAA/) return "Eddystone"
  if(svcd ~ /5AFD/ || svcd ~ /FD5A/) return "Samsung"
  return ""
}
function osfam(ven,bleco,model){
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
$1=="B"{ ler[$2]=$3; mfrm[$2]=$4; svcm[$2]=$5; next }
$1=="H"{ if($3!="") host[$2]=$3; next }
$1=="F"{ fpm[$2]=$3; next }
$1=="D"{
  key=$2; src=$3; mac=$4; rssi=$5; ven=$6; bleco=$7; blen=$8
  isble=(src ~ /BLE|BTC/)
  if(isble){ rnd=(ler[key]==""?0:(ler[key]+0)) } else { rnd=(substr(toupper(mac),2,1) ~ /[2367ABEF]/)?1:0 }
  model=devtype(mfrm[key],svcm[key]); os=osfam(ven,bleco,model)
  fp=(isble?"":fpm[key])
  printf "%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s\n", src, mac, rnd, ven, fp, pnl[key], bleco, blen, model, host[key], os, rssi
}
SNEOF

# Identity correlation (union-find + PNL rare-SSID union + mutual-NN cross-radio).
cat > "$cmpAwk" <<'CMEOF'
BEGIN{FS="|"}
function find(x,  r){ r=x; while(par[r]!=r && par[r]!="") r=par[r];
                      while(par[x]!=r && par[x]!=""){ n=par[x]; par[x]=r; x=n } return r }
function uni(a,b,  ra,rb){ if(a==""||b=="")return; if(!(a in par))par[a]=a;
                      if(!(b in par))par[b]=b; ra=find(a); rb=find(b); if(ra!=rb)par[rb]=ra }
function tok(x){ if(x==""||x=="?")return ""; if(!(x in par))par[x]=x; return x }
{
  snap=$1+0; src=$2; mac=$3; rnd=$4; ven=$5; fp=$6; probes=$7;
  bleco=$8; blen=$9; model=$10; host=$11; os=$12; rssi=$13;
  radio="WIFI"; if(src ~ /BLE|BTC/) radio="BLE";
  delete T; nt=0;
  if(host!=""  && host!="*")                 T[++nt]="H:" tolower(host);
  if(bleco!="" && blen!="")                   T[++nt]="B:" bleco ":" tolower(blen);
  if(fp!="")                                  T[++nt]="F:" fp;
  if(mac!="" && rnd=="0")                      T[++nt]="M:" mac;
  for(i=1;i<=nt;i++){ tok(T[i]); if(i>1) uni(T[1],T[i]) }
  if(nt>0) anchor=T[1];
  else { anchor="W:" src ":" mac; tok(anchor) }
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
  if(probes!="" && !(key in ev_pnl)) ev_pnl[key]=probes;
  if(mac!="")  ev_macs[key]=ev_macs[key] (index(" " ev_macs[key] " ", " " mac " ")?"":(ev_macs[key]==""?"":" ") mac);
  allkeys[key]=1;
}
END{
  for(s in scount){ if(scount[s]>=2 && scount[s]<=CMN){
     n=split(sanch[s], AA, SUBSEP); base="";
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
    if(ev_pnl[k]!="" && !(r in R_pnl)) R_pnl[r]=ev_pnl[k];
    if(ev_macs[k]!="")  R_macs[r]=R_macs[r] (R_macs[r]==""?"":" ") ev_macs[k];
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
    R_lbl[r]=lbl; R_m1[r]=mm[1];
  }
  n=0; for(r in roots){ if(cnt[r]>=TH) ord[++n]=r }
  for(i=1;i<=n;i++)for(j=i+1;j<=n;j++) if(cnt[ord[j]]>cnt[ord[i]]){t=ord[i];ord[i]=ord[j];ord[j]=t}
  printf("FLAGGED %d\n", n);
  for(i=1;i<=n;i++){ r=ord[i];
    printf("f\t%d/%d\t%s\t%s\t%s\t%s\n", cnt[r], NS, R_lbl[r],
           (R_os[r]!=""?R_os[r]:"-"), (Rrad[r]!=""?Rrad[r]:"-"), R_m1[r]);
  }
  nw=0; nb=0;
  for(r in roots){ if(cnt[r]<XMIN) continue;
     if(Rrad[r]=="WIFI") warr[++nw]=r;
     else if(Rrad[r]=="BLE") barr[++nb]=r }
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
[ "$liveIe" = true ] && [ -n "$ieIface" ] && LOG "IE fingerprint: $ieIface"
if [ "$activeFp" = true ]; then LOG red "MODE: ACTIVE fingerprinting ON (will connect to nearby devices)"; else LOG green "MODE: passive only (activeFp=false)"; fi

bgCollector & colPid=$!
[ "$liveIe" = true ] && [ -n "$ieIface" ] && { bgFpcap & fpcapPid=$!; }
menu

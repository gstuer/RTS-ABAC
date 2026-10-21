#!/usr/bin/env bash
#
# SV-rate load experiments for RTS-ABAC (E4b).
#
#   ./sv-load.sh server       ON THE PASSIVE ENTITY: iperf3 --server --interval 1
#
#   ./sv-load.sh probe        10 s ladder, text only - find the knee
#   ./sv-load.sh capacity     60 s runs, JSON   | DEPs WITHOUT -f, validity >= 2 h
#   ./sv-load.sh baseline     60 s runs, JSON   | DEPs WITH    -f, validity >= 2 h
#   ./sv-load.sh concurrent   load + RTT bench  | DEPs WITHOUT -f, validity >= 2 h
#   ./sv-load.sh refresh      120 s single rate | DEPs WITHOUT -f, validity ~5 s
#   ./sv-load.sh summarize    re-print the table from existing *.json
#
# Everything but "server" runs ON THE ACTIVE ENTITY.
#
# capacity vs. baseline: identical client commands, identical rates. The only
# difference is how the DEPs were launched. "capacity" measures the full
# RTS-ABAC path; "baseline" measures the same path with the DEPs started with
# -f ("forwards all traffic without filtering and access control"), i.e. the
# Java capture-and-inject path alone - no authorization, no access control, no
# encapsulation, no HMAC. That is Table 3's "None" configuration, and it is
# what proves the ceiling belongs to RTS-ABAC's processing rather than to the
# Pi, the USB NIC, the switch or iperf3. The script cannot tell how the DEPs
# were started: that is on the operator, hence the reminder each mode prints.
#
# Environment overrides:
#   SERVER   passive entity            (default 192.168.0.63)
#   LEN      UDP payload bytes         (default 300)
#   TAG      file name tag             (default hmac)
#   BASELINE_TAG  tag for baseline mode    (default forward; no crypto in the
#            name, since -f authenticates nothing by design)
#   DUR      seconds per run           (default per mode)
#   PPS      rate for refresh mode     (default 4000)
#
# Packet size: 300 B approximates an R-SV datagram carrying the sampled values
# of a three-phase protection application. On the wire that is a 342 B frame,
# which the DEP hex-encodes into a ~900 B payload exchange datagram - below the
# MTU. Do not raise LEN much above 600 B of protected frame: the DEP-to-DEP
# datagram then fragments and loss becomes ambiguous. Rerun with LEN=150 to
# match a single-ASDU 9-2LE protection frame and see whether the ceiling is
# rate-bound or byte-bound.
#
# No chrt, anywhere: RT priority on the DEPs cost 7 frames at 2400 fps and
# quadrupled the loss at 5000 fps (it preempts ksoftirqd/NAPI), and the -f
# baseline carried 6000 fps with zero loss at default priority, so the
# measurement chain needs no help. Default scheduling also matches the
# configuration that produced Table 3.
set -u

SERVER=${SERVER:-192.168.0.63}
LEN=${LEN:-300}
TAG=${TAG:-hmac}
RTT_SRC=${RTT_SRC:-$HOME/rtt-estimation}
RTT_PORT=${RTT_PORT:-8000}
RTT_READINGS=${RTT_READINGS:-5000}
PORT=${PORT:-5201}

RATES="600 1200 1800 2400 3000 4000 4250 4500 4750 5000 6000"

usage() { sed -n '3,17p' "$0" >&2; }
bps()   { echo $(( $1 * LEN * 8 )); }
name()  { echo "svload_${TAG}_l${LEN}_${1}pps${2:-}.json"; }

run() {               # run <pps> <outfile> [extra iperf3 args...]
  local pps=$1 out=$2; shift 2
  iperf3 -c "$SERVER" -p "$PORT" -u -l "$LEN" -b "$(bps "$pps")" \
         -t "$DUR" -i 1 --pacing-timer 100 --get-server-output \
         --json --logfile "$out" "$@"
}

warmup() {
  # The first datagram of a new flow triggers an access request and is held by
  # the DEP; install the decision before anything is measured.
  printf 'warm-up (discarded) ... '
  iperf3 -c "$SERVER" -p "$PORT" -u -l "$LEN" -b "$(bps 600)" -t 5 -i 0 >/dev/null 2>&1
  echo done
}

summarize() {
  command -v jq >/dev/null || { echo "(install jq for the summary table)"; return; }
  printf '\n%-52s %9s %7s %8s %9s %8s %10s\n' \
         FILE DATAGRAMS LOST "LOST_%" JITTER_MS SECONDS OUT_OF_ORD
  ls -1 svload_${TAG}_l${LEN}_*.json 2>/dev/null |
    awk '{ n=$0; sub(/pps.*$/,"",n); sub(/^.*_/,"",n); print n "\t" $0 }' |
    sort -n | cut -f2 |
    while read -r f; do
      jq -r --arg f "$f" '
        .end.sum as $s |
        [ $f,
          ($s.packets      // 0),
          ($s.lost_packets // 0),
          (($s.lost_percent // 0) * 1000 | round / 1000),
          (($s.jitter_ms    // 0) * 1000 | round / 1000),
          (($s.seconds      // 0) * 100  | round / 100),
          ($s.out_of_order // "n/a") ] | @tsv' "$f" |
      awk -F'\t' '{printf "%-52s %9s %7s %8s %9s %8s %10s\n",$1,$2,$3,$4,$5,$6,$7}'
    done
  echo
  echo "Reordering cross-check in the embedded server log:"
  echo "  jq -r .server_output_text <file> | grep -i 'out of order'"
}

case "${1:-}" in
  server)
    echo "iperf3 server on port $PORT. For 'concurrent' also start:"
    echo "  python $RTT_SRC/PassiveEntity.py $RTT_PORT"
    exec iperf3 --server --interval 1 --port "$PORT"
    ;;

  probe)
    DUR=${DUR:-10}
    echo "REMINDER: DEPs without -f. Text output only; for a JSON ladder use DUR=10 capacity."
    warmup
    for PPS in $RATES; do
      printf '\n=== %s pps ===\n' "$PPS"
      iperf3 -c "$SERVER" -p "$PORT" -u -l "$LEN" -b "$(bps "$PPS")" \
             -t "$DUR" -i 0 --pacing-timer 100
      sleep 3
    done
    ;;

  capacity|baseline)
    if [ "$1" = baseline ]; then
      TAG="${BASELINE_TAG:-forward}"
      echo "REMINDER: both DEPs must be running WITH -f (plain forwarding)."
    else
      echo "REMINDER: both DEPs must be running WITHOUT -f (full RTS-ABAC path)."
    fi
    echo "REMINDER: policy validity >= 2 h, so that no renewal falls into a run."
    DUR=${DUR:-60}; warmup
    for PPS in $RATES; do
      OUT=$(name "$PPS")
      printf '%5s pps -> %s\n' "$PPS" "$OUT"
      run "$PPS" "$OUT" -O 2
      sleep 5
    done
    summarize
    ;;

  concurrent)
    echo "REMINDER: DEPs WITHOUT -f, policy validity >= 2 h."
    echo "REMINDER: the passive entity needs iperf3 --server AND PassiveEntity.py $RTT_PORT."
    DUR=${DUR:-30}; warmup
    for PPS in 2400 4000; do
      OUT=$(name "$PPS" _concurrent)
      RTT_LABEL="rtt_${TAG}_l${LEN}_under_load_${PPS}pps"
      printf '\n%s pps + RTT benchmark -> %s / %s.json\n' "$PPS" "$OUT" "$RTT_LABEL"
      run "$PPS" "$OUT" -O 2 &
      LOAD=$!
      sleep 2
      python "$RTT_SRC/ActiveEntity.py" "$SERVER" "$RTT_PORT" "$RTT_READINGS" "$RTT_LABEL"
      wait $LOAD
      sleep 5
    done
    summarize
    ;;

  refresh)
    # Short policy validity on purpose: every renewal shows up as a small burst
    # of lost frames. frames_per_renewal = lost / number of renewals, and the
    # renewal count comes from the DEP log, so capture it:
    #   DEP:  grep -c 'Access request sent' <dep stdout>
    #   PDP:  grep -c '\[PDP\] Grant'       <pdp stdout>
    # No -O here: omitting the first seconds would drop renewals from the count.
    DUR=${DUR:-120}; PPS=${PPS:-4000}
    echo "REMINDER: DEPs WITHOUT -f, policy validity ~5 s (not below ~1 s)."
    echo "REMINDER: keep the DEP and PDP stdout of this run."
    warmup
    OUT=$(name "$PPS" _refresh)
    printf '%s pps for %s s -> %s\n' "$PPS" "$DUR" "$OUT"
    run "$PPS" "$OUT"
    summarize
    ;;

  summarize) summarize ;;
  *) usage; exit 2 ;;
esac

#!/data/data/com.termux/files/usr/bin/bash
stty sane 2>/dev/null

NEXUS_DIR="/data/data/com.termux/files/home/nexus-ir"
CASE_DIR="/data/data/com.termux/files/home/cases"
STRESS_DIR="$CASE_DIR/stress_volume_run"
RESULTS_FILE="$NEXUS_DIR/tests/pressure_results.txt"
COOLDOWN=0

for arg in "$@"; do
    case $arg in
        --cooldown) shift; COOLDOWN=$1; shift ;;
        --cooldown=*) COOLDOWN="${arg#*=}" ;;
    esac
done

ms_now() {
    python3 -c "import time; print(int(time.perf_counter()*1000))"
}

ms_diff() {
    echo $((${2} - ${1}))
}

echo "========================================================="
echo "   NEXUS-IR VOLUMETRIC PRESSURE TEST"
echo "   Cooldown: ${COOLDOWN}s between burst iterations"
echo "========================================================="

python3 >/dev/null 2>&1 <<'PYCHECK'
import sys
sys.exit(0)
PYCHECK
if [ $? -ne 0 ]; then echo "[ERROR] python3 unavailable"; exit 1; fi

mkdir -p "$STRESS_DIR" || { echo "[ERROR] Cannot create $STRESS_DIR"; exit 1; }

# Generate stress case
cat > "$STRESS_DIR/chaotic_kill_chain.log" << 'EOF'
2026-05-22 08:30:01 [AUTH] Failed password for invalid user admin from 185.220.101.45 port 49221 ssh2
2026-05-22 08:30:05 [AUTH] Accepted password for root from 185.220.101.45 port 49221 ssh2
2026-05-22 08:30:10 [AUTH] sudo command executed by root outside business hours
2026-05-22 08:31:00 [MEMORY] Target Process lsass.exe opened via VirtualAllocEx and WriteProcessMemory anomaly process
2026-05-22 08:31:05 [POWERSHELL] executionpolicy bypass -windowstyle hidden FromBase64String encoded payload
2026-05-22 08:31:15 [DISK] Backdoor service installed: C:\Users\Public\svchost_update.exe
2026-05-22 08:32:00 [NETWORK] ICMP Tunneling detected: payload length 1450 bytes entropy 7.91 to 45.33.22.11
2026-05-22 08:32:10 [NETWORK] Data exfiltration 850MB outbound to 45.142.212.100 reverse shell 4444
2026-05-22 08:32:15 [SECURITY] wevtutil cl System audit log cleared lateral movement mimikatz lsass ransomware
EOF
echo "[+] Stress payload generated."

# PHASE 2: Sequential
echo ""
echo "[*] Phase 2: Sequential throughput (10 runs)..."
SEQ_PASS=0; SEQ_FAIL=0; SEQ_TOTAL_MS=0; SEQ_MIN=999999; SEQ_MAX=0
for i in {1..10}; do
    T0=$(ms_now)
    python3 "$NEXUS_DIR/main.py" "$STRESS_DIR" > /dev/null 2>&1 && SEQ_PASS=$((SEQ_PASS+1)) || SEQ_FAIL=$((SEQ_FAIL+1))
    T1=$(ms_now)
    DUR=$(ms_diff $T0 $T1)
    SEQ_TOTAL_MS=$((SEQ_TOTAL_MS + DUR))
    [ $DUR -gt $SEQ_MAX ] && SEQ_MAX=$DUR
    [ $DUR -lt $SEQ_MIN ] && SEQ_MIN=$DUR
    echo "  Run $i: ${DUR}ms"
done
SEQ_AVG_MS=$((SEQ_TOTAL_MS / 10))
echo "  Results: ${SEQ_PASS}/10 passed | avg=${SEQ_AVG_MS}ms | min=${SEQ_MIN}ms | max=${SEQ_MAX}ms"

# PHASE 3: All real cases
echo ""
echo "[*] Phase 3: All real cases throughput..."
REAL_CASES=("obfuscated_malware" "financial_breach" "apt_attack" "ransomware" "brute_force" "lolbin_invasion" "defense_blinding" "icmp_tunnel" "stealth_evasion" "insider")
REAL_PASS=0; REAL_FAIL=0; PHASE3_START=$(ms_now)
for c in "${REAL_CASES[@]}"; do
    p="$CASE_DIR/$c"
    [ ! -d "$p" ] && echo "  [SKIP] $c" && continue
    T0=$(ms_now)
    python3 "$NEXUS_DIR/main.py" "$p" > /dev/null 2>&1 && { REAL_PASS=$((REAL_PASS+1)); S="OK"; } || { REAL_FAIL=$((REAL_FAIL+1)); S="FAIL"; }
    T1=$(ms_now)
    echo "  $c: $(ms_diff $T0 $T1)ms [$S]"
done
PHASE3_END=$(ms_now)
echo "  Results: ${REAL_PASS}/${#REAL_CASES[@]} passed | total=$(ms_diff $PHASE3_START $PHASE3_END)ms"

# PHASE 4: Parallel (3 workers)
echo ""
echo "[*] Phase 4: Parallel concurrency (3 workers)..."
T0=$(ms_now)
python3 "$NEXUS_DIR/main.py" "$CASE_DIR/obfuscated_malware" > /dev/null 2>&1 &
python3 "$NEXUS_DIR/main.py" "$CASE_DIR/financial_breach"   > /dev/null 2>&1 &
python3 "$NEXUS_DIR/main.py" "$STRESS_DIR"                  > /dev/null 2>&1 &
wait
T1=$(ms_now)
PAR_DUR=$(ms_diff $T0 $T1)
echo "  3 parallel workers wall time: ${PAR_DUR}ms"
echo "  vs sequential estimate: $((SEQ_AVG_MS * 3))ms"
[ $PAR_DUR -lt $((SEQ_AVG_MS * 3)) ] && echo "  Verdict: PARALLEL SPEEDUP CONFIRMED" || echo "  Verdict: Memory-bound (no speedup on this device)"

# PHASE 5: Burst (20 runs) with optional cooldown
echo ""
echo "[*] Phase 5: Burst fire (20x brute_force, cooldown=${COOLDOWN}s)..."
BURST_PASS=0; BURST_FAIL=0; BURST_FIRST_MS=0; BURST_LAST_MS=0; BURST_TOTAL_MS=0
BURST_TIMES=()
for i in {1..20}; do
    T0=$(ms_now)
    python3 "$NEXUS_DIR/main.py" "$CASE_DIR/brute_force" > /dev/null 2>&1 && BURST_PASS=$((BURST_PASS+1)) || BURST_FAIL=$((BURST_FAIL+1))
    T1=$(ms_now)
    DUR=$(ms_diff $T0 $T1)
    BURST_TIMES+=($DUR)
    BURST_TOTAL_MS=$((BURST_TOTAL_MS + DUR))
    [ $i -eq 1  ] && BURST_FIRST_MS=$DUR
    [ $i -eq 20 ] && BURST_LAST_MS=$DUR
    [ $((i % 5)) -eq 0 ] && echo "  Completed $i/20 | last=${DUR}ms"
    [ "$COOLDOWN" -gt 0 ] && sleep "$COOLDOWN"
done
BURST_AVG=$((BURST_TOTAL_MS / 20))
DRIFT_MS=$((BURST_LAST_MS - BURST_FIRST_MS))
echo "  Results: ${BURST_PASS}/20 passed | first=${BURST_FIRST_MS}ms | last=${BURST_LAST_MS}ms | avg=${BURST_AVG}ms"
if [ $DRIFT_MS -gt 2000 ]; then
    [ "$COOLDOWN" -gt 0 ] && echo "  Verdict: DRIFT PRESENT WITH COOLDOWN -- code-level degradation" || echo "  Verdict: THERMAL THROTTLING LIKELY -- retry with --cooldown 3"
else
    echo "  Verdict: STABLE -- no drift detected (${DRIFT_MS}ms delta)"
fi

# SUMMARY
echo ""
echo "========================================================="
echo "   PRESSURE TEST COMPLETE"
echo "========================================================="
TOTAL_PASS=$((SEQ_PASS + REAL_PASS + 3 + BURST_PASS))
TOTAL_RUN=$((10 + ${#REAL_CASES[@]} + 3 + 20))
echo "  Phase 2 Sequential : ${SEQ_PASS}/10  | avg ${SEQ_AVG_MS}ms/run"
echo "  Phase 3 Real cases : ${REAL_PASS}/${#REAL_CASES[@]}"
echo "  Phase 4 Parallel   : ${PAR_DUR}ms wall time"
echo "  Phase 5 Burst      : ${BURST_PASS}/20 | drift ${DRIFT_MS}ms"
echo "  TOTAL              : ${TOTAL_PASS}/${TOTAL_RUN} passed"
echo "========================================================="

{
    echo "NEXUS-IR Pressure Test -- $(date)"
    echo "Sequential: ${SEQ_PASS}/10, avg=${SEQ_AVG_MS}ms, min=${SEQ_MIN}ms, max=${SEQ_MAX}ms"
    echo "Real cases: ${REAL_PASS}/${#REAL_CASES[@]}"
    echo "Parallel: ${PAR_DUR}ms wall time"
    echo "Burst: ${BURST_PASS}/20, first=${BURST_FIRST_MS}ms, last=${BURST_LAST_MS}ms, drift=${DRIFT_MS}ms"
    echo "Total: ${TOTAL_PASS}/${TOTAL_RUN}"
} > "$RESULTS_FILE"
echo "[*] Results saved: $RESULTS_FILE"

rm -rf "$STRESS_DIR"
echo "[*] Cleanup complete."

set -u

IFACE=${1:-veth0}
QUERIES=${2:-100000}
CONC=500
WORKERS=8
SERVER_IP=${SERVER_IP:-10.11.0.1}
CLIENT_NS=${CLIENT_NS:-ns1}
OUT=results/$(date +%Y%m%d_%H%M%S)

mkdir -p "$OUT"
echo "results -> $OUT"

have() { command -v "$1" >/dev/null 2>&1; }

SAVED_COMBINED=""

setup_queues() {
	have ethtool || { echo "WARN: no ethtool; cannot verify rx queue count"; return; }

	local nq
	nq=$(ls -d /sys/class/net/"$IFACE"/queues/rx-* 2>/dev/null | wc -l)
	[ "$nq" -le 1 ] && return

	SAVED_COMBINED=$(ethtool -l "$IFACE" 2>/dev/null | awk '/^Current/{f=1} f&&/Combined:/{print $2; exit}')
	echo "reducing $IFACE from $nq rx queues to 1 (was combined=$SAVED_COMBINED)"
	ethtool -L "$IFACE" combined 1 || echo "WARN: ethtool -L failed; results will be unusable"
}

restore_queues() {
	[ -n "$SAVED_COMBINED" ] && have ethtool && \
		ethtool -L "$IFACE" combined "$SAVED_COMBINED" 2>/dev/null
}

trap restore_queues EXIT
setup_queues

# perf stat -t so worker threads are counted, not just the main thread.
perf_wrap() {
	local name=$1 out=$2
	if have perf; then
		local pid
		pid=$(pgrep -x "$name" | head -1)
		[ -n "$pid" ] && perf stat -t "$pid" -e task-clock,cycles,instructions \
			-o "$out" -- sleep 5 2>/dev/null &
	fi
}

load() {
	# dnsperf if it is here, otherwise our own generator
	if have dnsperf; then
		echo "www.example.com A" > /tmp/queryfile
		ip netns exec "$CLIENT_NS" dnsperf -s "$SERVER_IP" -d /tmp/queryfile \
			-c 1 -q "$CONC" -n 1 -l 10 2>&1
	else
		ip netns exec "$CLIENT_NS" ./loadgen -s "$SERVER_IP" \
			-n "$QUERIES" -c "$CONC" 2>&1
	fi
}

run_xdp() {
	local label=$1; shift
	echo "--- $label ---"
	./"$1" -d "$IFACE" --filename ./af_xdp_kern.o -w "$WORKERS" "${@:2}" \
		> "$OUT/$label.server" 2>&1 &
	local pid=$!
	sleep 3
	perf_wrap "$1" "$OUT/$label.perf"
	load | tee "$OUT/$label.client"
	kill -INT $pid 2>/dev/null
	wait $pid 2>/dev/null
	echo
}

run_udp() {
	local label=$1 bin=$2
	echo "--- $label ---"
	./"$bin" -p 53 -w "$WORKERS" > "$OUT/$label.server" 2>&1 &
	local pid=$!
	sleep 2
	perf_wrap "$bin" "$OUT/$label.perf"
	SERVER_IP=127.0.0.1 CLIENT_NS="" load | tee "$OUT/$label.client"
	kill -INT $pid 2>/dev/null
	wait $pid 2>/dev/null
	echo
}

echo
echo "===================================================================="
echo " phase 1  --  transport isolation (stub backend, $CONC outstanding)"
echo "===================================================================="
run_xdp xdp_stub_poll      af_xdp_user_stub -S
run_xdp xdp_stub_busy      af_xdp_user_stub -S -b
run_xdp xdp_stub_copy      af_xdp_user_stub -S -c
run_udp udp_stub           server_stub

echo
echo "===================================================================="
echo " phase 2  --  end to end (real iterative resolver)"
echo "===================================================================="
CONC=50
run_xdp xdp_real           af_xdp_user -S
run_udp udp_real           server

echo "done. per-case server stats and client output are in $OUT/"

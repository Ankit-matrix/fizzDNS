#!/bin/bash
# Brings up the hostile hierarchy and a resolver pointed at it, runs the
# full-stack tests, and tears both down again.
#
#   ./run_integration.sh [PART]     PART = A, B or AB (default AB)
#
# A  acceptance rules vs a lying server
# B  every feature at once, concurrently
#
# Kept separate from `make offline`, which runs the same resolver
# against the HONEST hierarchy. Both matter: offline proves resolution
# works, this proves it refuses to be lied to.
set -u
PART=${1:-AB}
PORT=${PORT:-5355}

cleanup() {
    [ -n "${SRV_PID:-}" ] && kill -INT "$SRV_PID" 2>/dev/null
    [ -n "${EVIL_PID:-}" ] && kill -TERM "$EVIL_PID" 2>/dev/null
    wait 2>/dev/null
}
trap cleanup EXIT

if [ ! -x ./server ]; then
    echo "build first: make server"
    exit 2
fi

python3 evil_hierarchy.py > /tmp/evil_hierarchy.log 2>&1 &
EVIL_PID=$!
sleep 1.5

DNS_ROOT_HINTS=127.0.0.21 ./server -p "$PORT" -w 8 > /tmp/evil_server.log 2>&1 &
SRV_PID=$!
sleep 1.5

python3 -u test_integration.py "$PORT" "$PART"
rc=$?

echo
echo "--- resolver counters ---"
kill -INT "$SRV_PID" 2>/dev/null
sleep 1
grep -E "cache hits|cache misses|hit rate|bloom|upstream" /tmp/evil_server.log || true
SRV_PID=""

exit $rc

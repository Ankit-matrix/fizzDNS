#!/bin/bash
# KERNEL-SIDE setup for a 2-core run. Must run on the HOST, not in the
# container: rx queue count and IRQ affinity are properties of the
# device and its interrupts, and a container cannot set either.
#
#   ./setup-2core.sh eth0 [cpu0] [cpu1]
set -eu
IFACE=${1:-eth0}
C0=${2:-0}
C1=${3:-1}

command -v ethtool >/dev/null || { echo "need ethtool"; exit 1; }

# 1. Two rx queues, so RSS has somewhere to spread to. With one queue
#    the second AF_XDP socket has nothing to bind and the second core
#    sits idle no matter what userspace does.
echo "setting $IFACE to 2 combined channels"
ethtool -L "$IFACE" combined 2 || echo "WARN: driver refused; check ethtool -l $IFACE"

nq=$(ls -d /sys/class/net/"$IFACE"/queues/rx-* 2>/dev/null | wc -l)
echo "$IFACE now reports $nq rx queue(s)"
[ "$nq" -ge 2 ] || echo "WARN: fewer than 2 rx queues; --queues 2 will be refused"

# 2. One IRQ per core. Without this both queues' NAPI polls can land on
#    the same core: userspace is then parallel while the kernel half is
#    not, and the run measures one core's softirq capacity.
echo "pinning $IFACE irqs to cpus $C0 and $C1"
i=0
for irq in $(grep -oP "^\s*\K\d+(?=:.*$IFACE)" /proc/interrupts); do
    cpu=$([ $((i % 2)) -eq 0 ] && echo "$C0" || echo "$C1")
    echo "$cpu" > "/proc/irq/$irq/smp_affinity_list" 2>/dev/null \
        && echo "  irq $irq -> cpu $cpu" \
        || echo "  irq $irq -> FAILED (irqbalance running?)"
    i=$((i + 1))
done

# irqbalance will undo the above within seconds if it is running.
if systemctl is-active --quiet irqbalance 2>/dev/null; then
    echo "WARN: irqbalance is active and will revert these settings."
    echo "      sudo systemctl stop irqbalance"
fi

echo
echo "kernel side ready. user side:"
echo "  IFACE=$IFACE docker compose -f docker-compose.mt.yml up resolver"

#!/bin/bash
# Guardian Network Sensor - Isolated Namespace Lab Setup
# Configures a non-routed veth pair connecting the host to an isolated 'lab' namespace.
# Guarantee: Zero WAN route exists inside 'lab', preventing any internet leakage.

set -euo pipefail

NS_NAME="lab"
VETH_HOST="veth0"
VETH_LAB="veth1"
HOST_IP="10.77.0.1/24"
LAB_IP="10.77.0.2/24"

usage() {
    echo "Usage: $0 [up|down|status]"
    echo "  up     : Create network namespace '$NS_NAME' and veth pair ($HOST_IP <-> $LAB_IP)"
    echo "  down   : Tear down namespace and veth interfaces"
    echo "  status : Display current interface and namespace status"
    exit 1
}

ACTION="${1:-up}"

if [ "$ACTION" = "up" ]; then
    echo "[+] Creating network namespace '$NS_NAME'..."
    sudo ip netns add "$NS_NAME" 2>/dev/null || true

    echo "[+] Creating veth pair $VETH_HOST <-> $VETH_LAB..."
    sudo ip link add "$VETH_HOST" type veth peer name "$VETH_LAB" 2>/dev/null || true

    echo "[+] Assigning $VETH_LAB to namespace '$NS_NAME'..."
    sudo ip link set "$VETH_LAB" netns "$NS_NAME"

    echo "[+] Configuring host interface $VETH_HOST with $HOST_IP..."
    sudo ip addr add "$HOST_IP" dev "$VETH_HOST" 2>/dev/null || true
    sudo ip link set "$VETH_HOST" up

    echo "[+] Configuring lab interface $VETH_LAB with $LAB_IP..."
    sudo ip netns exec "$NS_NAME" ip addr add "$LAB_IP" dev "$VETH_LAB" 2>/dev/null || true
    sudo ip netns exec "$NS_NAME" ip link set "$VETH_LAB" up
    sudo ip netns exec "$NS_NAME" ip link set lo up

    echo "[+] Isolation verification: ensuring NO default route out of '$NS_NAME'..."
    sudo ip netns exec "$NS_NAME" ip route del default 2>/dev/null || true

    echo "[✓] Lab isolated namespace active:"
    echo "    Host side: $VETH_HOST ($HOST_IP)"
    echo "    Lab side:  $VETH_LAB ($LAB_IP) inside namespace '$NS_NAME'"
    echo "    WAN Route: NONE (completely isolated by construction)"

elif [ "$ACTION" = "down" ]; then
    echo "[-] Tearing down lab namespace..."
    sudo ip link delete "$VETH_HOST" 2>/dev/null || true
    sudo ip netns delete "$NS_NAME" 2>/dev/null || true
    echo "[✓] Lab torn down."

elif [ "$ACTION" = "status" ]; then
    echo "=== Network Namespaces ==="
    ip netns list || true
    echo "=== Lab Routes ==="
    sudo ip netns exec "$NS_NAME" ip route 2>/dev/null || echo "Namespace $NS_NAME not active."
else
    usage
fi

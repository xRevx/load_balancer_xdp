#!/bin/bash

usage() {
  echo "Usage: $0 -i <interface> -s <start_port> -n <num_servers> -a <snat_source_ip>"
  echo "  -i Interface to attach XDP/TC program (e.g. ens33)"
  echo "  -s Start port for backend servers (e.g. 8001)"
  echo "  -n Number of backend servers"
  echo "  -a SNAT source IP address (e.g. 1.0.0.1)"
  exit 1
}

while getopts "i:s:n:a:" opt; do
  case $opt in
    i) IFACE=$OPTARG ;;
    s) START_PORT=$OPTARG ;;
    n) NUM_SERVERS=$OPTARG ;;
    a) SNAT_IP=$OPTARG ;;
    *) usage ;;
  esac
done

if [ -z "$IFACE" ] || [ -z "$START_PORT" ] || [ -z "$NUM_SERVERS" ] || [ -z "$SNAT_IP" ]; then
  usage
fi

# Filenames
XDP_SRC="xdp_load_balancer.c"
XDP_OBJ="xdp_load_balancer.o"
TC_SRC="tc_sport_changer.c"
TC_OBJ="tc_sport_changer.o"

# Cleanup function
exit_cleanup() {
  echo -e "\n🧹 Cleaning up..."

  echo "🔻 Killing all Python HTTP servers..."
  pkill -f "python3 -m http.server"

  echo "🔻 Killing trace_pipe if running..."
  if [ -n "$TRACE_PID" ]; then
    sudo kill "$TRACE_PID" 2>/dev/null
  fi

  echo "🔻 Removing XDP program from $IFACE..."
  sudo ip link set dev "$IFACE" xdp off 2>/dev/null

  echo "🔻 Removing TC qdisc from $IFACE..."
  sudo tc qdisc del dev "$IFACE" clsact 2>/dev/null

  echo "✅ Cleanup complete."
  exit 0
}

# Trap SIGINT and SIGTERM
trap exit_cleanup INT TERM

# Start backend HTTP servers
echo "🌐 Starting $NUM_SERVERS Python HTTP servers from port $START_PORT..."
for ((port=START_PORT; port<START_PORT+NUM_SERVERS; port++)); do
  nohup python3 -m http.server "$port" > "/tmp/http_server_$port.log" 2>&1 &
done

# --- Compile and attach XDP ---
echo "🛠️ Compiling XDP program..."
if ! clang -O2 -g -Wall -target bpf -D__TARGET_ARCH_x86 -I/usr/include -c "$XDP_SRC" -o "$XDP_OBJ"; then
  echo "❌ XDP compilation failed!"
  exit 1
fi

echo "🧹 Removing existing XDP program (if any)..."
sudo ip link set dev "$IFACE" xdp off 2>/dev/null

echo "📎 Attaching XDP program to $IFACE..."
if ! sudo ip link set dev "$IFACE" xdp obj "$XDP_OBJ" sec xdp; then
  echo "❌ Failed to attach XDP program"
  exit 1
fi

# --- Compile and attach TC ---
echo "🛠️ Compiling TC eBPF program..."
if ! clang -O2 -g -Wall -target bpf -D__TARGET_ARCH_x86 -I/usr/include -c "$TC_SRC" -o "$TC_OBJ"; then
  echo "❌ TC compilation failed!"
  exit 1
fi

echo "🔧 Setting up clsact qdisc on $IFACE..."
sudo tc qdisc del dev "$IFACE" clsact 2>/dev/null
if ! sudo tc qdisc add dev "$IFACE" clsact; then
  echo "❌ Failed to add clsact"
  exit 1
fi

echo "📎 Attaching TC program on egress of $IFACE..."
sudo tc filter del dev "$IFACE" egress 2>/dev/null
if ! sudo tc filter add dev "$IFACE" egress bpf da obj "$TC_OBJ" sec tc; then
  echo "❌ Failed to attach TC program"
  exit 1
fi

# Optional system settings
echo "🛡️ Enabling IP forwarding..."
sudo sysctl -w net.ipv4.ip_forward=1

echo "🔍 Setting $IFACE to promiscuous mode..."
sudo ip link set dev "$IFACE" promisc on

# Summary
echo "✅ XDP and TC programs attached successfully."
echo "📦 Interface $IFACE info:"
ip link show "$IFACE"

# Watch trace_pipe in background
echo "📟 Watching trace logs (Ctrl+C to stop)..."
sudo cat /sys/kernel/debug/tracing/trace_pipe | while read line; do
  echo "$line"
done

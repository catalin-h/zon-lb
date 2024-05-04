#!/bin/sh

set -e

if [ "$(id -u)" != "0" ]; then
  printf "please run script as root\n"
  exit 1
fi

NSA=0
NSB=2

setup_ns() {
  NS=zone$1
  P0=$1
  NET=$1
  P1=$(($P0+1))
  IF0=veth$P0
  IF1=veth$P1
  IP0=10.$NET.0.1
  IP1=10.$NET.0.2

  printf "setup ns $NS $IF0:$IP0 $IF1:$IP1\n"

  if [ ! -f /var/run/netns/$NS ]; then
    ip netns add $NS
    # by default the loopback interface in newly created netns is down
    ip -netns $NS link set dev lo up
  else
    printf "netns $NS already created\n"
  fi

  if [ -d /sys/class/net/$IF0 ]; then
    printf "$IF0 already created\n"
    return;
  fi

  ip link add name $IF0 type veth peer netns $NS name $IF1
  ip link set dev $IF0 up
  ip -netns $NS link set dev $IF1 up
  ip address add $IP0/24 dev $IF0
  ip -netns $NS address add $IP1/24 dev $IF1

  printf "pinging $IP0 from $NS .. "
  ip netns exec $NS ping $IP0 -c1 -s0 -w 1 > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    printf "ok\n"
  else
    printf "failed\n"
  fi

  # Fix veth driver bug that falsely advertises that it support checksum compute
  # offload and the network stack does skip computing it. As a result the
  # tcp checksum is not computed and the packet will be dropped. Disabling the
  # the hw checsum offload on TX for the veth interface fixes the TCP bad
  # checksum issue.
  printf "disabling tx-checksumming for $IF0 ...\n"
  ethtool -K $IF0 tx-checksumming off >> /dev/null 
  ethtool -k $IF0 | grep tx-checksumming

  printf "disabling tx-checksumming for $NS/$IF1 ...\n"
  ip netns exec $NS ethtool -K $IF1 tx-checksumming off >> /dev/null
  ip netns exec $NS ethtool -k $IF1 | grep tx-checksumming

  # In order for receiving veth interfaces to handle xdp redirects they must
  # have an xdp program loaded and must return XDP_PASS.
  printf "attaching xdp program to $NS/$IF1 ...\n"
  ip -netns $NS link set $IF1 xdp obj xdp_pass.o sec .text

  # Enable forwarding on veth from default netns so the
  # fib lookup wouldn't fail.
  sysctl -w net.ipv4.conf.$IF0.forwarding=1

  printf "done setup $NS\n"
}

cleanup_ns() {
  NS=zone$1

  if [ ! -f /var/run/netns/$NS ]; then
    printf "No $NS\n"
    return;
  fi

  printf "cleanup $NS ..\n"

  # local veth will be deleted after deleting the netns
  ip netns del $NS
  printf "done!\n"
}

if [ "$1" = "cleanup" ]; then
	cleanup_ns $NSA
	cleanup_ns $NSB
	exit 0
fi

setup_ns $NSA
setup_ns $NSB

printf "setup done!\n"


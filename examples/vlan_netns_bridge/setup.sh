#!/bin/sh

set -e

if [ "$(id -u)" != "0" ]; then
  printf "please run script as root\n"
  exit 1
fi

NSA=0
NSB=2
VLANID2=2

# To reduce the likelihood of conflict and confusion when relating
# documented examples to deployed systems, an IPv6 unicast address
# prefix is reserved for use in examples in RFCs, books, documentation,
# and the like.  Since site-local and link-local unicast addresses have
# special meaning in IPv6, these addresses cannot be used in many
# example situations.  The document describes the use of the IPv6
# address prefix 2001:DB8::/32 as a reserved prefix for use in
# documentation.
# See: https://datatracker.ietf.org/doc/html/rfc3849

setup_ns() {
  NS=zone$1
  P0=$1
  NET=$1
  P1=$(($P0+1))
  IF0=veth$P0
  IF1=veth$P1
  IPV4_0=10.$NET.0.1
  IPV4_1=10.$NET.0.2
  IPV6_0=2001:db8::$NET:1
  IPV6_1=2001:db8::$NET:2
  # VLAN config
  IF0_VID2=$IF0.$VLANID2
  IF0_VID2_IPV4=10.$NET.$VLANID2.1
  IF1_VID2=$IF1.$VLANID2
  IF1_VID2_IPV4=10.$NET.$VLANID2.2

  printf "setup ns $NS $IF0:$IPV4_0|$IPV6_0 $IF1:$IPV4_1|$IPV6_1\n"

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
  ip address add $IPV6_0/120 dev $IF0
  ip address add $IPV4_0/24 dev $IF0
  ip -netns $NS address add $IPV6_1/120 dev $IF1
  ip -netns $NS address add $IPV4_1/24 dev $IF1
  ip link set dev $IF0 up
  ip -netns $NS link set dev $IF1 up

  # Add VLAN interfaces inside the netns and attached to the
  # same veth interface. Use the same IP as the main interface to
  # demonstrate packets are delivered to VLAN interface.
  ip -netns $NS link add link $IF1 name $IF1_VID2 type vlan id $VLANID2
  ip -netns $NS address add $IF1_VID2_IPV4/24 dev $IF1_VID2
  ip -netns $NS link set dev $IF1_VID2 up
  # In order to make the ARP work within the VLAN all veth for either netns
  # must have sub-interface in the same VLAN.
  # Can't have the LB act as a brigde and the veth act as a trunk interface
  # without having this additional VLAN if or some kind of ARP proxy between
  # the two test netns.
  # As a future functionality, the LB must act as ARP proxy and forward ARP
  # packets & other types between netns. This will simplify the requiremens,
  # for e.g. creating VLAN sub-interfaces and just use the two veth as trunks.
  # Note that this example will bridge packets between two subnets activate
  # within the same VLAN.
  ip link add link $IF0 name $IF0_VID2 type vlan id $VLANID2
  ip address add $IF0_VID2_IPV4/24 dev $IF0_VID2
  ip link set dev $IF0_VID2 up

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

  printf "disabling vlan offload for $IF0 ...\n"
  ethtool -K $IF0 rxvlan off txvlan off >> /dev/null
  ethtool -k $IF0 | grep vlan-offload

  # > Since XDP needs to see the VLAN headers as part of the packet headers, it is
  # > important to turn off VLAN hardware offload (which most hardware NICs
  # > support), since that will remove the VLAN tag from the packet header and
  # > instead communicate it out of band to the kernel via the packet hardware
  # > descriptor
  #
  # See: https://github.com/xdp-project/xdp-tutorial/tree/master/packet01-parsing#assignment-4-adding-vlan-support
  printf "disabling vlan offload for $IF1 ...\n"
  ip netns exec $NS ethtool -K $IF1 rxvlan off txvlan off >> /dev/null
  ip netns exec $NS ethtool -k $IF1 | grep vlan-offload

  # In order for receiving veth interfaces to handle xdp redirects they must
  # have an xdp program loaded and must return XDP_PASS.
  printf "attaching xdp program to $NS/$IF1 ...\n"
  ip -netns $NS link set $IF1 xdp obj xdp_pass.o sec .text
  #ip -netns $NS link set $IF1_VID2 xdp obj xdp_pass.o sec .text

  # Enable forwarding on veth from default netns so the
  # fib lookup wouldn't fail.
  sysctl -w net.ipv6.conf.$IF0.forwarding=1
  sysctl -w net.ipv4.conf.$IF0.forwarding=1

  printf "pinging $IPV4_0 from $NS .. "
  set +e
  ip netns exec $NS ping $IPV4_0 -c1 -s0 -w 5 -v -d  > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    printf "ok\n"
  else
    printf "failed\n"
    exit 1
  fi
  set -e

  printf "pinging $IPV6_0 from $NS .. "
  set +e
  # ip netns exec $NS ip neigh get $IPV6_0 dev $IF1
  # After adding bringing the iface up the NDP kicks in and
  # this may take a while so we need to set a bigger 5s timeout
  # with option `-w 5`
  ip netns exec $NS ping $IPV6_0 -c1 -s0 -w 5 -v -d  > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    printf "ok\n"
  else
    printf "failed\n"
    exit 1
  fi
  set -e

  # here after ping the pair interface should appear as neighbour
  printf "[$NS neighbour show]\n"
  ip netns exec $NS ip neigh show

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

if [ "$1" != "" ]; then
  printf "unknown '$1' args\n"
  exit 1
fi

setup_ns $NSA
setup_ns $NSB

printf "setup done!\n"


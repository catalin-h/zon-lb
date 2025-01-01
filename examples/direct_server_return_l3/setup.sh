#!/bin/sh -

set -e

if [ "$(id -u)" != "0" ]; then
  printf "please run script as root\n"
  exit 1
fi

NSA=0
NSB=1
VIP=10.$NSA.0.1
VIP6=2001:db8::$NSA:1

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
  P0=$((2*$1))
  NET=$P0
  P1=$(($P0+1))
  IF0=veth$P0
  IF1=veth$P1
  IP0V4=10.$NET.0.1
  IP1V4=10.$NET.0.2
  IP0V6=2001:db8::$NET:1
  IP1V6=2001:db8::$NET:2
  IP6TNL1=ip6tnl1
  IP6TNL1IP=2001:db8::$NET:3

  LINK="$IF0 <-> $NS/$IF1"

  printf "setting up link $LINK...\n"
  printf "\t$IP0V4 <-> $IP1V4\n\t$IP0V6 <-> $IP1V6\n"

  if [ ! -f /var/run/netns/$NS ]; then
    ip netns add $NS
    # by default the loopback interface in newly created netns is down
    ip -netns $NS link set dev lo up
  else
    printf "netns $NS already created\n"
  fi

  if [ ! -d /sys/class/net/$IF0 ]; then
    printf "creating link $LINK ...\n"

    ip link add name $IF0 type veth peer netns $NS name $IF1

    ip address add $IP0V6/120 dev $IF0
    ip address add $IP0V4/24  dev $IF0

    ip -netns $NS address add $IP1V6/120 dev $IF1
    ip -netns $NS address add $IP1V4/24  dev $IF1

    ip link set dev $IF0 up
    ip -netns $NS link set dev $IF1 up

    if [ ! -z "$3" ]; then
      printf "Setting VIPs to lo:\n\t$VIP\n\t$VIP6\n"
      # Set VIP address for lo inside backend netns
      # Note: the VIP must be a single IP or set 32 as CIDR block
      ip -netns $NS address add $VIP dev lo
      ip -netns $NS address add $VIP6 dev lo

      # Add default gateway for backend netns
      ip -netns $NS route add default via $IP0V4
      ip -netns $NS route add default via $IP0V6

      # Create and configure the ipv6tnl interface.
      # Note: The fallback device "ip6tnl0", created during module
      # initialization, can be used for creating other tunnel devices.
      # See:
      # https://elixir.bootlin.com/linux/v6.1.26/source/net/ipv6/ip6_tunnel.c#L1601
      # Note: The interface IP addressed should be from same pool as the backend
      # server address.
      # Note: local ADDR - specifies the fixed local address for tunneled
      # packets. It must be an address on another interface on this host for
      # IPIP, SIT but for ip6tnl it can be an address on the same tunnel if.
	  ip -netns $NS link add name $IP6TNL1 type ip6tnl local $IP6TNL1IP mode any
	  ip -netns $NS address add $IP6TNL1IP dev $IP6TNL1
	  ip -netns $NS link set $IP6TNL1 up
    fi

    # In order for receiving veth interfaces to handle xdp redirects they must
    # have an xdp program loaded and must return XDP_PASS.
    printf "attaching xdp program to $NS/$IF1 ...\n"
    ip -netns $NS link set $IF1 xdp obj xdp_pass.o sec .text

    printf "$LINK link created!\n"
  else
    printf "$LINK link already created!\n"
  fi

  if [ -d /sys/class/net/$IF0 ]; then
    # Enable forwarding on veth from default netns so the
    # fib lookup wouldn't fail.
    printf "enable forwarding for $NS/$IF1 ...\n"
    sysctl -w net.ipv6.conf.$IF0.forwarding=1
    sysctl -w net.ipv4.conf.$IF0.forwarding=1

    # Fix veth driver bug that falsely advertises that it support checksum compute
    # offload and the network stack does skip computing it. As a result the
    # tcp checksum is not computed and the packet will be dropped. Disabling the
    # the hw checsum offload on TX for the veth interface fixes the TCP bad
    # checksum issue.
    # Even for L2 DSR this is required because the IP checksum must be computed
    # in order for the pair TCP/UDP endpoint to ack the connection.
    printf "disabling tx-checksumming for $IF0 ...\n"
    ethtool -K $IF0 tx-checksumming off >> /dev/null
    ethtool -k $IF0 | grep tx-checksumming

    printf "disabling tx-checksumming for $NS/$IF1 ...\n"
    ip netns exec $NS ethtool -K $IF1 tx-checksumming off >> /dev/null
    ip netns exec $NS ethtool -k $IF1 | grep tx-checksumming

    if [ ! -z "$3" ]; then
      # clear RP_FILTER for backend netns conf.all
      ip netns exec $NS sysctl -w net.ipv4.conf.all.rp_filter=0

      # Enable forwarding inside the backend netns so the tunnel
      # interface can forward the inner packet.
      printf "enable forwarding inside $NS ...\n"
      ip netns exec $NS sysctl -w net.ipv6.conf.all.forwarding=1
      ip netns exec $NS sysctl -w net.ipv4.conf.all.forwarding=1

      # Enable forwarding in the default netns so the replied packet
      # from the backend server can be forwarded to the client.
      printf "enable forwarding inside default netns ...\n"
      sysctl -w net.ipv6.conf.all.forwarding=1
      sysctl -w net.ipv4.conf.all.forwarding=1

      # For IPv4 in order for the example to work must be enabled the following
      # options:
      # a) accept_source_route=1 or Accept packets with SRR option for the
      # default netns interface that the reply should be forwarded
      # b) accept_local=1 or Accept packets with local source addresses for the
      # default netns interface that the reply should is received
      #
      # See: https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/6
      #/html/security_guide/sect-security_guide-server_security-disable-source
      #-routing#sect-Security_Guide-Server_Security-Disable-Source-Routing
      printf "accept packets with local source addresses for $IF0 ...\n"
      sysctl -w net.ipv4.conf.$IF0.accept_local=1
    else
      printf "accept packets with SRR option for $IF0 ...\n"
	  sysctl -w net.ipv4.conf.$IF0.accept_source_route=1
	fi
  fi

  if [ ! -z "$2" ]; then
    MTU=$2
    if [ "$MTU" -lt "1280" ]; then
      printf "MTU=$MTU is less than IPv6 min MTU=1280\n"
      printf "Reset to 1280 to allow IPv6 addresses\n"
      MTU=1280
    fi
    printf "setting $LINK link MTU=$MTU\n"
    ip link set dev $IF0 mtu $MTU
    ip -netns $NS link set dev $IF1 mtu $MTU
  fi

  printf "setup link done!\n"

  printf "testing link ... \n"
  printf "pinging $IP0V6 from $NS .. "
  set +e
  # ip netns exec $NS ip neigh get $IP0 dev $IF1
  # After adding bringing the iface up the NDP kicks in and
  # this may take a while so we need to set a bigger 5s timeout
  # with option `-w 5`
  ip netns exec $NS ping $IP0V6 -c1 -s0 -w 5 -v -d  > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    printf "ok\n"
  else
    printf "failed\n"
    exit 1
  fi
  set -e

  printf "pinging $IP0V4 from $NS .. "
  set +e
  ip netns exec $NS ping $IP0V4 -c1 -s0 -w 5 -v -d  > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    printf "ok\n"
  else
    printf "failed\n"
    exit 1
  fi
  set -e

  printf "testing done!\n"
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

key=${1%=*}
value=${1#*=}

if [ "${key}" != "mtu" ] && [ "${key}" != "" ] ; then
  printf "unknown '$1' args\n"
  exit 1
fi

setup_ns $NSA
setup_ns $NSB "$value" 1

printf "setup done!\n"


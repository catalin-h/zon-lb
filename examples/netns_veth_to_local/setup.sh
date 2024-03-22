#!/bin/sh
NS=zone1
IF0=veth0
IF1=veth1
IP0=10.0.0.1
IP1=10.0.0.2

if [ "$1" = "cleanup" ]; then
	printf "cleanup ..\n"
	# local veth will be deleted after deleting the netns
	ip netns del $NS
	printf "done!\n"
	exit 0
fi

if [ ! -f /var/run/netns/$NS ]; then
	ip netns add $NS
else
	printf "netns $NS and veth already created\n"
	ip -s address show dev $IF0
	ip -s -netns $NS address show dev $IF1
	printf  "done!\n"
	exit 0
fi

ip link add name $IF0 type veth peer netns $NS name $IF1
ip link set dev $IF0 up
ip -netns $NS link set dev $IF1 up
# by default the loopback interface in newly created netns is down
ip -netns $NS link set dev lo up
ip address add $IP0/24 dev $IF0
ip -netns $NS address add $IP1/24 dev $IF1
ip netns exec $NS ping $IP0 -c1 -s0
ip -s address show dev $IF0
ip -s -netns $NS address show dev $IF1

# By default veth does not compute the TCP checksum and the connect
# request might be droped. To exclude this just disable offloads on TX.
# ethtool -K $IF0 tx off
# ip netns exec $NS ethtool -K $IF1 tx off

# Accept packets with local source addresses. In combination with
# suitable routing, this can be used to direct packets between two
# local interfaces over the wire and have them accepted properly.
sysctl -w net.ipv4.conf.$IF0.accept_local=1

printf "done!\n"


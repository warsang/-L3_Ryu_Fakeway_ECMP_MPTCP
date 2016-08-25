#!/bin/bash
ifconfig h1-eth0 10.1.1.2/24
ifconfig h1-eth1 10.1.2.2/24
ifconfig h1-eth2 10.1.3.2/24

# This creates two different routing tables, that we use based on the source-address.
ip rule add from 10.1.1.2 table 1
ip rule add from 10.1.2.2 table 2
ip rule add from 10.1.3.2 table 3

# Configure the two different routing tables
ip route add 10.1.1.0/24 dev h1-eth0 scope link table 1
ip route add default via 10.1.1.1 dev h1-eth0 table 1

ip route add 10.1.2.0/24 dev h1-eth1 scope link table 2
ip route add default via 10.1.2.1 dev h1-eth1 table 2

ip route add 10.1.3.0/24 dev h1-eth2 scope link table 3
ip route add default via 10.1.3.1 dev h1-eth2 table 3

###########REDIRECT TRAFFIC MARKED TO h1-eth3##########
##Must create a user
#iptables -t mangle -A OUTPUT -m owner --uid-owner 1001 -j MARK --set-mark 11
##check if the uid of user is 1001 with id -u "username"
#iptables rule add fwmark 11 priority 1000 table 11
#ip route add 10.1.5.0/24 dev h1-eth3 scope link table 11
#ip route add default via 10.1.5.1 dev h1-eth3 table 11
#########
# default route for the selection process of normal internet-traffic
ip route add default scope global nexthop via 10.1.1.1 dev h1-eth0

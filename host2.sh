#!/bin/bash
ifconfig h2-eth0 10.1.4.2/24

# This creates two different routing tables, that we use based on the source-address.
ip rule add from 10.1.4.2 table 1
ip rule add from 10.1.4.2 table 2
ip rule add from 10.1.4.2 table 3

# Configure the two different routing tables
ip route add 10.1.4.0/24 dev h2-eth0 scope link table 1
ip route add default via 10.1.4.1 dev h2-eth0 table 1

ip route add 10.1.4.0/24 dev h2-eth0 scope link table 2
ip route add default via 10.1.4.10 dev h2-eth0 table 2

ip route add 10.1.4.0/24 dev h2-eth0 scope link table 3
ip route add default via 10.1.4.20 dev h2-eth0 table 3

####To reply to traffic from swith 5########"
#ip rule add from 10.1.4.2 table 4
#ip route add 10.1.4.0/24 dev h2-eth1 scope link table 4

######

# default route for the selection process of normal internet-traffic
ip route add default scope global nexthop via 10.1.4.1 dev h2-eth0

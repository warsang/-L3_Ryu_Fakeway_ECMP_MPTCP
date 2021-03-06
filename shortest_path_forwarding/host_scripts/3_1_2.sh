#!/bin/bash
ifconfig 3_1_2-eth0 10.0.0.25/24
ifconfig 3_1_2-eth1 10.0.0.26/24

# This creates two different routing tables, that we use based on the source-address.
ip rule add from 10.0.0.25 table 1
ip rule add from 10.0.0.26 table 2

# Configure the two different routing tables
ip route add 10.0.0.0/8 dev 3_1_2-eth0 scope link table 1
ip route add default via 10.0.0.1 dev 3_1_2-eth0 table 1

ip route add 10.0.0.0/8 dev 3_1_2-eth1 scope link table 2
ip route add default via 10.0.0.1 dev 3_1_2-eth1 table 2

###########REDIRECT TRAFFIC MARKED TO 3_1_2eth3##########
##Must create a user
#iptables -t mangle -A OUTPUT -m owner --uid-owner 1001 -j MARK --set-mark 11
##check if the uid of user is 1001 with id -u "username"
#iptables rule add fwmark 11 priority 1000 table 11
#ip route add 10.1.5.0/24 dev 3_1_2eth3 scope link table 11
#ip route add default via 10.1.5.1 dev 3_1_2eth3 table 11
#########
# default route for the selection process of normal internet-traffic
ip route add default scope global nexthop via 10.0.0.1 dev 3_1_2-eth0

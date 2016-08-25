#!/bin/bash
sudo ovs-vsctl set Bridge s1 protocols=OpenFlow10,OpenFlow11,OpenFlow12,OpenFlow13,OpenFlow14
sudo ovs-vsctl set Bridge s2 protocols=OpenFlow10,OpenFlow11,OpenFlow12,OpenFlow13,OpenFlow14
sudo ovs-vsctl set Bridge s3 protocols=OpenFlow10,OpenFlow11,OpenFlow12,OpenFlow13,OpenFlow14
sudo ovs-vsctl set Bridge s4 protocols=OpenFlow10,OpenFlow11,OpenFlow12,OpenFlow13,OpenFlow14

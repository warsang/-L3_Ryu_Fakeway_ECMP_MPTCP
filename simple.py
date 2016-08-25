# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_4
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet.arp import arp
from ryu.lib.packet.packet import Packet

import random

ROUTER_IPADDR1 = '10.1.1.1'
ROUTER_IPADDR2 = '10.1.4.1'
ROUTER_MACADDR1 = '00:00:00:00:00:01'
ROUTER_MACADDR2 = '00:00:00:00:00:02'
ROUTER_PORT1 = 1
ROUTER_PORT2 = 2

def randomMAC():
        return [ 0x00, 0x16, 0x3e,
                random.randint(0x00, 0x7f),
                random.randint(0x00, 0xff),
                random.randint(0x00, 0xff) ]
def macPrettyPrint(mac):
        return ':'.join(map(lambda x: "%02x" % x, mac))

    
class SimpleSwitch14(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_4.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch14, self).__init__(*args, **kwargs)
        #To map non router macs to certain ports
        self.mac_to_port = {}
        #To map non router ip to certain macs
        self.mac_to_ip = {}
        #Router IpAddresses
        self.fakeways = {ROUTER_IPADDR1,ROUTER_IPADDR2}
        #To Map router Mac to router IP
        self.fakewayMac_to_ip = {}
        #To Map router Port to router mac
        self.fakewayMac_to_port = {}
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    def receive_arp(self,datapath,packet,etherFrame,inPort):
        arpPacket = packet.get_protocol(arp)
        if arpPacket.opcode == 1 :
            arp_dstIp = arpPacket.dst_ip
            self.logger.debug('received ARP Request %s => %s (port%d)'%(etherFrame.src,etherFrame.dst,inPort))
            self.reply_arp(datapath,etherFrame,arpPacket,arp_dstIp,inPort)
        elif arpPacket.opcode == 2 :
            arp_srcIp = arpPacket.src_ip
            srcMac = etherFrame.src
            #Add Mac source and Ip to our Mac_to_Ip table
            self.mac_to_ip[datapath.id][srcMac] = arp_srcIp
            #Add Mac source to our mac to port table
            self.mac_to_port[datapath.id][srcMac] = inPort
            pass

    def reply_arp(self, datapath, etherFrame, arpPacket, arp_dstIp, inPort):
        dstIp = arpPacket.src_ip
        srcIp = arpPacket.dst_ip
        dstMac = etherFrame.src
        self.logger.debug("ARP dstIp: %s"%arp_dstIp)
        #Check to see if the ip is a fake gateway
        if arp_dstIp in self.fakeways:
            #Create a random mac address
            routerMac = str(macPrettyPrint(randomMAC()))
            #Add it to RouterIp/Mac Table
            self.fakewayMac_to_ip[datapath.id][routerMac] = arp_dstIp
            #Add it to Gateway interface-Mac Table
            self.fakewayMac_to_port[datapath.id][routerMac] = inPort
            srcMac = routerMac
            outPort = inPort
      #  if arp_dstIp == ROUTER_IPADDR1:
      #      srcMac = ROUTER_MACADDR1
      #      outPort = inPort
      #  elif arp_dstIp == ROUTER_IPADDR2:
      #      srcMac = ROUTER_MACADDR2
      #      outPort = inPort
        else:
            self.logger.debug("unknown arp request received !")
        self.send_arp(datapath, 2, srcMac, srcIp, dstMac, dstIp, outPort)
        self.logger.debug("send ARP reply %s => %s (port%d)" %(srcMac, dstMac, outPort))
    
    def send_arp(self, datapath, opcode, srcMac, srcIp, dstMac, dstIp, outPort):
        if opcode == 1:
            targetMac = "00:00:00:00:00:00"
            targetIp = dstIp
        elif opcode == 2:
            targetMac = dstMac
            targetIp = dstIp
        e = ethernet.ethernet(dstMac, srcMac, ether_types.ETH_TYPE_ARP)
        a = arp(1, 0x0800, 6, 4, opcode, srcMac, srcIp, targetMac, targetIp)
        p = Packet()
        p.add_protocol(e)
        p.add_protocol(a)
        p.serialize()
        actions = [datapath.ofproto_parser.OFPActionOutput(outPort, 0)]
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=0xffffffff,
            in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=p.data)
        datapath.send_msg(out)
   
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        actions = None
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_ip.setdefault(dpid,{})
        self.fakewayMac_to_ip.setdefault(dpid,{})
        self.fakewayMac_to_port.setdefault(dpid,{})
        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
        ###ADDED######
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            self.receive_arp(datapath,pkt,eth,in_port)
            #Learn src mac and src ip
            self.mac_to_ip[dpid][src] = pkt.get_protocol(arp).src_ip
            #Learn src mac and port it came from
            self.mac_to_port[dpid][src] = in_port
        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port
        #learn ip to mac
        if eth.ethertype == ether_types.ETH_TYPE_IP:
            ipv4_pak = pkt.get_protocol(ipv4.ipv4)
            self.mac_to_ip[dpid][src] = ipv4_pak.src 
        #if dst in self.mac_to_port[dpid]:
        #    out_port = self.mac_to_port[dpid][dst]
        #else:
        #    out_port = ofproto.OFPP_FLOOD
            if dst in self.fakewayMac_to_ip[dpid]:
                if self.fakewayMac_to_port[dpid][dst] == 1:
                    out_port = 2
                    #Check if port 2 has a mac
                    if 2 in self.fakewayMac_to_port[dpid].values():
                        #It does, we assign it
                        srcMac = self.fakewayMac_to_port[dpid].keys()[self.fakewayMac_to_port[dpid].values().index(2)]
                    else:
                        #It doesn't we assign a new mac address:
                        srcMac = str(macPrettyPrint(randomMAC()))
                        #Add it to RouterIp/Mac Table
                        self.fakewayMac_to_ip[dpid][srcMac] = '10.1.4.1'
                        #Add it to Gateway interface-Mac Table
                        self.fakewayMac_to_port[dpid][srcMac] = out_port
                else:
                    out_port = 1
                    #Check if port 1 has a mac
                    if 1 in self.fakewayMac_to_port[dpid].values():
                        #It does, we assign it
                        srcMac = self.fakewayMac_to_port[dpid].keys()[self.fakewayMac_to_port[dpid].values().index(1)]
                    else:
                        #It doesn't we assign a new mac address:
                        srcMac = str(macPrettyPrint(randomMAC()))
                        #Add it to RouterIp/Mac Table
                        self.fakewayMac_to_ip[dpid][srcMac] = '10.1.1.1'
                        #Add it to Gateway interface-Mac Table
                        self.fakewayMac_to_port[dpid][srcMac] = out_port
                #Is the Ip destination in Mac to IP table?
                if ipv4_pak.dst in  self.mac_to_ip[dpid].values():
                    actions = [parser.OFPActionSetField(eth_dst = self.mac_to_ip[dpid].keys()[self.mac_to_ip[dpid].values().index(ipv4_pak.dst)])]
                else:
                    #SEND ARP REQUEST FOR THIS IP IF NOT KNOWN
                    self.send_arp(datapath,1,srcMac,self.fakewayMac_to_ip[dpid][srcMac],'ff:ff:ff:ff:ff:ff',ipv4_pak.dst,out_port)
                    return
                actions.append(parser.OFPActionSetField(eth_src = srcMac))
                actions.append(parser.OFPActionOutput(out_port))
       # if dst == '00:00:00:00:00:01':
       #     out_port = ROUTER_PORT2
       #     actions = [parser.OFPActionSetField(eth_dst = 'b2:64:b7:5f:5a:97')]
       #     actions.append(parser.OFPActionSetField(eth_src = ROUTER_MACADDR2))
       #     actions.append(parser.OFPActionOutput(out_port))
       #     self.logger.info('ok')
       # elif dst == '00:00:00:00:00:02':
       #     out_port = ROUTER_PORT1
       #     actions = [parser.OFPActionSetField(eth_dst = 'a2:86:fb:29:dc:57')]
       #     actions.append(parser.OFPActionSetField(eth_src = ROUTER_MACADDR1))
       #     actions.append(parser.OFPActionOutput(out_port))
       #     self.logger.info('ok')
##########################
        #install a flow
        match = parser.OFPMatch(in_port = in_port, eth_dst = dst)
        if actions:
            self.add_flow(datapath,1,match,actions)
            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data
                out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                          in_port=in_port, actions=actions, data=data)
                datapath.send_msg(out)

      # install a flow to avoid packet_in next time
    #    if out_port != ofproto.ofpp_flood:
    #        match = parser.ofpmatch(in_port=in_port, eth_dst=dst)
    #        self.add_flow(datapath, 1, match, actions)

    #    data = none
    #    if msg.buffer_id == ofproto.ofp_no_bUFFER:
    #        data = msg.data

    #    out = parser.ofppacketout(datapath=datapath, buffer_id=msg.buffer_id,
    #                              in_port=in_port, actions=actions, data=data)
    #    datapath.send_msg(out)'''

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

from ryu.topology.api import get_switch,get_link
from ryu.topology import event,switches
import networkx as nx
from random import randint

class SimpleSwitch14(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_4.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch14, self).__init__(*args, **kwargs)
        self.topology_api_app = self
        self.net = nx.DiGraph()
        self.nodes = {}
        self.dst_to_group = {}
        self.dst_to_rule = {}
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

    def add_group(self,datapath,path_list,group_id):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        weight = 100 / len(path_list)
        watch_port = ofproto_v1_4.OFPP_ANY
        watch_group = ofproto_v1_4.OFPQ_ALL
        try:
            rest = 100 % len(path_list)
        except:
            rest = 0
        weight_list = []
        for p in path_list:
            weight_list.append(weight)
        weight_list[0] = weight_list[0] + rest
        buckets = []
        for i in range(len(path_list)):
            print path_list[i]
            try:
                next = path_list[i][path_list[i].index(dpid) + 1]
            except:
                try:
                    next = path_list[i+1][path_list[i+1].index(dpid) + 1]
                except:
                    next = path_list[i-1][path_list[i - 1].index(dpid) +1]
            out_port = self.net[dpid][next]['port']
            actions = [parser.OFPActionOutput(out_port)]
            buckets.append(parser.OFPBucket(weight_list[i],watch_port, watch_group,actions))
            
        req = parser.OFPGroupMod(datapath,ofproto.OFPFC_ADD,ofproto.OFPGT_SELECT,group_id,buckets)
        datapath.send_msg(req)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        out_port = None
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.dst_to_group.setdefault(dpid,{})
        self.dst_to_rule.setdefault(dpid,{})
        actions = []
        #Ignore printing LLDP packets (mac is controller)
        if dst != '01:80:c2:00:00:0e': 
            print "dpid %s src %s dst %s in_port %s" % (dpid,src,dst,in_port)
        if src not in self.net:
            print 'Adding node and links'
            self.net.add_node(src)
            self.net.add_edge(dpid,src,{'port':in_port})
            self.net.add_edge(src,dpid)
            print self.net
        if dst in self.net and dst not in self.dst_to_group[dpid]:
            print 'Determining how many paths'
            paths = nx.all_shortest_paths(self.net,dpid,dst)
            path_list = list(paths)
            print path_list
            if len(path_list) > 1:
                print 'calculating several short path (group)'
                group_id = randint(1,99999) #Generate random  group_id TODO Check if doesn't exist
                self.dst_to_group[dpid][dst] = group_id
                self.add_group(datapath,path_list,group_id)
                actions.append(parser.OFPActionGroup(group_id))
            elif len(path_list) == 1:
                print 'calculating one short path'
                self.dst_to_group[dpid][dst] = 0
                path = path_list[0]
                next = path[path.index(dpid) + 1]
                out_port = self.net[dpid][next]['port']
                actions.append(parser.OFPActionOutput(out_port))
             
        else:
            out_port = ofproto.OFPP_FLOOD
            actions.append(parser.OFPActionOutput(out_port))
        #if out_port == None:
        #    out_port = ofproto.OFPP_FLOOD
        #actions.append(parser.OFPActionOutput(out_port))

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            print "datapath %s match %s actions %s" %(datapath,match,actions)
            self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        switch_list = get_switch(self.topology_api_app, None)   
        switches=[switch.dp.id for switch in switch_list]
        self.net.add_nodes_from(switches)
        links_list = get_link(self.topology_api_app, None)
        links=[(link.src.dpid,link.dst.dpid,{'port':link.src.port_no}) for link in links_list]
        self.net.add_edges_from(links)
        links=[(link.dst.dpid,link.src.dpid,{'port':link.dst.port_no}) for link in links_list]
        self.net.add_edges_from(links)
        print "**********List of links"
        print self.net.edges()

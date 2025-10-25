from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, ether_types
import time


THRESHOLD_PPS = 7500
SAMPLING_INTERVAL = 1

class SimpleDDoSDetector(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleDDoSDetector, self).__init__(*args, **kwargs)
        self.flow_stats = {} 
        self.attackers = set()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, idle_timeout=0, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                idle_timeout=idle_timeout, hard_timeout=hard_timeout,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        _ipv4 = pkt.get_protocol(ipv4.ipv4)
        if not _ipv4:
            actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions, data=msg.data)
            datapath.send_msg(out)
            return
        
        src_ip = _ipv4.src
        dst_ip = _ipv4.dst
        
        if src_ip in self.attackers:
            return

        self.check_and_mitigate(datapath, in_port, src_ip)

        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=msg.data)
        datapath.send_msg(out)
        
    
    def check_and_mitigate(self, datapath, in_port, src_ip):
        now = time.time()
        key = (datapath.id, in_port, src_ip) 

        if key not in self.flow_stats:
            self.flow_stats[key] = (1, now)
            return
        
        old_count, start_time = self.flow_stats[key]
        delta_time = now - start_time
        
        current_count = old_count + 1
        self.flow_stats[key] = (current_count, start_time)

        if delta_time >= SAMPLING_INTERVAL:
            
            pps = current_count / delta_time
            
            self.logger.info(f"Host {src_ip} (DPID {datapath.id}): PPS = {pps:.2f}")

            if pps > THRESHOLD_PPS:
                self.logger.warning(f"!!! DDoS Attack Spotted!! Host: {src_ip} (PPS: {pps:.2f}) has reached limit {THRESHOLD_PPS} PPS.")
                self.mitigate_attack(datapath, src_ip)
                self.attackers.add(src_ip)
            
            self.flow_stats[key] = (0, now)


    def mitigate_attack(self, datapath, src_ip):
        """Zablokowanie ruchu złośliwego hosta poprzez dodanie reguły DROP."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=src_ip)
        
        actions = []
        
        self.add_flow(datapath, 2, match, actions, hard_timeout=0, idle_timeout=0)
        
        self.logger.critical(f"Host {src_ip} has ben blocked on switch: {datapath.id}.")
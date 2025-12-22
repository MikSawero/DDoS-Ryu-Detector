import csv
from datetime import datetime
import joblib
import numpy as np
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, ether_types
from ryu.lib import hub
import math
import time

import torch

from autoencoder import DDoSAutoencoder

csv_filename = "flow_stats.csv"

file_initialized = False
writer = None

class HostState:
    def __init__(self):
        self.ewma_rate = 0.0
        self.ewma_dev = 0.0        # odchylenie
        self.last_total_bytes = 0
        self.last_time = 0.0
        self.initialized = False   # First run flag
        self.strikes = 1

class AdaptiveDDoSMonitor(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(AdaptiveDDoSMonitor, self).__init__(*args, **kwargs)

        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)

        self.mac_to_port = {}
        self.host_states = {}
        
        self.whitelist = ['10.0.0.1']
        self.blocked_hosts = set()
        
        self.prev_stats = {}
        self.timer = time.time()
        self.warmup_time = 15.0

        self.interval = 5.0
        self.alpha = 0.250
        self.dev_threshold = 0.8
        self.min_threshold = 500

        self.USE_MODEL = 1
        self.MAKE_CSV = 0

        self.csv_filename = 'data1.csv'
        if self.MAKE_CSV == 1:
            self._init_csv()

        self.model = None
        self.scaler = None
        self.threshold = None
        
        if self.USE_MODEL == 1:
            self.logger.info("Implementing AI...")
            try:
                INPUT_DIM = 7
                DEVICE = torch.device('cpu')
                print("loading model")
                self.model = DDoSAutoencoder(INPUT_DIM).to(DEVICE)
                self.model.load_state_dict(torch.load('ddos_model.pth', map_location=DEVICE))
                self.model.eval()

                print("loading scaler")
                self.scaler = joblib.load('scaler.pkl')
                with open('threshold.txt', 'r') as f:
                    self.threshold = float(f.read())

                print("AI implemented properly")
            except Exception as e:
                self.logger.error(f"Error occured while implementing AI. Working on EWMA")
                self.USE_MODEL = 0
                
    def _init_csv(self):
        try:
            with open(self.csv_filename, 'w', newline='') as f:
                writer = csv.writer(f)
                headers = [
                    'timestamp', 'datapath_id', 'ip_src', 'ip_dst', 
                    'in_port', 'protocol', 
                    'total_packets', 'total_bytes', 
                    'duration_sec', 'flow_bytes_per_sec',
                    'flow_packets_per_sec',
                    'avg_packet_size', 
                    'flows_count_of_src_ip', 
                    'ai_alarm_label'
                ]
                writer.writerow(headers)
            self.logger.info(f"Created csv file: {self.csv_filename}")
        except Exception as e:
            self.logger.error(f"Couldn't create csv file: {e}")

    def append_row_to_csv(self, row):
        try:
            with open(self.csv_filename, 'a', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(row)
        except Exception as e:
            self.logger.error(f"Error during save to csv: {e}")
    
           
    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]
                
    def _calculate_delta(self, key, curr_pkts, curr_bytes, curr_time):
        prev_time, prev_pkts, prev_bytes = self.prev_stats.get(key, (curr_time - 1.0, 0, 0))

        dt = curr_time - prev_time
        d_pkts = curr_pkts - prev_pkts
        d_bytes = curr_bytes - prev_bytes

        if dt <= 0.0001: dt = 1.0

        if d_pkts < 0: d_pkts = curr_pkts
        if d_bytes < 0: d_bytes = curr_bytes

        self.prev_stats[key] = (curr_time, curr_pkts, curr_bytes)

        pps = d_pkts / dt
        bps = d_bytes / dt

        return d_pkts, d_bytes, dt, pps, bps

    def _update_ewma(self, ip_src, total_bytes, current_time):
        state = self.host_states[ip_src]

        if not state.initialized:
            state.last_total_bytes = total_bytes
            state.last_time = current_time
            state.initialized = True
            return 0, 0, False 

        dt = current_time - state.last_time
        if dt < 0.1: return 0, 0, False

        d_bytes = total_bytes - state.last_total_bytes
        if d_bytes < 0: d_bytes = total_bytes

        current_rate = d_bytes / dt

        state.last_total_bytes = total_bytes
        state.last_time = current_time

        diff = current_rate - state.ewma_rate
        state.ewma_rate = state.ewma_rate + (self.alpha * diff)
        state.ewma_dev = (1 - self.alpha) * state.ewma_dev + self.alpha * abs(diff)
        
        dynamic_threshold = state.ewma_rate + (self.dev_threshold * state.ewma_dev)
        
        is_alarm = (current_rate > dynamic_threshold) and (current_rate > self.min_threshold)
        
        return current_rate, dynamic_threshold, is_alarm
    
    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(self.interval)

    def _request_stats(self, datapath):
        self.logger.debug('Asking for stats from: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        datapath = ev.msg.datapath
        dpid = datapath.id
        current_time_epoch = time.time()
        timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        mitigated_this_cycle = set()
        
        src_ip_counts = {}   
        src_ip_bytes = {}    
        valid_stats = [s for s in body if s.packet_count > 0]

        for stat in valid_stats:
            if 'ipv4_src' not in stat.match: continue
            ip_src = stat.match['ipv4_src']
            if ip_src in self.blocked_hosts: continue
            
            src_ip_counts[ip_src] = src_ip_counts.get(ip_src, 0) + 1
            if ip_src not in src_ip_bytes: src_ip_bytes[ip_src] = 0
            src_ip_bytes[ip_src] += stat.byte_count

        for ip_src, total_bytes in src_ip_bytes.items():
            if ip_src in self.whitelist: continue
            if ip_src not in self.host_states: self.host_states[ip_src] = HostState()
            
            state = self.host_states[ip_src]
            current_rate, threshold, is_ewma_alarm = self._update_ewma(ip_src, total_bytes, current_time_epoch)
            if current_rate > 10:
                self.logger.info(f"{ip_src} - Rate {current_rate}")
            if is_ewma_alarm and self.USE_MODEL == 0:
                if (current_time_epoch - self.timer) > self.warmup_time:
                    
                    self.logger.warning(f"EWMA detected: {ip_src} Rate: {current_rate:.0f} > Thr: {threshold:.0f}")
                    
                    if self.MAKE_CSV == 0:
                        state.strikes += 1
                        if state.strikes >= 2:
                             if ip_src not in mitigated_this_cycle:
                                self.logger.critical(f"EWMA Blocked {ip_src}")
                                self.mitigate_attack(datapath, ip_src)
                                mitigated_this_cycle.add(ip_src)
                                self.blocked_hosts.add(ip_src)

        for stat in valid_stats:
            if 'ipv4_src' not in stat.match: continue
            ip_src = stat.match['ipv4_src']
            dst_ip = stat.match.get('ipv4_dst', 'unknown')
            
            if ip_src in self.whitelist or ip_src in self.blocked_hosts: continue

            flow_key = (dpid, ip_src, dst_ip)
            d_pkts, d_bytes, dt, pps, bps = self._calculate_delta(
                flow_key, stat.packet_count, stat.byte_count, current_time_epoch
            )

            if d_pkts <= 0: continue
            
            avg_pkt_size = d_bytes / d_pkts if d_pkts > 0 else 0
            flow_count = src_ip_counts.get(ip_src, 0)

            ai_alarm = False
            
            if self.USE_MODEL == 1 and self.model is not None:
                features = np.array([
                    d_pkts, d_bytes, stat.duration_sec,
                    bps, pps, avg_pkt_size, flow_count
                ]).reshape(1, -1)
                
                try:
                    scaled = self.scaler.transform(features)
                    tensor = torch.FloatTensor(scaled)
                    with torch.no_grad():
                        recon = self.model(tensor)
                        ml_loss = torch.mean((tensor - recon) ** 2).item()
                    
                    if ml_loss > self.threshold:
                        ai_alarm = True
                        self.logger.warning(f"Autoencoder detected: {ip_src} Loss: {ml_loss:.4f}")
                        
                        if self.MAKE_CSV == 0:
                            state.strikes += 1
                            if state.strikes >= 3:
                                if ip_src not in mitigated_this_cycle:
                                    self.logger.critical(f"Autoencoder Blocked {ip_src}")
                                    self.mitigate_attack(datapath, ip_src)
                                    mitigated_this_cycle.add(ip_src)
                                    self.blocked_hosts.add(ip_src)
                                    state.strikes= 0

                except Exception as e:
                     pass

            if self.MAKE_CSV == 1:
                ewma_alarm_state = False
                if ip_src in self.host_states:
                    current_rate, threshold, ewma_alarm_state = self._update_ewma(ip_src, src_ip_bytes.get(ip_src,0), current_time_epoch)

                final_label = 1 if (ai_alarm or ewma_alarm_state) else 0
                
                row = [
                    timestamp_str, dpid, ip_src, dst_ip, 
                    stat.match.get('in_port', 0), stat.match.get('ip_proto', 0),
                    d_pkts, d_bytes, stat.duration_sec,
                    f"{bps:.2f}", f"{pps:.2f}", f"{avg_pkt_size:.2f}",
                    flow_count, final_label 
                ]
                self.append_row_to_csv(row)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions,0, None)

    def add_flow(self, datapath, priority, match, actions,hard_timeout, buffer_id = None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    buffer_id = buffer_id, match=match,
                                    instructions=inst, hard_timeout = hard_timeout)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst, hard_timeout = hard_timeout)
            
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
            
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        
        dst = eth.dst
        src = eth.src

        dpid = format(datapath.id, "d").zfill(16)

        self.mac_to_port.setdefault(dpid, {})

        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            if eth.ethertype == ether_types.ETH_TYPE_IP:
                ip_pkt = pkt.get_protocol(ipv4.ipv4)    
                match = parser.OFPMatch(
                    in_port=in_port,
                    eth_dst=dst,
                    eth_src=src,
                    eth_type=ether_types.ETH_TYPE_IP, 
                    ipv4_src=ip_pkt.src,
                    ipv4_dst=ip_pkt.dst
                )
                priority = 10
            elif eth.ethertype == ether_types.ETH_TYPE_ARP:
                match = parser.OFPMatch(
                    in_port=in_port,
                    eth_dst=dst,
                    eth_src=src,
                    eth_type=ether_types.ETH_TYPE_ARP
                )
                priority = 1
            else:
                match = parser.OFPMatch(
                    in_port=in_port,
                    eth_dst=dst,
                    eth_src=src
                )
                priority = 1

            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, priority, match, actions, 0, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, priority, match, actions, 0)
        
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def mitigate_attack(self, datapath, src_ip):
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=src_ip)

        self.add_flow(datapath, 1000, match,[],hard_timeout=60)

        self.logger.critical(f"Host {src_ip} has been blocked")

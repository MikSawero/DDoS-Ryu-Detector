import time
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, ether_types
from ryu.lib import hub


class AdaptiveDDoSMonitor(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(AdaptiveDDoSMonitor, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.host_stats = {} 
        self.prev_stats = {}

        self.datapaths = {}

        self.alpha = 0.125
        self.multiplier = 2.0
        self.min_pps_floor = 50
        self.monitor_interval = 5

        self.monitor_thread = hub.spawn(self._monitor)


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        actions = {}
        
        match = parser.OFPMatch()
        #actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    @set_ev_cls(ofp_event.EventOFPStateChange,)
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        
        # Switch się podłączył (jest aktywny) -> Dodaj do listy
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('Zarejestrowano switch: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
                
        # Switch się rozłączył (umarł) -> Usuń z listy
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('Wyrejestrowano switch: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle=0, hard=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = {}

        # ZABEZPIECZENIE 1: Obsługa buffer_id
        # Jeśli buffer_id jest None, musimy użyć stałej OFP_NO_BUFFER (liczba całkowita)
        if buffer_id is None:
            buffer_id = ofproto.OFP_NO_BUFFER

        # ZABEZPIECZENIE 2: Wymuszenie liczb całkowitych (int)
        # Python 3 jest restrykcyjny - float (np. 60.0) tutaj spowoduje błąd struct.error
        priority = int(priority)
        idle = int(idle)
        hard = int(hard)

        mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                priority=priority, match=match,
                                instructions=inst, idle_timeout=idle, hard_timeout=hard)
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

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        
        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD
        
        actions = [parser.OFPActionOutput(out_port)]
        if out_port!= ofproto.OFPP_FlOOD:
            match = parser.OFPPacketOut(in_port=in_port, eth_dst=dst, eth_src=src)
            if msg.buffer_id!= ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions, data=msg.data)

        datapath.send_msg(out)
        
    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(self.monitor_interval)
    
    def _request_stats(self, datapath):
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)
    
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        """Analiza statystyk i wykrywanie anomalii EWMA"""
        body = ev.msg.body
        datapath = ev.msg.datapath
        current_time = time.time()

        # A. Agregacja pakietów per IP
        ip_packet_counts = {}
        for stat in body:
            if 'ipv4_src' in stat.match:
                src_ip = stat.match['ipv4_src']
                ip_packet_counts[src_ip] = ip_packet_counts.get(src_ip, 0) + stat.packet_count

        # B. Analiza każdego hosta
        for src_ip, total_packets in ip_packet_counts.items():
            
            # 1. Obliczanie PPS (Packet Per Second)
            if src_ip not in self.prev_stats:
                self.prev_stats[src_ip] = (total_packets, current_time)
                continue

            prev_packets, prev_time = self.prev_stats[src_ip]
            delta_packets = total_packets - prev_packets
            delta_time = current_time - prev_time
            
            if delta_time <= 0: continue # Zabezpieczenie

            # TU JEST TWOJA ZMIENNA:
            current_pps = delta_packets / delta_time
            self.prev_stats[src_ip] = (total_packets, current_time)

            # 2. Logika EWMA
            if src_ip not in self.host_stats:
                # Inicjalizacja nowego hosta
                self.host_stats[src_ip] = {'ewma': current_pps, 'blocked': False}
                continue

            stats = self.host_stats[src_ip]
            
            # Próg dynamiczny z "podłogą"
            dynamic_threshold = max(stats['ewma'] * self.multiplier, self.min_pps_floor)

            # 3. Decyzja
            if current_pps > dynamic_threshold:
                if not stats['blocked']:
                    self.logger.warning(f"!!! ATAK wykryty: {src_ip} (PPS: {current_pps:.1f} > Próg: {dynamic_threshold:.1f})")
                    self.mitigate_attack(datapath, src_ip)
                    stats['blocked'] = True
                # Podczas ataku NIE aktualizujemy średniej!
            else:
                # Aktualizacja średniej kroczącej (wzór EWMA)
                stats['ewma'] = (1 - self.alpha) * stats['ewma'] + (self.alpha * current_pps)
                
                # Recovery (Odblokowanie po ustaniu ataku)
                if stats['blocked'] and current_pps < stats['ewma']:
                    self.logger.info(f"Host {src_ip} uspokoił się. Zdejmuję blokadę w bazie (reguła wygasa sama).")
                    stats['blocked'] = False

    def mitigate_attack(self, datapath, src_ip):
        """Blokuje hosta na 60 sekund"""
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=src_ip)
        
        # Blokada z wysokim priorytetem
        self.add_flow(datapath, 100, match, idle=0, hard=60)
        self.logger.critical(f"Zablokowano hosta {src_ip} na 60s.")

    # Obsługa podłączania/rozłączania switchy (potrzebne do self.datapaths)
    @set_ev_cls(ofp_event.EventOFPStateChange,)
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not hasattr(self, 'datapaths'): self.datapaths = {}
            self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if hasattr(self, 'datapaths') and datapath.id in self.datapaths:
                del self.datapaths[datapath.id]
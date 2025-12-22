#!/usr/bin/python

from logging import info
import random
import sys
import time
from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.term import makeTerms
from mininet.topo import Topo
from mininet.link import TCLink

class DDOSTopology(Topo):
    def build(self):
        switches = []
        for i in range(1,4):
            s = self.addSwitch(f's{i}', protocols = 'OpenFlow13')
            if i > 1:
                self.addLink(f's{i-1}', f's{i}')
            switches.append(s)

        hosts = []
        for i in range (1,10):
            h = self.addHost(f'h{i}', ip =f'10.0.0.{i}/24')
            hosts.append(h)
        
        for i in range (3):
            for j in range (3):
                self.addLink(hosts[i*3 + j], switches[i], bw=100)
        
def startNetwork(controller_ip):

    topology = DDOSTopology()
    c1 = RemoteController('c1', ip=controller_ip, port =6653)
    net = Mininet(topo=topology, link=TCLink, controller=c1)

    try:
        net.start()
        print("*** Network started")

        net.pingAll()
                        
        test_network(net)

        CLI(net)

    except Exception as e:
        print(f"An error occurred: {e}")
        
    finally:
        print("*** Stopping network")
        net.stop()
    


def test_network(net):
    print("Starting network flow test...")

    CYCLE_DURATION = 30  

    current_host_count = len(net.hosts)
    next_host_id = current_host_count + 1
    
    target_switch = random.choice(net.switches)

    cycle_counter = 0

    try:
        while True:
            cycle_counter += 1
            print(f"\n[Cycle {cycle_counter}]")

            for h in net.hosts:
                h.cmd('killall -9 iperf')
            time.sleep(1)

            if cycle_counter % 3 == 0:
                print(f"Adding new host: h{next_host_id}.")
                
                
                new_host_name = f'h{next_host_id}'
                new_host_ip = f'10.0.0.{next_host_id}'
                
                
                new_host = net.addHost(new_host_name, ip=new_host_ip)
                
                
                link = net.addLink(new_host, target_switch)
                
                
                target_switch.attach(link.intf2) 

                new_host.configDefault()         
                
                time.sleep(1) 
                
                new_host.cmd('ping -c 1 10.0.0.1')
                
                print(f"New host {new_host_name} ({new_host_ip}) Started working")
                next_host_id += 1

            all_hosts = net.hosts 

            current_server = net.hosts[0]#random.choice(all_hosts)
            current_server.cmd('iperf -s -D') 
            current_server.cmd('iperf -s -u -D') 

            remaining_hosts = [h for h in all_hosts if h != current_server]
            
            num_clients = int(len(remaining_hosts) * 0.75) 
            if num_clients < 1: num_clients = 1
            
            active_clients = random.sample(remaining_hosts, num_clients)

            print(f"Server: {current_server.name} ({current_server.IP()})")
            print(f"Working: {len(active_clients)} out of {len(all_hosts)})")
            attackers = 1
            for client in active_clients:
                profile = random.choice(['heavy_download', 'web_browsing', 'video_stream', 'attack_udp_flood', 'attack_tcp_syn_flood'])
                cmd = ""
                if profile == 'heavy_download':
                    cmd = f'iperf -c {current_server.IP()} -t {CYCLE_DURATION - 2} &'
                elif profile == 'web_browsing':
                    cmd = f'iperf -c {current_server.IP()} -b 1M -t {CYCLE_DURATION - 2} &'
                elif profile == 'video_stream':
                    cmd = f'iperf -u -c {current_server.IP()} -b 10M -t {CYCLE_DURATION - 2} &'
                elif profile == 'attack_udp_flood':
                    if(attackers > 0):
                        print("udp flood attack - ")
                        print(client)
                        cmd = f'hping3 --udp --flood -p 80 {current_server.IP()} &'
                        attackers -= 1
                elif profile == 'attack_tcp_syn_flood':
                    if(attackers > 0):
                        print("tcp syn flood attack - ")
                        print(client)
                        cmd = f'hping3 -S --flood -p 80 {current_server.IP()} &'
                        attackers -= 1

                client.cmd(cmd)

            time.sleep(CYCLE_DURATION)

    except KeyboardInterrupt:
        print("\nStopped network test")
        for h in net.hosts:
            h.cmd('killall -9 iperf')

if __name__ == '__main__':
    ctrl_ip = '127.0.0.1'
    setLogLevel('info')
    if len(sys.argv) > 1:
        ctrl_ip = sys.argv[1]
    startNetwork(controller_ip=ctrl_ip)
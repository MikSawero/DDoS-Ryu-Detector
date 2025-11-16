#!/usr/bin/python

from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.term import makeTerms

def DDOSTopology():
    # Ustawiamy adres IP i port kontrolera (domyślny dla Ryu)
    net = Mininet(controller=lambda name: RemoteController(name, ip='127.0.0.1', port=6653), 
                  switch=OVSKernelSwitch, 
                  waitConnected=True)

    # 1. Dodaj Kontroler
    c1 = net.addController('c1')

    # 2. Dodaj Przełącznik
    s1 = net.addSwitch('s1')

    # 3. Dodaj Hosty
    h1 = net.addHost('h1', ip='10.0.0.1/24')
    h2 = net.addHost('h2', ip='10.0.0.2/24')
    h3 = net.addHost('h3', ip='10.0.0.3/24')
    h4 = net.addHost('h4', ip='10.0.0.4/24')
    h5 = net.addHost('h5', ip='10.0.0.5/24')
    h6 = net.addHost('h6', ip='10.0.0.6/24') # Ofiara
    hosts = [h1, h2, h3, h4, h5, h6]
    # 4. Dodaj Linki
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(h3, s1)
    net.addLink(h4, s1)
    net.addLink(h5, s1)
    net.addLink(h6, s1) # Serwer ofiara
    # 5. Uruchom Sieć
    net.start()
    makeTerms(hosts, title='Host')
    print("Mininet uruchomiony. Host 10.0.0.6 jest ofiarą.")

    # 6. Uruchom CLI Mininet
    CLI(net)

    # 7. Zatrzymaj Sieć
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    DDOSTopology()
#!/bin/bash

gnome-terminal --title="Mininet" -- /bin/bash -c \
    "sudo mn -c;
    
gnome-terminal --title="Ryu Controler" -- /bin/bash -c \
    "ryu-manager ryu.app.simple_switch_13 'ddos_detector.py'; \
    echo '-- Controler has stopped --'; exec bash"

sleep 2

# gnome-terminal --title="Mininet": -- /bin/bash -c \
#     "sudo mn --controller=remote,ip=127.0.0.1,port=8000 \
#     --switch=ovs,protocols=OpenFlow13 \
#     --topo=tree,depth=2,fanout=2; \
#     echo '-- Mininet has stopped --'; exec bash"

gnome-terminal --title="Mininet" -- /bin/bash -c \
    "sudo mn -c; \
    sudo python3 'topo_ddos.py'; \
    echo '-- Mininet has stopped'; exec bash"
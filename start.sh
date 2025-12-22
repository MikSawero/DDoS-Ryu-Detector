#!/bin/bash


sudo lsof -t -i :6653 | xargs sudo kill -9
#sudo kill -9 $(sudo lsof -t -i :6633)
sudo mn -c
echo "czysto"
sleep 5

ryu-manager ryu.conf ddos_detector.py > ryu.log 2>&1 &
RYU_PID=$!

sleep 3


sudo python3 topo_ddos.py 
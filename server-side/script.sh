#!/bin/bash
cur_date=$EPOCHSECONDS
echo ${cur_date}
OUTPUT_FILE="/home/ruslan/1/papka/traffic_${cur_date}.pcap"
echo $OUTPUT_FILE
tcpdump -i enp0s8 -G 10 -w $OUTPUT_FILE
sudo chmod 777 $OUTPUT_FILE
echo "Im here"
sudo python3 "/home/ruslan/1/scapy_run.py" $OUTPUT_FILE

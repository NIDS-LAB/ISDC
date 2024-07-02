#!/bin/bash

i=1
j=0
cnt=0
while read line
do
	iface="s"$i"-eth"$line
	tcpreplay -i $iface -K --loop 1 --pps 80 " ./example/pcap"$j.pcap &

	i=$(($i + 1))
	j=$(($j + 1))
	cnt=$(($cnt + 1))
done <<< `cat host_port.txt | cut -d " " -f 2`

wait

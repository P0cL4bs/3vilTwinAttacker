#!/bin/bash 
# TCP proxy using IPTables
# tcpproxy LOCAL_IP LOCAL_PORT REMOTE_IP REMOTE_PORT 

IPTABLES=/sbin/iptables 
 
echo 1 > /proc/sys/net/ipv4/ip_forward 
sysctl net.ipv4.conf.all.forwarding=1
# Flush nat table 
$IPTABLES -t nat -F 
 
# tcpproxy LOCAL_IP LOCAL_PORT REMOTE_IP REMOTE_PORT 
listen_address=$1
listen_port=$2
source_address=$1
#    source_port=$4
destination_address=$3
destination_port=$4
 
$IPTABLES -t nat -A PREROUTING --dst $listen_address -p tcp --dport $listen_port -j DNAT --to-destination $destination_address:$destination_port 
$IPTABLES -t nat -A POSTROUTING -j MASQUERADE

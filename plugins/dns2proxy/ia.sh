#!/bin/bash

# Lanzar: start.sh <interfaz> <ip escucha dns> <routing IP>
#
# Example: start.sh eth0 192.168.1.101 192.168.1.200



interfaz=$1
dnsserver=$2
routingIP=$3

adminIP="192.168.1.82"

ifconfig $interfaz:1 $routingIP

iptables -F
iptables -F -t nat
iptables -P INPUT DROP 
iptables -A INPUT -p tcp --dport 443  -j REJECT --reject-with tcp-reset
#iptables -A INPUT -p tcp --dport 443  -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -s $adminIP -j ACCEPT

#iptables -A INPUT -p tcp --dport 5900 -j ACCEPT
#iptables -A INPUT -p tcp --dport 5901 -j ACCEPT
iptables -A INPUT -p udp --dport 53 -j ACCEPT
iptables -A INPUT -p udp --sport 53 -j ACCEPT

iptables -A INPUT -p udp -j REJECT
iptables -A INPUT -p icmp -j REJECT
iptables -A INPUT -p tcp -m state --state RELATED,ESTABLISHED -j ACCEPT

modprobe ip_nat_ftp
modprobe ip_conntrack_ftp
iptables -A INPUT -m helper --helper ftp -j ACCEPT

python2.6 dns2proxy.py $interfaz $dnsserver $routingIP 



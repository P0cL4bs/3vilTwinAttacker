#!/bin/sh

iptables -P INPUT ACCEPT
iptables -F
iptables -F -t nat

killall python2.6

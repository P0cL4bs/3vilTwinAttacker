from struct import pack
from time import sleep,asctime
from random import randint
from base64 import b64encode
from os import popen,path,walk,stat,kill,remove
from subprocess import check_output,Popen,PIPE,STDOUT,CalledProcessError,call
from re import search,compile,VERBOSE,IGNORECASE
import netifaces
from scapy.all import *
from PyQt4 import QtCore
from PyQt4 import QtGui
import logging
import signal
try:
    import configparser
except:
    import ConfigParser as configparser
import core.utility.constants as C
from shlex import split
from glob import glob

"""
Description:
    This program is a core for modules wifi-pumpkin.py. file which includes all Implementation
    for modules.

Copyright:
    Copyright (C) 2015-2017 Marcos Nesster P0cl4bs Team
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

class set_monitor_mode(QtGui.QDialog):
    ''' enable/disable interface for monitor mode '''
    def __init__(self,interface,parent = None):
        super(set_monitor_mode, self).__init__(parent)
        self.interface = interface
    def setEnable(self):
        try:
            output  = check_output(['ifconfig', self.interface, 'down'])
            output += check_output(['iwconfig', self.interface, 'mode','monitor'])
            output += check_output(['ifconfig', self.interface, 'up'])
            if len(output) > 0:QtGui.QMessageBox.information(self,'Monitor Mode',
            'device %s.%s'%(self.interface,output))
            return self.interface
        except Exception ,e:
            QtGui.QMessageBox.information(self,'Monitor Mode',
            'mode on device %s.your card does not support Monitor Mode'%(self.interface))
    def setDisable(self):
        Popen(['ifconfig', self.interface, 'down'])
        Popen(['iwconfig', self.interface, 'mode','managed'])
        Popen(['ifconfig', self.interface, 'up'])


class ThreadPhishingServer(QtCore.QThread):
    ''' thread for get ouput the Phishing file .log requests '''
    send = QtCore.pyqtSignal(str)
    def __init__(self,cmd,):
        QtCore.QThread.__init__(self)
        self.cmd     = cmd
        self.process = None

    def run(self):
        print 'Starting Thread:' + self.objectName()
        self.process = Popen(self.cmd,stdout=PIPE,stderr=STDOUT)
        for line in iter(self.process.stdout.readline, b''):
            self.send.emit(line.rstrip())

    def stop(self):
        print 'Stop thread:' + self.objectName()
        if self.process is not None:
            self.process.terminate()


loggers = {}
'''http://stackoverflow.com/questions/17035077/python-logging-to-multiple-log-files-from-different-classes'''
def setup_logger(logger_name, log_file,key=str(), level=logging.INFO):
    global loggers
    if loggers.get(logger_name):
        return loggers.get(logger_name)
    else:
        logger = logging.getLogger(logger_name)
        logger.propagate = False
        formatter = logging.Formatter('SessionID[{}] %(asctime)s : %(message)s'.format(key))
        fileHandler = logging.FileHandler(log_file, mode='a')
        fileHandler.setFormatter(formatter)
        logger.setLevel(logging.INFO)
        logger.addHandler(fileHandler)
    return logger

class Refactor:
    @staticmethod
    def htmlContent(title):
        html = {'htmlheader':[
            '<html>',
            '<head>',
            '<title>'+title+'</title>',
            '<meta http-equiv="Content-Type" content="text/html; charset=utf-8">',
            '<style type="text/css">',
            '.ln { color: rgb(0,0,0); font-weight: normal; font-style: normal; }',
            '.s0 { color: rgb(128,128,128); }',
            '.s1 { color: rgb(169,183,198); }',
            '.s2 { color: rgb(204,120,50); font-weight: bold; }',
            '.s3 { color: rgb(204,120,50); }',
            '.s4 { color: rgb(165,194,97); }',
            '.s5 { color: rgb(104,151,187); }',
            '</style>',
            '</head>',
            '<BODY BGCOLOR="#2b2b2b">',
            '<TABLE CELLSPACING=0 CELLPADDING=5 COLS=1 WIDTH="100%" BGCOLOR="#C0C0C0" >',
            '<TR><TD><CENTER>',
            '<FONT FACE="Arial, Helvetica" COLOR="#000000">'+title+'</FONT>',
            '</center></TD></TR></TABLE>',
            '<pre>',
            ]
        }
        return html

    @staticmethod
    def get_content_by_session(filelines,sessionID=str):
        ''' find lines in session by ID '''
        filterSession = []
        sessiongrap = 'SessionID[{}]'.format(sessionID)
        for line in filelines:
            if sessiongrap in line:
                filterSession.append(line)
        return ''.join(filterSession)

    @staticmethod
    def exportHtml(unchecked={},sessionID='',dataLogger=[],APname=''):
        ''' funtion for get and check report files '''
        readFile = {
         'dhcp': {C.LOG_DHCP:[]},
         'urls': {C.LOG_URLCAPTURE:[]},
         'hostapd': {C.LOG_HOSTAPD:[]},
         'bdfproxy': {C.LOG_BDFPROXY:[]},
         'credentials': {C.LOG_CREDSCAPTURE:[]},
         'dns2proxy': {C.LOG_DNS2PROXY:[]},
         'injectionPage': {C.LOG_SSLSTRIP:[]},
         'dnsspoofAP': {C.LOG_DNSSPOOF:[]},
         'responder': {C.LOG_RESPONDER:[]},
         'pumpkinproxy': {C.LOG_PUMPKINPROXY:[]},
         'tcpproxy': {C.LOG_TCPPROXY:[]},
         'phishing': {C.LOG_PHISHING:[]},}
        count_files = len(readFile.keys())
        if unchecked != {}:
            for key in unchecked.keys(): readFile.pop(key)
        for key in readFile.keys():
            for filename in readFile[key]:
                with open(filename,'r') as file:
                    if len(sessionID) != 0:
                        content = Refactor.get_content_by_session(file.readlines(),sessionID)
                        readFile[key][filename] = content
                    else:
                        readFile[key][filename] = file.read()

        contenthtml,HTML,emptyFile,activated_Files = Refactor.htmlContent('WiFi-Pumpkin Report Logger'),'',[],[]
        for i in contenthtml['htmlheader']: HTML += i+"\n"
        if dataLogger != []:
            HTML += '</span><span class="s2">Session information::</span><span class="s1">\n\n'
            HTML += '</span><span class="s5">[*] ESSID AP: {}</span><span class="s0"></span>\n'.format(APname)
            HTML += '</span><span class="s5">[*] AP Create at: </span><span class="s0">'+dataLogger[0]+'</span>\n'
            HTML += '</span><span class="s5">[*] AP Down   at: </span><span class="s0">'+dataLogger[1]+'</span>\n\n'
        HTML += '</span><span class="s5">Report Generated at::</span><span class="s0">'+asctime()+'</span>\n\n'
        HTML += '</span><span class="s4"><br></span><span class="s1">\n'
        for key in readFile.keys():
            if len(readFile[key][readFile[key].keys()[0]]) > 0:
                HTML += '</span><span class="s2">-[ {} Logger ]-</span><span class="s1">\n'.format(key)
                HTML += readFile[key][readFile[key].keys()[0]]
                HTML += '</span><span class="s4"><br><br></span><span class="s1">\n'
                activated_Files.append(key)
            elif Refactor.getSize(readFile[key].keys()[0]) == 0:
                emptyFile.append(key)
        HTML += '</span></pre>\n<TABLE CELLSPACING=0 CELLPADDING=5 COLS=1 WIDTH="100%" BGCOLOR="#C0C0C0" >\
        <TR><TD><CENTER>''<FONT FACE="Arial, Helvetica" COLOR="#000000">WiFi-Pumpkin (C) 2015-2017 P0cL4bs Team' \
        '</FONT></center></TD></TR></TABLE></body>\n</html>\n'

        Load_ = {'HTML': HTML,'Files':[readFile[x].keys()[0] for x in readFile.keys()],
        'activated_Files':activated_Files,'empty_files': emptyFile, 'Count': count_files}
        return Load_

    @staticmethod
    def settingsNetworkManager(interface=str,Remove=False):
        ''' mac address of interface to exclude '''
        networkmanager = C.NETWORKMANAGER
        config  = configparser.RawConfigParser()
        MAC     = Refactor.get_interface_mac(interface)
        exclude = {'MAC': 'mac:{}'.format(MAC),'interface': 'interface-name:{}'.format(interface)}
        if  not Remove:
            if path.exists(networkmanager):
                config.read(networkmanager)
                try:
                    config.add_section('keyfile')
                except configparser.DuplicateSectionError, e:
                    config.set('keyfile','unmanaged-devices','{}'.format(
                        exclude['interface'] if MAC != None else exclude['MAC']))
                else:
                    config.set('keyfile','unmanaged-devices','{}'.format(
                        exclude['interface'] if MAC != None else exclude['MAC']))
                finally:
                    with open(networkmanager, 'wb') as configfile:
                        config.write(configfile)
                return True
            return False
        elif Remove:
            if path.exists(networkmanager):
                config.read(networkmanager)
                try:
                    config.remove_option('keyfile','unmanaged-devices')
                    with open(networkmanager, 'wb') as configfile:
                        config.write(configfile)
                        return True
                except configparser.NoSectionError:
                    return True
            return False

    @staticmethod
    def set_ip_forward(value):
        '''set forward to redirect packets '''
        with open(C.IPFORWARD, 'w') as file:
            file.write(str(value))
            file.close()
    '''
    http://stackoverflow.com/questions/159137/getting-mac-address
    '''
    @staticmethod
    def getHwAddr(ifname):
        ''' another functions for get mac adreess '''
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        info = ioctl(s.fileno(), 0x8927,  pack('256s', ifname[:15]))
        return ':'.join(['%02x' % ord(char) for char in info[18:24]])

    @staticmethod
    def kill_procInterfaceBusy():
        ''' kill network processes are keeping the interface busy '''
        willkill = ('wpa_supplicant','dhclient') # for ethernet conntion
        proc = Popen(['ps', '-A'], stdout=PIPE)
        out, err = proc.communicate()
        try:
            for line in out.splitlines():
                for name in willkill:
                    if name in line:
                        pid = int(line.split()[0])
                        kill(pid, signal.SIGKILL)
        except Exception as e:
            print('[!] Error: find process network: {}'.format(str(e)))

    @staticmethod
    def get_interfaces():
        ''' get interfaces and check status connection '''
        interfaces = {'activated':[None,None],'all':[],'gateway':None,'IPaddress': None}
        interfaces['all'] = netifaces.interfaces()
        try:
            interfaces['gateway'] = netifaces.gateways()['default'][netifaces.AF_INET][0]
            interfaces['activated'][0] = netifaces.gateways()['default'][netifaces.AF_INET][1]
            interfaces['IPaddress'] = netifaces.ifaddresses(interfaces['activated'][0])[netifaces.AF_INET][0]['addr']
            # check type interfaces connected with internet
            itype = None
            iface = interfaces['activated'][0]
            if iface[:-1] in ['ppp']:
                itype = 'ppp'
            elif iface[:2] in ['wl', 'wi', 'ra', 'at']:
                itype = 'wireless'
            elif iface[:2] in ['en','et']:
                itype = 'ethernet'
            interfaces['activated'][1] = itype
        except KeyError:
            pass
        return interfaces

    @staticmethod
    def get_supported_interface(dev):
        ''' get all support mode from interface wireless  '''
        _iface = {'info':{},'Supported': []}
        try:
            output = check_output(['iw',dev,'info'],stderr=STDOUT, universal_newlines=True)
            for line in output.split('\n\t'):
                _iface['info'][line.split()[0]] = line.split()[1]
            rulesfilter = '| grep "Supported interface modes" -A 10 | grep "*"'
            supportMode = popen('iw phy{} info {}'.format(_iface['info']['wiphy'],rulesfilter)).read()
            for mode in supportMode.split('\n\t\t'):
                _iface['Supported'].append(mode.split('* ')[1])
        except CalledProcessError:
            return _iface
        return _iface

    @staticmethod
    def get_Ipaddr(card):
        ''' get ipadress by interface name'''
        if card == None:
            return get_if_addr('{}'.format(Refactor.get_interfaces()['activated'][0]))
        return get_if_addr('{}'.format(card))

    @staticmethod
    def get_mac(host):
        ''' return mac by ipadress local network '''
        fields = popen('grep "%s " /proc/net/arp' % host).read().split()
        if len(fields) == 6 and fields[3] != "00:00:00:00:00:00":
            return fields[3]
        else:
            return None

    @staticmethod
    def get_interface_mac(device):
        ''' get mac from interface local system '''
        result = check_output(["ifconfig", device], stderr=STDOUT, universal_newlines=True)
        m = search("(?<=HWaddr\\s)(.*)", result)
        n = search("(?<=ether\\s)(.*)", result)
        if hasattr(m, "group") : return m.group(0).strip()
        if hasattr(n, "group") : return n.group(0).split()[0]
        return None

    @staticmethod
    def randomMacAddress(prefix):
        '''generate random mac for prefix '''
        for ount in xrange(6-len(prefix)):
            prefix.append(randint(0x00, 0x7f))
        return ':'.join(map(lambda x: "%02x" % x, prefix))


    @staticmethod
    def check_is_mac(value):
        '''check if mac is mac type '''
        checked = compile(r"""(
         ^([0-9A-F]{2}[-]){5}([0-9A-F]{2})$
        |^([0-9A-F]{2}[:]){5}([0-9A-F]{2})$
        )""",VERBOSE|IGNORECASE)
        if checked.match(value) is None:return False
        else:
            return True

    @staticmethod
    def find(name, paths):
        ''' find all files in directory '''
        for root, dirs, files in walk(paths):
            if name in files:
                return path.join(root, name)
    @staticmethod
    def getSize(filename):
        ''' return files size by pathnme '''
        st = stat(filename)
        return st.st_size

    @staticmethod
    def generateSessionID():
        ''' generate session encoded base64 '''
        return str(b64encode(str(random.randint(0,100000))))

class waiterSleepThread(QtCore.QThread):
    ''' Simples Thread for wait 10 segunds for check update app'''
    quit = QtCore.pyqtSignal(object)
    def __int__(self,parent=None):
        super(waiterSleepThread, self).__init__(self,parent)
    def run(self):
        sleep(10),self.quit.emit(True)

def is_hexadecimal(text):
    try:
        int(text, 16)
    except ValueError:
        return False
    else:
        return True

def is_ascii( text):
    try:
        text.decode('ascii')
    except UnicodeDecodeError:
        return False
    else:
        return True

def exec_bash(command):
    ''' run command on background hide output'''
    popen(command)

def del_item_folder(directorys):
    ''' delete all items in folder '''
    for folder in directorys:
        files = glob(folder)
        for file in files:
            if path.isfile(file) and not '.py' in file:
                remove(file)

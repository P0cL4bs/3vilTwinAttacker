import logging
import signal
import argparse
import threading
from re import search
from sys import stdout
from time import asctime
from os import path,stat,getpgid,setsid,killpg,devnull
from twisted.web import http
from twisted.internet import reactor
from twisted.internet.defer import DebugInfo
del DebugInfo.__del__
from core.utils import setup_logger,Refactor
from subprocess import (Popen,PIPE,STDOUT)
from PyQt4.QtCore import QThread,pyqtSignal,SIGNAL,pyqtSlot,QProcess,QObject,SLOT
from PyQt4.QtGui import QMessageBox
from plugins.external.sergio_proxy.plugins import *
from multiprocessing import Process,Manager
from core.servers.proxy.controller.handler import MasterHandler
from mitmproxy import controller, proxy
from mitmproxy.proxy.server import ProxyServer

"""
Description:
    This program is a core for wifi-pumpkin.py. file which includes functionality
    for threads core program.

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


class ProcessThreadScanner(threading.Thread):
    ''' thread for run airodump-ng backgroung and get data'''
    def __init__(self, cmd):
        threading.Thread.__init__(self)
        self.cmd = cmd
    def run(self):
        self.process = Popen(self.cmd,stdout=PIPE,stderr=STDOUT)
        for line in iter(self.process.stdout.readline, b''):
            pass
    def stop(self):
        if self.process is not None:
            self.process.terminate()

class ThreadPopen(QThread):
    def __init__(self,cmd):
        QThread.__init__(self)
        self.cmd = cmd
        self.process = None

    def getNameThread(self):
        return '[New Thread {} ({})]'.format(self.currentThreadId(),self.objectName())

    def run(self):
        print '[New Thread {} ({})]'.format(self.currentThreadId(),self.objectName())
        self.process = Popen(self.cmd,stdout=PIPE,stderr=STDOUT,close_fds=True)
        for line in iter(self.process.stdout.readline, b''):
            self.emit(SIGNAL('Activated( QString )'),line.rstrip())

    def stop(self):
        print 'Stop thread:' + self.objectName()
        if self.process is not None:
            self.process.terminate()
            self.process = None

class ThRunDhcp(QThread):
    ''' thread: run DHCP on background fuctions'''
    sendRequest = pyqtSignal(object)
    def __init__(self,args,session):
        QThread.__init__(self)
        self.args    = args
        self.session = session
        self.process = None

    def getNameThread(self):
        return '[New Thread {} ({})]'.format(self.currentThreadId(),self.objectName())

    def run(self):
        self.process = Popen(self.args,
        stdout=PIPE,stderr=STDOUT,preexec_fn=setsid)
        print '[New Thread {} ({})]'.format(self.process.pid,self.objectName())
        setup_logger('dhcp', './logs/AccessPoint/dhcp.log',self.session)
        loggerDhcp = logging.getLogger('dhcp')
        loggerDhcp.info('---[ Start DHCP '+asctime()+']---')
        for line,data in enumerate(iter(self.process.stdout.readline, b'')):
            if 'DHCPREQUEST for' in data.rstrip():
                self.sendRequest.emit(data.split())
            elif 'DHCPACK on' in data.rstrip():
                self.sendRequest.emit(data.split())
            loggerDhcp.info(data.rstrip())

    def stop(self):
        print 'Thread::[{}] successfully stopped.'.format(self.objectName())
        if self.process is not None:
            killpg(getpgid(self.process.pid), signal.SIGTERM)


class ThreadScan(QThread):
    def __init__(self,gateway):
        QThread.__init__(self)
        self.gateway = gateway
        self.result = ''
    def run(self):
        try:
            nm = PortScanner()
            a=nm.scan(hosts=self.gateway, arguments='-sU --script nbstat.nse -O -p137')
            for k,v in a['scan'].iteritems():
                if str(v['status']['state']) == 'up':
                    try:
                        ip = str(v['addresses']['ipv4'])
                        hostname = str(v['hostscript'][0]['output']).split(',')[0]
                        hostname = hostname.split(':')[1]
                        mac = str(v['hostscript'][0]['output']).split(',')[2]
                        if search('<unknown>',mac):mac = '<unknown>'
                        else:mac = mac[13:32]
                        self.result = ip +'|'+mac.replace('\n','')+'|'+hostname.replace('\n','')
                        self.emit(SIGNAL('Activated( QString )'),self.result)
                    except :
                        pass
        except NameError:
            QMessageBox.information(self,'Missing Module','The module python-nmap is not installed')

class ThreadFastScanIP(QThread):
    sendDictResultscan = pyqtSignal(object)
    def __init__(self,gateway,iprange,parent=None):
        super(ThreadFastScanIP, self).__init__(parent)
        self.ip_range = str(iprange).split('-')
        self.workingThread = True
        self.gatewayNT = gateway[:len(gateway)-len(gateway.split('.').pop())]
        self.setTerminationEnabled(True)

    def run(self):
        self.jobs = []
        self.manager = Manager()
        on_ips = self.manager.dict()
        for n in xrange(int(self.ip_range[0]),int(self.ip_range[1])):
            ip='%s{0}'.format(n)%(self.gatewayNT)
            if not self.workingThread: break
            p = Process(target=self.working,args=(ip,on_ips))
            self.jobs.append(p)
            p.start()
        for proc in self.jobs:
            proc.join()
            proc.terminate()
        self.sendDictResultscan.emit(on_ips)

    def working(self,ip,lista):
        with open(devnull, 'wb') as limbo:
            result=Popen(['ping', '-c', '1', '-n', '-W', '1', ip],
            stdout=limbo, stderr=limbo).wait()
            if not result:
                if Refactor.get_mac(ip) == None:
                    lista[ip] = ip + '|' + 'Not found'
                else:
                    lista[ip] = ip + '|' + Refactor.get_mac(ip)
    def stop(self):
        self.workingThread = False


class ProcessThread(QObject):
    _ProcssOutput = pyqtSignal(object)
    def __init__(self,cmd,):
        QObject.__init__(self)
        self.cmd = cmd

    def getNameThread(self):
        return '[New Thread {} ({})]'.format(self.procThread.pid(),self.objectName())

    @pyqtSlot()
    def readProcessOutput(self):
        self.data = str(self.procThread.readAllStandardOutput())
        self._ProcssOutput.emit(self.data)

    def start(self):
        self.procThread = QProcess(self)
        self.procThread.setProcessChannelMode(QProcess.MergedChannels)
        QObject.connect(self.procThread, SIGNAL('readyReadStandardOutput()'), self, SLOT('readProcessOutput()'))
        self.procThread.start(self.cmd.keys()[0],self.cmd[self.cmd.keys()[0]])
        print '[New Thread {} ({})]'.format(self.procThread.pid(),self.objectName())

    def stop(self):
        print 'Thread::[{}] successfully stopped.'.format(self.objectName())
        if hasattr(self,'procThread'):
            self.procThread.terminate()
            self.procThread.waitForFinished()
            self.procThread.kill()


class ProcessHostapd(QObject):
    statusAP_connected = pyqtSignal(object)
    statusAPError = pyqtSignal(object)
    def __init__(self,cmd,session):
        QObject.__init__(self)
        self.cmd         = cmd
        self.session     = session
        self.errorAPDriver = ('AP-DISABLED',
        'Failed to initialize interface',
        'nl80211 driver initialization failed.',
        'errors found in configuration file')

    def getNameThread(self):
        return '[New Thread {} ({})]'.format(self.procHostapd.pid(),self.objectName())

    @pyqtSlot()
    def read_OutputCommand(self):
        self.data = str(self.procHostapd.readAllStandardOutput())
        if 'AP-STA-DISCONNECTED' in self.data.rstrip() or 'inactivity (timer DEAUTH/REMOVE)' in self.data.rstrip():
            self.statusAP_connected.emit(self.data.split()[2])
        self.log_hostapd.info(self.data)
        for error in self.errorAPDriver:
            if self.data.find(error) != -1:
                return self.statusAPError.emit(self.data)

    def start(self):
        self.makeLogger()
        self.procHostapd = QProcess(self)
        self.procHostapd.setProcessChannelMode(QProcess.MergedChannels)
        QObject.connect(self.procHostapd, SIGNAL('readyReadStandardOutput()'), self, SLOT('read_OutputCommand()'));
        self.procHostapd.start(self.cmd.keys()[0],self.cmd[self.cmd.keys()[0]])
        print '[New Thread {} ({})]'.format(self.procHostapd.pid(),self.objectName())

    def makeLogger(self):
        setup_logger('hostapd', './logs/AccessPoint/hostapd.log',self.session)
        self.log_hostapd = logging.getLogger('hostapd')

    def stop(self):
        print 'Thread::[{}] successfully stopped.'.format(self.objectName())
        if hasattr(self,'procHostapd'):
            QObject.disconnect(self.procHostapd,
            SIGNAL('readyReadStandardOutput()'), self, SLOT('read_OutputCommand()'))
            self.procHostapd.terminate()
            self.procHostapd.waitForFinished()
            self.procHostapd.kill()

class ThreadReactor(QThread):
    '''Thread: run reactor twisted on brackground'''
    def __init__(self,parent=None):
        super(ThreadReactor, self).__init__(parent)
    def run(self):
        reactor.run(installSignalHandlers=False)
    def stop(self):
        reactor.callFromThread(reactor.stop)

class ThreadPumpkinProxy(QObject):
    '''Thread: run Pumpkin-Proxy mitmproxy on brackground'''
    send = pyqtSignal(object)
    def __init__(self,session=None):
        QObject.__init__(self)
        self.session = session

    def start(self):
        config = proxy.ProxyConfig(port=8080,mode='transparent')
        print "[*] Pumpkin-Proxy running on port:8080 \n"
        server = ProxyServer(config)
        server.allow_reuse_address = True
        self.m = MasterHandler(server,self.session)
        self.m.run(self.send)

    def stop(self):
        self.m.shutdown()
        print 'Thread::[{}] successfully stopped.'.format(self.objectName())


class Thread_sslstrip(QThread):
    '''Thread: run sslstrip on brackground'''
    def __init__(self,port,plugins={},data= {},session=None):
        QThread.__init__(self)
        self.port     = port
        self.plugins  = plugins
        self.loaderPlugins = data
        self.session    = session

    def getNameThread(self):
        return '[New Thread {} ({})]'.format(self.currentThreadId(),self.objectName())

    def run(self):
        print 'SSLstrip v0.9 + POC by Leonardo Nve'
        killSessions = True
        spoofFavicon = False
        listenPort   = self.port
        from plugins.external.sslstrip.StrippingProxy import StrippingProxy
        from plugins.external.sslstrip.URLMonitor import URLMonitor
        from plugins.external.sslstrip.CookieCleaner import CookieCleaner
        if self.loaderPlugins['plugins'] != None:
            self.plugins[self.loaderPlugins['plugins']].getInstance()._activated = True
            self.plugins[self.loaderPlugins['plugins']].getInstance().setInjectionCode(
                self.loaderPlugins['Content'],self.session)
        URLMonitor.getInstance().setFaviconSpoofing(spoofFavicon)
        CookieCleaner.getInstance().setEnabled(killSessions)
        strippingFactory              = http.HTTPFactory(timeout=10)
        strippingFactory.protocol     = StrippingProxy
        self.connector = reactor.listenTCP(int(listenPort), strippingFactory)

    def stop(self):
        print 'Thread::[{}] successfully stopped.'.format(self.objectName())
        self.connector.loseConnection()
        self.connector.connectionLost(reason=None)

class Thread_sergioProxy(QThread):
    '''Thread: run sergio-proxy on brackground'''
    def __init__(self,port,plugins={},data= {},session=None):
        QThread.__init__(self)
        self.port          = port
        self.PumpPlugins   = plugins
        self.loaderPlugins = data
        self.session       = session

    def getNameThread(self):
        return '[New Thread {} ({})]'.format(self.currentThreadId(),self.objectName())

    def run(self):
        killSessions = True
        spoofFavicon = False
        listenPort   = self.port
        sslstrip_version = "0.9"
        sergio_version = "0.2.1"
        if self.loaderPlugins['plugins'] != None:
            self.PumpPlugins[self.loaderPlugins['plugins']].getInstance()._activated = True
            self.PumpPlugins[self.loaderPlugins['plugins']].getInstance().setInjectionCode(
                self.loaderPlugins['Content'],self.session)
        # load plugins will be implemented coming soon
        parser = argparse.ArgumentParser(
               description="Sergio Proxy v%s - An HTTP MITM Tool" % sergio_version,
               epilog="Use wisely, young Padawan.",
               fromfile_prefix_chars='@' )
        #add sslstrip options
        sgroup = parser.add_argument_group("sslstrip",
               "Options for sslstrip library")

        sgroup.add_argument("-w","--write",type=argparse.FileType('w'),
               metavar="filename", default=stdout,
               help="Specify file to log to (stdout by default).")
        sgroup.add_argument("--log-level",type=str,
               choices=['debug','info','warning','error'],default="info",
               help="Specify file to log to (stdout by default).")
        slogopts = sgroup.add_mutually_exclusive_group()
        slogopts.add_argument("-p","--post",action="store_true",
               help="Log only SSL POSTs. (default)")
        slogopts.add_argument("-s","--ssl",action="store_true",
               help="Log all SSL traffic to and from server.")
        slogopts.add_argument("-a","--all",action="store_true",
               help="Log all SSL and HTTP traffic to and from server.")
        sgroup.add_argument("-l","--listen",type=int,metavar="port",default=10000,
               help="Port to listen on (default 10000)")
        sgroup.add_argument("-f","--favicon",action="store_true",
                help="Substitute a lock favicon on secure requests.")
        sgroup.add_argument("-k","--killsessions",action="store_true",
                help="Kill sessions in progress.")

        #add msf options
        sgroup = parser.add_argument_group("MSF",
                "Generic Options for MSF integration")

        sgroup.add_argument("--msf-path",type=str,default="/pentest/exploits/framework/",
                help="Path to msf (default: /pentest/exploits/framework)")
        sgroup.add_argument("--msf-rc",type=str,default="/tmp/tmp.rc",
                help="Specify a custom rc file (overrides all other settings)")
        sgroup.add_argument("--msf-user",type=str,default="root",
                help="Specify what user to run Metasploit under.")
        sgroup.add_argument("--msf-lhost",type=str,default="192.168.1.1",
                help="The IP address Metasploit is listening at.")

        plugin_classes = plugin.Plugin.__subclasses__()
        #Initialize plugins
        plugins = []
        try:
            for p in plugin_classes:
                plugins.append(p())
        except:
            print "Failed to load plugin class %s" % str(p)

        #Give subgroup to each plugin with options
        try:
            for p in plugins:
                if p.desc == "":
                    sgroup = parser.add_argument_group("%s" % p.name,
                        "Options for %s." % p.name)
                else:
                    sgroup = parser.add_argument_group("%s" % p.name,
                        p.desc)

                sgroup.add_argument("--%s" % p.optname, action="store_true",
                        help="Load plugin %s" % p.name)
                if p.has_opts:
                    p.add_options(sgroup)
        except NotImplementedError:
            print "Plugin %s claimed option support, but didn't have it." % p.name

        args = parser.parse_args()
        if args.msf_rc == "/tmp/tmp.rc":
            #need to wipe
            open(args.msf_rc,"w").close()
        args.full_path = path.dirname(path.abspath(__file__))

        #All our options should be loaded now, pass them onto plugins
        load = []
        try:
            for p in plugins:
                if  getattr(args,p.optname):
                    p.initialize(args)
                    load.append(p)
        except NotImplementedError:
            print "Plugin %s lacked initialize function." % p.name

        #this whole msf loading process sucks. need to improve
        if args.msf_rc != "/tmp/tmp.rc" or stat("/tmp/tmp.rc").st_size != 0:
            from plugins.external.sergio_proxy import launch_msf
            launch_msf(args.msf_path,args.msf_rc,args.msf_user)

        from plugins.external.sergio_proxy.sslstrip.StrippingProxy import StrippingProxy
        from plugins.external.sergio_proxy.sslstrip.URLMonitor import URLMonitor
        from plugins.external.sergio_proxy.sslstrip.CookieCleaner import CookieCleaner

        URLMonitor.getInstance().setFaviconSpoofing(spoofFavicon)
        CookieCleaner.getInstance().setEnabled(killSessions)
        strippingFactory              = http.HTTPFactory(timeout=10)
        strippingFactory.protocol     = StrippingProxy
        print 'sslstrip {} + sergio-proxy v{} online'.format(sslstrip_version,sergio_version)
        self.connectorSP = reactor.listenTCP(int(listenPort), strippingFactory)

    def stop(self):
        print 'Thread::[{}] successfully stopped.'.format(self.objectName())
        self.connectorSP.loseConnection()
        self.connectorSP.connectionLost(reason=None)

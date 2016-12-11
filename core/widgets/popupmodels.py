from re import search
import modules as GUIs
from PyQt4.QtGui import *
from PyQt4.QtCore import *
from core.utils import Refactor
from core.widgets.pluginssettings import BDFProxySettings,ResponderSettings
"""
Description:
    This program is a core for wifi-pumpkin.py. file which includes functionality
    for load plugins mitm attack and phishing module.

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

class PopUpPlugins(QVBoxLayout):
    ''' this module control all plugins to MITM attack'''
    sendSingal_disable = pyqtSignal(object)
    def __init__(self,FSettings,main,parent=None):
        super(PopUpPlugins, self).__init__(parent)
        self.main_method = main
        self.FSettings = FSettings
        self.layout = QVBoxLayout()
        self.layoutform = QFormLayout()
        self.layoutproxy = QVBoxLayout()
        self.GroupPlugins = QGroupBox()
        self.GroupPluginsProxy = QGroupBox()
        self.GroupPlugins.setTitle('plugins:')
        self.GroupPluginsProxy.setTitle('Enable proxy server:')
        self.GroupPluginsProxy.setCheckable(True)
        self.GroupPluginsProxy.clicked.connect(self.get_disable_proxyserver)
        self.GroupPluginsProxy.setLayout(self.layoutproxy)
        self.GroupPlugins.setLayout(self.layoutform)

        self.check_netcreds     = QCheckBox('net-creds ')
        self.check_responder    = QCheckBox('Responder')
        self.check_dns2proy     = QRadioButton('SSLstrip+|Dns2proxy')
        self.check_sergioProxy  = QRadioButton('SSLstrip|Sergio-proxy')
        self.check_bdfproxy     = QRadioButton('BDFProxy-ng')
        self.check_noproxy      = QRadioButton('No Proxy')

        self.btnBDFSettings    = QPushButton('Change')
        self.btnResponderSettings = QPushButton('Change')
        self.btnBDFSettings.setIcon(QIcon('icons/config.png'))
        self.btnResponderSettings.setIcon(QIcon('icons/config.png'))
        self.btnBDFSettings.clicked.connect(self.ConfigOBJBDFproxy)
        self.btnResponderSettings.clicked.connect(self.ConfigOBJBResponder)

        self.tableplugins = QTableWidget()
        self.tableplugins.setColumnCount(3)
        self.tableplugins.setRowCount(3)
        self.tableplugins.resizeRowsToContents()
        self.tableplugins.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Preferred)
        self.tableplugins.horizontalHeader().setStretchLastSection(True)
        self.tableplugins.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.tableplugins.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.tableplugins.verticalHeader().setVisible(False)
        self.tableplugins.verticalHeader().setDefaultSectionSize(23)
        self.tableplugins.setSortingEnabled(True)
        self.Headers = ('plugins','settings','Description')
        self.tableplugins.setHorizontalHeaderLabels(self.Headers)
        self.tableplugins.horizontalHeader().resizeSection(0,158)
        self.tableplugins.horizontalHeader().resizeSection(1,80)
        self.tableplugins.resizeRowsToContents()

        self.tableplugincheckbox = QTableWidget()
        self.tableplugincheckbox.setColumnCount(3)
        self.tableplugincheckbox.setRowCount(2)
        self.tableplugincheckbox.resizeRowsToContents()
        self.tableplugincheckbox.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Preferred)
        self.tableplugincheckbox.horizontalHeader().setStretchLastSection(True)
        self.tableplugincheckbox.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.tableplugincheckbox.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.tableplugincheckbox.verticalHeader().setVisible(False)
        self.tableplugincheckbox.verticalHeader().setDefaultSectionSize(23)
        self.tableplugincheckbox.setSortingEnabled(True)
        self.Headers = ('plugins','settings','Description')
        self.tableplugincheckbox.setHorizontalHeaderLabels(self.Headers)
        self.tableplugincheckbox.horizontalHeader().resizeSection(0,158)
        self.tableplugincheckbox.horizontalHeader().resizeSection(1,80)
        self.tableplugincheckbox.resizeRowsToContents()

        desc_dns2proxy = QTableWidgetItem()
        desc_sergioproxy = QTableWidgetItem()
        desc_bdfproxy  = QTableWidgetItem()
        desc_netcreds  = QTableWidgetItem()
        desc_responder  = QTableWidgetItem()

        # set text description plugins
        desc_dns2proxy.setText('This tool offers different features '
        'for post-explotation once you change the DNS server to a Victim. coded by: LeonardoNve')
        desc_sergioproxy.setText('Sergio proxy is an HTTP proxy that was written '
        'in Python for the Twisted framework. coded by: LeonardoNve')
        desc_bdfproxy.setText('Patch Binaries via MITM: BackdoorFactory + mitmProxy, '
        'bdfproxy-ng is a fork and review of the original BDFProxy. coded by: secretsquirrel.')
        desc_netcreds.setText('Sniffs passwords and hashes from an interface or pcap file. coded by: Dan McInerney')
        desc_responder.setText('Responder and LLMNR, NBT-NS and MDNS poisoner. '
        'By default, the tool will only answer to File Server Service request, which is for SMB.')

        self.tableplugins.setItem(0, 2, desc_dns2proxy)
        self.tableplugins.setItem(1, 2, desc_sergioproxy)
        self.tableplugins.setItem(2, 2, desc_bdfproxy)
        self.tableplugins.setCellWidget(0,0,self.check_dns2proy)
        self.tableplugins.setCellWidget(1,0,self.check_sergioProxy)
        self.tableplugins.setCellWidget(2,0,self.check_bdfproxy)
        self.tableplugins.setCellWidget(1,1,QPushButton('None'))
        self.tableplugins.setCellWidget(2,1,self.btnBDFSettings)
        self.tableplugins.setCellWidget(0,1,QPushButton('None'))

        # table 2 for add plugins with checkbox
        self.tableplugincheckbox.setItem(0, 2, desc_netcreds)
        self.tableplugincheckbox.setItem(1, 2, desc_responder)
        self.tableplugincheckbox.setCellWidget(0,0,self.check_netcreds)
        self.tableplugincheckbox.setCellWidget(1,0,self.check_responder)
        self.tableplugincheckbox.setCellWidget(0,1,QPushButton('None'))
        self.tableplugincheckbox.setCellWidget(1,1,self.btnResponderSettings)

        self.proxyGroup = QButtonGroup()
        self.proxyGroup.addButton(self.check_dns2proy)
        self.proxyGroup.addButton(self.check_sergioProxy)
        self.proxyGroup.addButton(self.check_noproxy)
        self.proxyGroup.addButton(self.check_bdfproxy)

        self.check_netcreds.clicked.connect(self.checkBoxNecreds)
        self.check_dns2proy.clicked.connect(self.checkGeneralOptions)
        self.check_sergioProxy.clicked.connect(self.checkGeneralOptions)
        self.check_bdfproxy.clicked.connect(self.checkGeneralOptions)
        self.check_noproxy.clicked.connect(self.checkGeneralOptions)
        self.check_responder.clicked.connect(self.checkBoxResponder)

        self.layoutproxy.addWidget(self.tableplugins)
        self.layoutproxy.addWidget(self.tableplugincheckbox)
        self.layout.addWidget(self.GroupPluginsProxy)
        self.addLayout(self.layout)

    def get_disable_proxyserver(self):
        ''' set disable or activate plugin proxy '''
        self.check_noproxy.setChecked(True)
        self.tableplugincheckbox.setEnabled(True)
        self.sendSingal_disable.emit(self.check_noproxy.isChecked())
        self.checkBoxNecreds()

    # control checkbox plugins
    def checkGeneralOptions(self):
        ''' settings plugins proxy options and rules iptables '''
        self.unset_Rules('dns2proxy')
        self.unset_Rules('sslstrip')
        self.unset_Rules('bdfproxy')
        if self.check_sergioProxy.isChecked():
            self.FSettings.Settings.set_setting('plugins','sergioproxy_plugin',True)
            self.FSettings.Settings.set_setting('plugins','dns2proxy_plugin',False)
            self.FSettings.Settings.set_setting('plugins','noproxy',False)
            self.FSettings.Settings.set_setting('plugins','bdfproxy_plugin',False)
            self.main_method.set_proxy_statusbar('SSLstrip|Sergio-proxy')
            self.set_sslStripRule()
        elif self.check_dns2proy.isChecked():
            self.FSettings.Settings.set_setting('plugins','dns2proxy_plugin',True)
            self.FSettings.Settings.set_setting('plugins','sergioproxy_plugin',False)
            self.FSettings.Settings.set_setting('plugins','noproxy',False)
            self.FSettings.Settings.set_setting('plugins','bdfproxy_plugin',False)
            self.main_method.set_proxy_statusbar('SSLstrip+|Dns2-proxy')
            self.set_sslStripRule()
            self.set_Dns2proxyRule()
        elif self.check_bdfproxy.isChecked():
            self.FSettings.Settings.set_setting('plugins','bdfproxy_plugin',True)
            self.FSettings.Settings.set_setting('plugins','dns2proxy_plugin',False)
            self.FSettings.Settings.set_setting('plugins','sergioproxy_plugin',False)
            self.FSettings.Settings.set_setting('plugins','noproxy',False)
            self.main_method.set_proxy_statusbar('BDF-proxy-ng')
            self.unset_Rules('dns2proxy')
            self.unset_Rules('sslstrip')
            self.set_BDFproxyRule()
        elif self.check_noproxy.isChecked():
            self.FSettings.Settings.set_setting('plugins','dns2proxy_plugin',False)
            self.FSettings.Settings.set_setting('plugins','sergioproxy_plugin',False)
            self.FSettings.Settings.set_setting('plugins','bdfproxy_plugin',False)
            self.FSettings.Settings.set_setting('plugins','noproxy',True)
            self.main_method.set_proxy_statusbar('',disabled=True)
            self.unset_Rules('dns2proxy')
            self.unset_Rules('sslstrip')
            self.unset_Rules('bdfproxy')

    def ConfigOBJBDFproxy(self):
        ''' show BDFproxy settings page '''
        self.SettingsBDFProxy  = BDFProxySettings()
        self.SettingsBDFProxy.show()

    def ConfigOBJBResponder(self):
        ''' show REsponder settings page '''
        self.SettingsResponder  = ResponderSettings()
        self.SettingsResponder.show()

    def checkBoxNecreds(self):
        if self.check_netcreds.isChecked():
            self.FSettings.Settings.set_setting('plugins','netcreds_plugin',True)
        else:
            self.FSettings.Settings.set_setting('plugins','netcreds_plugin',False)

    def checkBoxResponder(self):
        if self.check_responder.isChecked():
            self.FSettings.Settings.set_setting('plugins','responder_plugin',True)
        else:
            self.FSettings.Settings.set_setting('plugins','responder_plugin',False)

    def optionsRules(self,type):
        ''' add rules iptable by type plugins'''
        search = {
        'sslstrip': str('iptables -t nat -A PREROUTING -p tcp'+
        ' --destination-port 80 -j REDIRECT --to-port '+self.FSettings.redirectport.text()),
        'dns2proxy':str('iptables -t nat -A PREROUTING -p udp --destination-port 53 -j REDIRECT --to-port 53'),
        'bdfproxy':str('iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port '+
        str(self.FSettings.bdfProxy_port.value()))}
        return search[type]

    # set rules to sslstrip
    def set_sslStripRule(self):
        items = []
        for index in xrange(self.FSettings.ListRules.count()):
            items.append(str(self.FSettings.ListRules.item(index).text()))
        if self.optionsRules('sslstrip') in items:
            return
        item = QListWidgetItem()
        item.setText(self.optionsRules('sslstrip'))
        item.setSizeHint(QSize(30,30))
        self.FSettings.ListRules.addItem(item)

    # set redirect port rules dns2proy
    def set_Dns2proxyRule(self):
        item = QListWidgetItem()
        item.setText(self.optionsRules('dns2proxy'))
        item.setSizeHint(QSize(30,30))
        self.FSettings.ListRules.addItem(item)

    # set redirect port rules bdfproxy
    def set_BDFproxyRule(self):
        items = []
        for index in xrange(self.FSettings.ListRules.count()):
            items.append(str(self.FSettings.ListRules.item(index).text()))
        if self.optionsRules('bdfproxy') in items:
            return
        item = QListWidgetItem()
        item.setText(self.optionsRules('bdfproxy'))
        item.setSizeHint(QSize(30,30))
        self.FSettings.ListRules.addItem(item)

    def unset_Rules(self,type):
        ''' remove rules from Listwidget in settings widget'''
        items = []
        for index in xrange(self.FSettings.ListRules.count()):
            items.append(str(self.FSettings.ListRules.item(index).text()))
        for position,line in enumerate(items):
            if self.optionsRules(type) == line:
                self.FSettings.ListRules.takeItem(position)


class PopUpServer(QWidget):
    ''' this module fast access to phishing-manager'''
    def __init__(self,FSettings):
        QWidget.__init__(self)
        self.FSettings  = FSettings
        self.Ftemplates = GUIs.frm_PhishingManager()
        self.layout     = QVBoxLayout()
        self.FormLayout = QFormLayout()
        self.GridForm   = QGridLayout()
        self.Status     = QStatusBar()
        self.StatusLabel= QLabel(self)
        self.Status.addWidget(QLabel('Status::'))
        self.Status.addWidget(self.StatusLabel)
        self.GroupBox           = QGroupBox()
        self.GroupBox.setTitle('::Server-HTTP::')
        self.GroupBox.setLayout(self.FormLayout)
        self.btntemplates       = QPushButton('Phishing M.')
        self.btnStopServer      = QPushButton('Stop Server')
        self.btnRefresh         = QPushButton('Refresh')
        self.txt_IP             = QLineEdit(self)
        self.ComboIface         = QComboBox(self)
        self.txt_IP.setVisible(False)
        self.StatusServer(False)
        #icons
        self.btntemplates.setIcon(QIcon('icons/page.png'))
        self.btnStopServer.setIcon(QIcon('icons/close.png'))
        self.btnRefresh.setIcon(QIcon('icons/refresh.png'))

        #conects
        self.refrash_interface()
        self.btntemplates.clicked.connect(self.show_template_dialog)
        self.btnStopServer.clicked.connect(self.StopLocalServer)
        self.btnRefresh.clicked.connect(self.refrash_interface)
        self.connect(self.ComboIface, SIGNAL('currentIndexChanged(QString)'), self.discoveryIface)

        #layout
        self.GridForm.addWidget(self.ComboIface,0,1)
        self.GridForm.addWidget(self.btnRefresh,0,2)
        self.GridForm.addWidget(self.btntemplates,1,1)
        self.GridForm.addWidget(self.btnStopServer,1,2)
        self.FormLayout.addRow(self.GridForm)
        self.FormLayout.addWidget(self.Status)
        self.layout.addWidget(self.GroupBox)
        self.setLayout(self.layout)


    def emit_template(self,log):
        if log == 'started':
            self.StatusServer(True)

    def StopLocalServer(self):
        self.StatusServer(False)
        self.Ftemplates.killThread()

    def StatusServer(self,server):
        if server:
            self.StatusLabel.setText('[ ON ]')
            self.StatusLabel.setStyleSheet('QLabel {  color : green; }')
        elif not server:
            self.StatusLabel.setText('[ OFF ]')
            self.StatusLabel.setStyleSheet('QLabel {  color : red; }')

    def refrash_interface(self):
        self.ComboIface.clear()
        n = Refactor.get_interfaces()['all']
        for i,j in enumerate(n):
            if search('at',j) or search('wl',j):
                self.ComboIface.addItem(n[i])
                self.discoveryIface()

    def discoveryIface(self):
        iface = str(self.ComboIface.currentText())
        ip = Refactor.get_Ipaddr(iface)
        self.txt_IP.setText(ip)

    def show_template_dialog(self):
        self.connect(self.Ftemplates,SIGNAL('Activated ( QString ) '), self.emit_template)
        self.Ftemplates.txt_redirect.setText(self.txt_IP.text())
        self.Ftemplates.show()

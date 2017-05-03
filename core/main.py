from logging import getLogger,ERROR
getLogger('scapy.runtime').setLevel(ERROR)
try:
    from sys import exit
    from PyQt4.QtGui import *
    from PyQt4.QtCore import *
except ImportError:
    exit('WiFi-Pumpkin need PyQt4 :(')
from json import dumps,loads
from pwd import getpwnam
from grp import getgrnam
from time import asctime
from shutil import move
from re import search,sub
from platform import dist
from netaddr import EUI
from collections import OrderedDict

from os import (
    system,path,getcwd,
    popen,listdir,mkdir,chown
)
from subprocess import (
    Popen,PIPE,call,check_output,
)

from core.utils import (
    Refactor,set_monitor_mode,waiterSleepThread,
    setup_logger
)
from core.widgets.tabmodels import (
    ProxySSLstrip,PumpkinMitmproxy,PumpkinMonitor,
    PumpkinSettings
)

from core.widgets.popupmodels import (
    PopUpPlugins,PopUpServer
)

from core.utility.threads import  (
    ProcessHostapd,Thread_sergioProxy,
    ThRunDhcp,Thread_sslstrip,ProcessThread,
    ThreadReactor,ThreadPopen,ThreadPumpkinProxy
)

from plugins.external.scripts import *
import modules as GUIModules
from core.helpers.about import frmAbout
from core.helpers.update import frm_githubUpdate
from core.utility.settings import frm_Settings
from core.helpers.update import ProgressBarWid
from core.helpers.report import frm_ReportLogger
from core.packets.dhcpserver import DHCPServer,DNSServer
from core.widgets.notifications import ServiceNotify
from isc_dhcp_leases.iscdhcpleases import IscDhcpLeases
from netfilterqueue import NetfilterQueue

"""
Description:
    This program is a core for wifi-pumpkin.py. file which includes functionality
    for mount Access point.

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


author      = 'Marcos Nesster (@mh4x0f)  P0cl4bs Team'
emails      = ['mh4root@gmail.com','p0cl4bs@gmail.com']
license     = ' GNU GPL 3'
version     = '0.8.4'
update      = '22/12/2016' # This is Brasil :D
desc        = ['Framework for Rogue Wi-Fi Access Point Attacks']

class Initialize(QMainWindow):
    ''' Main window settings multi-window opened'''
    def __init__(self, parent=None):
        super(Initialize, self).__init__(parent)
        self.FSettings      = frm_Settings()
        self.form_widget    = WifiPumpkin(self,self,self.FSettings)

        # create advanced mode support
        dock = QDockWidget()
        dock.setTitleBarWidget(QWidget())
        dock.setWidget(self.form_widget)
        dock.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Preferred)
        dock.setFeatures(QDockWidget.NoDockWidgetFeatures)
        dock.setAllowedAreas(Qt.AllDockWidgetAreas)
        self.addDockWidget(Qt.LeftDockWidgetArea, dock)
        # set window title
        self.setWindowTitle('WiFi-Pumpkin v' + version)
        self.setGeometry(0, 0, 800, 450) # set geometry window
        self.loadtheme(self.FSettings.XmlThemeSelected())

    def loadtheme(self,theme):
        ''' load Theme from file .qss '''
        sshFile=("core/%s.qss"%(theme))
        with open(sshFile,"r") as fh:
            self.setStyleSheet(fh.read())

    def center(self):
        ''' set Window center desktop '''
        frameGm = self.frameGeometry()
        centerPoint = QDesktopWidget().availableGeometry().center()
        frameGm.moveCenter(centerPoint)
        self.move(frameGm.topLeft())

    def closeEvent(self, event):
        ''' When the user clicks on the X button '''
        if self.form_widget.THReactor.isRunning():
            self.form_widget.THReactor.stop()
        # check if any wireless card is enable as Monitor mode
        iwconfig = Popen(['iwconfig'], stdout=PIPE,shell=False,stderr=PIPE)
        for i in iwconfig.stdout.readlines():
            if search('Mode:Monitor',i):
                self.reply = QMessageBox.question(self,
                'About Exit','Are you sure you want to quit?', QMessageBox.Yes |
                QMessageBox.No, QMessageBox.No)
                if self.reply == QMessageBox.Yes:
                    set_monitor_mode(i.split()[0]).setDisable()
                    return event.accept()
                return event.ignore()

        # check is Rouge AP is running
        if self.form_widget.Apthreads['RougeAP'] != []:
            self.reply = QMessageBox.question(self,
            'About Access Point','Are you sure you want to stop all Access Points?', QMessageBox.Yes |
            QMessageBox.No, QMessageBox.No)
            if self.reply == QMessageBox.Yes:
                print('killing all threads...')
                self.form_widget.Stop_PumpAP()
                return event.accept()
            return event.ignore()
        return event.accept()

class WifiPumpkin(QWidget):
    ''' load main window class'''
    def __init__(self, parent = None,window=None,Fsettings=None):
        self.InitialMehtod = window
        super(WifiPumpkin, self).__init__(parent)

        # check update from github repository
        self.Timer = waiterSleepThread()
        self.Timer.quit.connect(self.get_status_new_commits)
        self.UpdateSoftware = frm_githubUpdate(version)
        self.UpdateSoftware.resize(480, 280)
        self.UpdateSoftware.show()
        self.UpdateSoftware.setHidden(True)
        self.UpdateSoftware.checkUpdate()
        self.Timer.start()

        # define all Widget TABs
        self.MainControl    = QVBoxLayout()
        self.TabControl     = QTabWidget()
        self.Tab_Default    = QWidget()
        self.Tab_Injector   = QWidget()
        self.Tab_PumpkinPro = QWidget()
        self.Tab_Settings   = QWidget()
        self.Tab_ApMonitor  = QWidget()
        self.Tab_Plugins    = QWidget()
        self.Tab_dock       = QMainWindow() # for dockarea
        self.FSettings      = Fsettings

        # create dockarea in Widget class
        self.dock = QDockWidget()
        self.dock.setTitleBarWidget(QWidget())
        self.dock.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Preferred)
        self.dock.setFeatures(QDockWidget.NoDockWidgetFeatures)
        self.dock.setAllowedAreas(Qt.AllDockWidgetAreas)

        # icons menus left widgets
        self.TabListWidget_Menu = QListWidget()
        self.item_home = QListWidgetItem()
        self.item_home.setText('Home')
        self.item_home.setSizeHint(QSize(30,30))
        self.item_home.setIcon(QIcon('icons/home.png'))
        self.TabListWidget_Menu.addItem(self.item_home)

        self.item_settings = QListWidgetItem()
        self.item_settings.setText('Settings')
        self.item_settings.setSizeHint(QSize(30,30))
        self.item_settings.setIcon(QIcon('icons/settings-AP.png'))
        self.TabListWidget_Menu.addItem(self.item_settings)

        self.item_plugins = QListWidgetItem()
        self.item_plugins.setText('Plugins')
        self.item_plugins.setSizeHint(QSize(30,30))
        self.item_plugins.setIcon(QIcon('icons/plugins-new.png'))
        self.TabListWidget_Menu.addItem(self.item_plugins)

        self.item_injector = QListWidgetItem()
        self.item_injector.setText('SSLstrip-Proxy')
        self.item_injector.setSizeHint(QSize(30,30))
        self.item_injector.setIcon(QIcon('icons/mac.png'))
        self.TabListWidget_Menu.addItem(self.item_injector)

        self.item_pumpkinProxy = QListWidgetItem()
        self.item_pumpkinProxy.setText('Pumpkin-Proxy')
        self.item_pumpkinProxy.setSizeHint(QSize(30,30))
        self.item_pumpkinProxy.setIcon(QIcon('icons/pumpkinproxy.png'))
        self.TabListWidget_Menu.addItem(self.item_pumpkinProxy)

        self.item_dock = QListWidgetItem()
        self.item_dock.setText('Activity-Monitor')
        self.item_dock.setSizeHint(QSize(30,30))
        self.item_dock.setIcon(QIcon('icons/activity-monitor.png'))
        self.TabListWidget_Menu.addItem(self.item_dock)

        self.item_monitor = QListWidgetItem()
        self.item_monitor.setText('Stations')
        self.item_monitor.setSizeHint(QSize(30,30))
        self.item_monitor.setIcon(QIcon('icons/stations.png'))
        self.TabListWidget_Menu.addItem(self.item_monitor)

        self.Stack = QStackedWidget(self)
        self.Stack.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Preferred)
        self.Tab_Default.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Preferred)
        self.Stack.addWidget(self.Tab_Default)
        self.TabListWidget_Menu.currentRowChanged.connect(self.display_tab_stack)
        self.TabListWidget_Menu.setFixedWidth(140)
        self.TabListWidget_Menu.setStyleSheet('QListWidget::item '
        '{border-style: solid; border-width:1px; border-color:#3A3939;}'
        'QListWidget::item:selected {border-style: solid;color:#FFFFFF; '
        'border-width:1px; border-color:#3A3939;}'
        'QListWidget {background-color: #302F2F;border-width:1px;border-color:#201F1F;}')
        # add in Tab default widget TABs

        # create Layout for add contents widgets TABs
        self.ContentTabHome    = QVBoxLayout(self.Tab_Default)
        self.ContentTabsettings= QVBoxLayout(self.Tab_Settings)
        self.ContentTabInject  = QVBoxLayout(self.Tab_Injector)
        self.ContentTabPumpPro = QVBoxLayout(self.Tab_PumpkinPro)
        self.ContentTabMonitor = QVBoxLayout(self.Tab_ApMonitor)
        self.ContentTabPlugins = QVBoxLayout(self.Tab_Plugins)
        self.Stack.addWidget(self.Tab_Settings)
        self.Stack.addWidget(self.Tab_Plugins)
        self.Stack.addWidget(self.Tab_Injector)
        self.Stack.addWidget(self.Tab_PumpkinPro)
        self.Stack.addWidget(self.Tab_dock)
        self.Stack.addWidget(self.Tab_ApMonitor)

        self.Apthreads      = {'RougeAP': []}
        self.APclients      = {}
        # settings advanced mode status
        self.AreaDockInfo = {
            'HTTP-Requests': { # netcreds url requests
                'active' : self.FSettings.Settings.get_setting('dockarea',
                'dock_urlmonitor',format=bool),
                'splitcode': ':[url]',
            },
            'HTTP-Authentication': { # netcreds passwords logins
                'active' : self.FSettings.Settings.get_setting('dockarea',
                'dock_credencials',format=bool),
                'splitcode': ':[creds]',
            },
            'BDFProxy': { # plugins bdfproxy ouput
                'active' : self.FSettings.Settings.get_setting('dockarea',
                'dock_bdfproxy',format=bool),
            },
            'Dns2Proxy': { # plugins dns2proxy output
                'active' : self.FSettings.Settings.get_setting('dockarea',
                'dock_dns2proxy',format=bool),
            },
            'Responder': { # plugins responder output
                'active' : self.FSettings.Settings.get_setting('dockarea',
                'dock_Responder',format=bool),
            },
            'PumpkinProxy': { # plugins Pumpkin-Proxy output
                'active' : self.FSettings.Settings.get_setting('dockarea',
                'dock_PumpkinProxy',format=bool),
            }
        }
        self.ConfigTwin     = {
        'ProgCheck':[],'AP_iface': None,'PortRedirect': None, 'interface':'None'}
        self.THeaders  = OrderedDict([ ('Devices',[]),('Mac Address',[]),('IP Address',[]),('Vendors',[])])
        # load all session saved in file ctg
        self.status_plugin_proxy_name = QLabel('') # status name proxy activated
        self.SessionsAP     = loads(str(self.FSettings.Settings.get_setting('accesspoint','sessions')))
        self.PopUpPlugins   = PopUpPlugins(self.FSettings,self) # create popupPlugins
        self.PopUpPlugins.sendSingal_disable.connect(self.get_disable_proxy_status)
        self.THReactor = ThreadReactor() # thread reactor for sslstrip
        self.checkPlugins() # check plugins activated
        self.intGUI()

    def get_disable_proxy_status(self,status):
        ''' check if checkbox proxy-server is enable '''
        self.PopUpPlugins.check_noproxy.setChecked(status)
        self.PopUpPlugins.checkGeneralOptions()

    def display_tab_stack(self,i):
        ''' show content tab index TabMenuListWidget '''
        self.Stack.setCurrentIndex(i)

    def sessionGenerate(self):
        ''' get key id for session AP '''
        session_id = Refactor.generateSessionID()
        while session_id in self.SessionsAP.keys():
            session_id = Refactor.generateSessionID()
        self.FormPopup.Ftemplates.session = session_id
        return session_id

    def get_status_new_commits(self,flag):
        ''' checks for commits in repository on Github '''
        if flag and self.UpdateSoftware.checkHasCommits:
            reply = QMessageBox.question(self, 'Update',
                'Would you like to update from GitHub?', QMessageBox.Yes |
                QMessageBox.No, QMessageBox.No)
            if reply == QMessageBox.Yes:
                self.UpdateSoftware.show()
        self.Timer.terminate()

    def InjectorTABContent(self):
        ''' add Layout page Pump-Proxy in dashboard '''
        self.ProxyPluginsTAB = ProxySSLstrip(self.PopUpPlugins,self,self.FSettings)
        self.ProxyPluginsTAB.sendError.connect(self.GetErrorInjector)
        self.ContentTabInject.addLayout(self.ProxyPluginsTAB)

    def PumpkinProxyTABContent(self):
        ''' add Layout page PumpkinProxy in dashboard '''
        self.PumpkinProxyTAB = PumpkinMitmproxy(main_method=self)
        self.ContentTabPumpPro.addLayout(self.PumpkinProxyTAB)

    def getContentTabDock(self,docklist):
        ''' get tab activated in Advanced mode '''
        self.dockAreaList = docklist

    def GetErrorInjector(self,data):
        ''' get error when ssslstrip or plugin args is not exist '''
        QMessageBox.warning(self,'Error Module::Proxy',data)
    def GetmessageSave(self,data):
        ''' get message dhcp configuration '''
        QMessageBox.information(self,'settings DHCP',data)

    def ApMonitorTabContent(self):
        ''' add Layout page Pump-Monitor in dashboard '''
        self.PumpMonitorTAB = PumpkinMonitor(self.FSettings)
        self.ContentTabMonitor.addLayout(self.PumpMonitorTAB)

    def SettingsTABContent(self):
        ''' add Layout page Pump-settings in dashboard '''
        self.PumpSettingsTAB = PumpkinSettings(None,self.slipt,self.AreaDockInfo,self.Tab_dock,self.FSettings)
        self.PumpSettingsTAB.checkDockArea.connect(self.getContentTabDock)
        self.PumpSettingsTAB.sendMensage.connect(self.GetmessageSave)
        self.ContentTabsettings.addLayout(self.PumpSettingsTAB)

    def PluginsTABContent(self):
        ''' add Layout page Pump-plugins in dashboard '''
        self.ContentTabPlugins.addLayout(self.PopUpPlugins)

    def DefaultTABContent(self):
        ''' configure all widget in home page '''
        self.StatusBar = QStatusBar()
        self.StatusBar.setFixedHeight(20)
        self.StatusDhcp = QLabel("")
        self.connectedCount = QLabel('')
        self.StatusDhcp = QLabel('')
        self.StatusApname = QLabel('')
        self.StatusApchannel = QLabel('')
        self.proxy_lstatus = QLabel('[OFF]')
        self.StatusApname.setMaximumWidth(130)

        # add widgets in status bar
        self.StatusBar.addWidget(QLabel('SSID:'))
        self.StatusBar.addWidget(self.StatusApname)
        self.StatusBar.addWidget(QLabel('Channel:'))
        self.StatusBar.addWidget(self.StatusApchannel)
        self.StatusBar.addWidget(QLabel("Access-Point:"))
        self.StatusBar.addWidget(self.StatusDhcp)
        self.StatusBar.addWidget(QLabel('Injector-Proxy:'))
        self.StatusBar.addWidget(self.proxy_lstatus)
        self.StatusBar.addWidget(QLabel('Activate-Plugin:'))
        self.StatusBar.addWidget(self.status_plugin_proxy_name)
        self.set_proxy_scripts(False)

        self.Started(False)
        self.progress = ProgressBarWid(total=101)
        self.progress.setFixedHeight(13)
        self.progress.setFixedWidth(140)

        self.StatusBar.addWidget(QLabel(''),20)
        self.StatusBar.addWidget(QLabel("Clients:"))
        self.connectedCount.setText("0")
        self.connectedCount.setStyleSheet("QLabel {  color : yellow; }")
        self.StatusBar.addWidget(self.connectedCount)
        self.EditGateway = QLineEdit(self)
        self.EditApName = QLineEdit(self)
        self.EditChannel =QSpinBox(self)
        self.EditChannel.setMinimum(1)
        self.EditChannel.setMaximum(13)
        self.EditChannel.setFixedWidth(50)
        self.EditApName.setFixedWidth(120)
        self.EditGateway.setFixedWidth(120)
        self.selectCard = QComboBox(self)
        self.EditApName.textChanged.connect(self.setAP_name_changer)
        self.EditChannel.valueChanged.connect(self.setAP_channel_changer)

        # table information AP connected
        self.TabInfoAP = QTableWidget(5,4)
        self.TabInfoAP.setRowCount(50)
        self.TabInfoAP.resizeRowsToContents()
        self.TabInfoAP.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Preferred)
        self.TabInfoAP.horizontalHeader().setStretchLastSection(True)
        self.TabInfoAP.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.TabInfoAP.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.TabInfoAP.verticalHeader().setVisible(False)
        self.TabInfoAP.setHorizontalHeaderLabels(self.THeaders.keys())
        self.TabInfoAP.verticalHeader().setDefaultSectionSize(23)
        self.TabInfoAP.horizontalHeader().resizeSection(3,158)
        self.TabInfoAP.horizontalHeader().resizeSection(0,150)
        self.TabInfoAP.horizontalHeader().resizeSection(2,120)
        self.TabInfoAP.horizontalHeader().resizeSection(1,120)
        self.TabInfoAP.setSortingEnabled(True)

        #edits
        self.mConfigure()
        self.FormGroup2 = QFormLayout()
        self.FormGroup3 = QFormLayout()

        # popupMenu HTTP server quick start
        self.btnHttpServer = QToolButton(self)
        self.btnHttpServer.setFixedHeight(25)
        self.btnHttpServer.setIcon(QIcon('icons/phishing.png'))
        self.btnHttpServer.setToolTip('HTTP Server Settings')
        self.FormPopup = PopUpServer(self.FSettings)
        self.btnHttpServer.setPopupMode(QToolButton.MenuButtonPopup)
        self.btnHttpServer.setMenu(QMenu(self.btnHttpServer))
        action = QWidgetAction(self.btnHttpServer)
        action.setDefaultWidget(self.FormPopup)
        self.btnHttpServer.menu().addAction(action)
        self.btnHttpServer.setHidden(True)

        # grid network adapter fix
        self.btrn_refresh = QPushButton('Refresh')
        self.btrn_refresh.setIcon(QIcon('icons/refresh.png'))
        self.btrn_refresh.clicked.connect(self.refrash_interface)
        self.btrn_refresh.setFixedWidth(90)
        self.btrn_refresh.setFixedHeight(25)

        # group for list network adapters
        self.GroupAdapter = QGroupBox()
        self.layoutNetworkAd = QFormLayout()
        self.GroupAdapter.setTitle('Network Adapter')
        self.layoutNetworkAd.addRow(self.selectCard,self.btrn_refresh)
        self.GroupAdapter.setLayout(self.layoutNetworkAd)

        # settings info access point
        self.GroupAP = QGroupBox()
        self.GroupAP.setTitle('Access Point')
        self.FormGroup3.addRow('Gateway:', self.EditGateway)
        self.FormGroup3.addRow('SSID:',    self.EditApName)
        self.FormGroup3.addRow('Channel:', self.EditChannel)
        self.FormGroup3.addRow(self.GroupAdapter)
        self.GroupAP.setLayout(self.FormGroup3)
        self.GroupAP.setFixedWidth(260)

        # create widgets for Wireless Security options
        self.GroupApPassphrase = QGroupBox()
        self.GroupApPassphrase.setTitle('Enable Wireless Security')
        self.GroupApPassphrase.setCheckable(True)
        self.GroupApPassphrase.setChecked(
            self.FSettings.Settings.get_setting('accesspoint','enable_Security',format=bool))
        self.GroupApPassphrase.clicked.connect(self.CheckStatusWPASecurity)
        self.layoutNetworkPass  = QFormLayout()
        self.editPasswordAP     = QLineEdit(self.FSettings.Settings.get_setting('accesspoint','WPA_SharedKey'))
        self.WPAtype_spinbox    = QSpinBox()
        self.wpa_pairwiseCB     = QComboBox()
        algoritms = ['TKIP','CCMP','TKIP + CCMP']
        wpa_algotims = self.FSettings.Settings.get_setting('accesspoint','WPA_Algorithms')
        self.wpa_pairwiseCB.addItems(algoritms)
        self.wpa_pairwiseCB.setCurrentIndex(algoritms.index(wpa_algotims))
        self.WPAtype_spinbox.setMaximum(2)
        self.WPAtype_spinbox.setMinimum(0)
        self.WPAtype_spinbox.setValue(
            self.FSettings.Settings.get_setting('accesspoint','WPA_type',format=int))
        self.editPasswordAP.setFixedWidth(150)
        self.editPasswordAP.textChanged.connect(self.update_settings)
        self.WPAtype_spinbox.valueChanged.connect(self.update_settings)
        self.update_settings()

        # add widgets on layout Group
        self.layoutNetworkPass.addRow('Security type:',self.WPAtype_spinbox)
        self.layoutNetworkPass.addRow('WPA Algorithms:',self.wpa_pairwiseCB)
        self.layoutNetworkPass.addRow('Security Key:',self.editPasswordAP)
        self.GroupApPassphrase.setLayout(self.layoutNetworkPass)

        self.btn_start_attack = QPushButton('Start', self)
        self.btn_start_attack.setIcon(QIcon('icons/start.png'))
        self.btn_cancelar = QPushButton('Stop', self)
        self.btn_cancelar.setIcon(QIcon('icons/Stop.png'))
        self.btn_cancelar.clicked.connect(self.Stop_PumpAP)
        self.btn_start_attack.clicked.connect(self.Start_PumpAP)
        self.btn_cancelar.setEnabled(False)

        self.hBoxbutton = QVBoxLayout()
        self.Formbuttons  = QFormLayout()
        self.Formbuttons.addRow(self.btn_start_attack,self.btn_cancelar)
        self.hBoxbutton.addLayout(self.Formbuttons)

        self.Main_  = QVBoxLayout()
        self.slipt = QHBoxLayout()
        self.slipt.addWidget(self.GroupAP)
        self.slipt.addWidget(self.GroupApPassphrase)

        self.donatelink = 'https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=PUPJEGHLJPFQL'
        self.donateLabel = ServiceNotify('Donations allow us to devote more time to the project so'
        ' if you are able to donate any amount, click ',title='Attention',
        link=self.donatelink,timeout=15000)
        # set main page Tool
        self.widget = QWidget()
        self.layout = QVBoxLayout(self.widget)
        self.layout.addWidget(self.donateLabel)
        self.layout.addWidget(self.TabInfoAP)
        self.Main_.addWidget(self.widget)
        self.ContentTabHome.addLayout(self.Main_)

    def intGUI(self):
        ''' configure GUI default window '''
        self.DefaultTABContent()
        self.InjectorTABContent()
        self.PumpkinProxyTABContent()
        self.SettingsTABContent()
        self.ApMonitorTabContent()
        self.PluginsTABContent()

        self.myQMenuBar = QMenuBar(self)
        self.myQMenuBar.setFixedWidth(400)
        Menu_file = self.myQMenuBar.addMenu('&File')
        exportAction = QAction('Report Logger...', self)
        deleteAction = QAction('Clear Logger', self)
        deleteAction.setIcon(QIcon('icons/delete.png'))
        exportAction.setIcon(QIcon('icons/export.png'))
        Menu_file.addAction(exportAction)
        Menu_file.addAction(deleteAction)
        deleteAction.triggered.connect(self.delete_logger)
        exportAction.triggered.connect(self.exportlogger)

        Menu_View = self.myQMenuBar.addMenu('&View')
        phishinglog = QAction('Monitor Phishing', self)
        netcredslog = QAction('Monitor NetCreds', self)
        dns2proxylog = QAction('Monitor Dns2proxy', self)
        #connect
        phishinglog.triggered.connect(self.credentials)
        netcredslog.triggered.connect(self.logsnetcreds)
        dns2proxylog.triggered.connect(self.logdns2proxy)
        #icons
        phishinglog.setIcon(QIcon('icons/password.png'))
        netcredslog.setIcon(QIcon('icons/logger.png'))
        dns2proxylog.setIcon(QIcon('icons/proxy.png'))
        Menu_View.addAction(phishinglog)
        Menu_View.addAction(netcredslog)
        Menu_View.addAction(dns2proxylog)

        #tools Menu
        Menu_tools = self.myQMenuBar.addMenu('&Tools')
        btn_drift = QAction('Active DriftNet', self)
        btn_drift.setShortcut('Ctrl+Y')
        btn_drift.triggered.connect(self.start_dift)

        # icons tools
        btn_drift.setIcon(QIcon('icons/capture.png'))
        Menu_tools.addAction(btn_drift)

        #menu module
        Menu_module = self.myQMenuBar.addMenu('&Modules')
        btn_deauth = QAction('Deauth Attack', self)
        btn_probe = QAction('Probe Request',self)
        btn_dhcpStar = QAction('DHCP Starvation',self)
        btn_winup = QAction('Windows Update',self)
        btn_arp = QAction('ARP Poison Attack',self)
        btn_dns = QAction('DNS Spoof Attack',self)
        btn_phishing = QAction('Phishing Manager',self)
        action_settings = QAction('Settings',self)

        # Shortcut modules
        btn_deauth.setShortcut('Ctrl+W')
        btn_probe.setShortcut('Ctrl+K')
        btn_dhcpStar.setShortcut('Ctrl+H')
        btn_winup.setShortcut('Ctrl+N')
        btn_dns.setShortcut('ctrl+D')
        btn_arp.setShortcut('ctrl+Q')
        btn_phishing.setShortcut('ctrl+Z')
        action_settings.setShortcut('Ctrl+X')

        #connect buttons
        btn_probe.triggered.connect(self.showProbe)
        btn_deauth.triggered.connect(self.formDauth)
        btn_dhcpStar.triggered.connect(self.show_dhcpDOS)
        btn_winup.triggered.connect(self.show_windows_update)
        btn_arp.triggered.connect(self.show_arp_posion)
        btn_dns.triggered.connect(self.show_dns_spoof)
        btn_phishing.triggered.connect(self.show_PhishingManager)
        action_settings.triggered.connect(self.show_settings)

        #icons modules
        btn_arp.setIcon(QIcon('icons/arp_.png'))
        btn_winup.setIcon(QIcon('icons/arp.png'))
        btn_dhcpStar.setIcon(QIcon('icons/dhcp.png'))
        btn_probe.setIcon(QIcon('icons/probe.png'))
        btn_deauth.setIcon(QIcon('icons/deauth.png'))
        btn_dns.setIcon(QIcon('icons/dns_spoof.png'))
        btn_phishing.setIcon(QIcon('icons/page.png'))
        action_settings.setIcon(QIcon('icons/setting.png'))

        # add modules menu
        Menu_module.addAction(btn_deauth)
        Menu_module.addAction(btn_probe)
        Menu_module.addAction(btn_dhcpStar)
        Menu_module.addAction(btn_winup)
        Menu_module.addAction(btn_arp)
        Menu_module.addAction(btn_dns)
        Menu_module.addAction(btn_phishing)
        Menu_module.addAction(action_settings)

        #menu extra
        Menu_extra= self.myQMenuBar.addMenu('&Help')
        Menu_update = QAction('Check for Updates',self)
        Menu_about = QAction('About WiFi-Pumpkin',self)
        Menu_issue = QAction('Submit Issue',self)
        Menu_donate = QAction('Donate',self)
        Menu_about.setIcon(QIcon('icons/about.png'))
        Menu_issue.setIcon(QIcon('icons/report.png'))
        Menu_update.setIcon(QIcon('icons/update.png'))
        Menu_donate.setIcon(QIcon('icons/donate.png'))
        Menu_about.triggered.connect(self.about)
        Menu_issue.triggered.connect(self.issue)
        Menu_donate.triggered.connect(self.donate)
        Menu_update.triggered.connect(self.show_update)
        Menu_extra.addAction(Menu_donate)
        Menu_extra.addAction(Menu_issue)
        Menu_extra.addAction(Menu_update)
        Menu_extra.addAction(Menu_about)
        # create box default Form
        self.boxHome = QVBoxLayout(self)
        self.boxHome.addWidget(self.myQMenuBar)

        # create Horizontal widgets
        hbox = QHBoxLayout()
        self.hBoxbutton.addWidget(self.TabListWidget_Menu)
        self.hBoxbutton.addWidget(self.progress)
        # add button start and stop
        hbox.addLayout(self.hBoxbutton)
        hbox.addWidget(self.Stack)
        self.boxHome.addLayout(hbox)
        self.boxHome.addWidget(self.StatusBar)
        self.TabListWidget_Menu.setCurrentRow(0)
        self.setLayout(self.boxHome)

    def is_hexadecimal(self, text):
        try:
            int(text, 16)
        except ValueError:
            return False
        else:
            return True

    def is_ascii(self, text):
        try:
            text.decode('ascii')
        except UnicodeDecodeError:
            return False
        else:
            return True

    def update_settings(self):
        if 1 <= self.WPAtype_spinbox.value() <= 2:
            if 8 <= len(self.editPasswordAP.text()) <= 63 and self.is_ascii(str(self.editPasswordAP.text())):
                self.editPasswordAP.setStyleSheet("QLineEdit { border: 1px solid green;}")
            else:
                self.editPasswordAP.setStyleSheet("QLineEdit { border: 1px solid red;}")
            self.wpa_pairwiseCB.setEnabled(True)
        if self.WPAtype_spinbox.value() == 0:
            if (len(self.editPasswordAP.text()) == 5 or len(self.editPasswordAP.text()) == 13) and \
                    self.is_ascii(str(self.editPasswordAP.text())) or (len(self.editPasswordAP.text()) == 10 or len(self.editPasswordAP.text()) == 26) and \
                    self.is_hexadecimal(str(self.editPasswordAP.text())):
                self.editPasswordAP.setStyleSheet("QLineEdit { border: 1px solid green;}")
            else:
                self.editPasswordAP.setStyleSheet("QLineEdit { border: 1px solid red;}")
            self.wpa_pairwiseCB.setEnabled(False)

    def show_arp_posion(self):
        ''' call GUI Arp Poison module '''
        if not self.FSettings.Settings.get_setting('accesspoint','statusAP',format=bool):
            self.Farp_posion = GUIModules.frm_Arp_Poison(self.FormPopup.Ftemplates)
            self.Farp_posion.setGeometry(0, 0, 450, 300)
            return self.Farp_posion.show()
        QMessageBox.information(self,'ARP Poison Attack','This module does not work with the Access Point enabled. ')

    def show_update(self):
        ''' call GUI software Update '''
        self.FUpdate = self.UpdateSoftware
        self.FUpdate.show()

    def exportlogger(self):
        ''' call GUI Report Logger files '''
        self.SessionsAP= loads(str(self.FSettings.Settings.get_setting('accesspoint','sessions')))
        self.FrmLogger =  frm_ReportLogger(self.SessionsAP)
        self.FrmLogger.show()

    def show_settings(self):
        self.FSettings.show()

    def show_windows_update(self):
        ''' call GUI Windows Phishing Page module '''
        self.FWinUpdate = GUIModules.frm_update_attack()
        self.FWinUpdate.setGeometry(QRect(100, 100, 300, 300))
        self.FWinUpdate.show()

    def show_dhcpDOS(self):
        ''' call GUI DHCP attack module '''
        self.Fstar = GUIModules.frm_dhcp_Attack()
        self.Fstar.setGeometry(QRect(100, 100, 450, 200))
        self.Fstar.show()

    def showProbe(self):
        ''' call GUI Probe Request monitor module '''
        self.Fprobe = GUIModules.frm_PMonitor()
        self.Fprobe.show()

    def formDauth(self):
        ''' call GUI deauth module '''
        self.Fdeauth =GUIModules.frm_deauth()
        self.Fdeauth.setGeometry(QRect(100, 100, 200, 200))
        self.Fdeauth.show()


    def show_dns_spoof(self):
        ''' call GUI DnsSpoof module '''
        if  self.FSettings.Settings.get_setting('accesspoint','statusAP',format=bool):
            if self.PopUpPlugins.GroupPluginsProxy.isChecked():
                return QMessageBox.information(self,'DNS Spoof with AP','If you want to use this module'
                ' with the Access Point started, you need to disable the Proxy Server. You can change this in plugins tab.'
                ' It\'s only necessary to uncheck "Enable Proxy Server" and restart the Access Point.')
        self.Fdns = GUIModules.frm_DnsSpoof(self.FormPopup.Ftemplates)
        self.Fdns.setGeometry(QRect(100, 100, 450, 500))
        self.Fdns.show()

    def show_PhishingManager(self):
        ''' call GUI phishing attack  '''
        self.FPhishingManager = self.FormPopup.Ftemplates
        self.FPhishingManager.txt_redirect.setText('0.0.0.0')
        self.FPhishingManager.show()

    def credentials(self):
        ''' call GUI phishing monitor logger '''
        self.Fcredentials = GUIModules.frm_get_credentials()
        self.Fcredentials.setWindowTitle('Phishing Logger')
        self.Fcredentials.show()

    def logsnetcreds(self):
        ''' call GUI netcreds monitor logger '''
        self.FnetCreds = GUIModules.frm_NetCredsLogger()
        self.FnetCreds.setWindowTitle('NetCreds Logger')
        self.FnetCreds.show()

    def logdns2proxy(self):
        ''' call GUI dns2proxy monitor logger '''
        self.Fdns2proxy = GUIModules.frm_dns2proxy()
        self.Fdns2proxy.setWindowTitle('DNS2Proxy Logger')
        self.Fdns2proxy.show()

    def CheckStatusWPASecurity(self):
        '''simple connect for get status security wireless click'''
        self.FSettings.Settings.set_setting('accesspoint',
        'enable_security',self.GroupApPassphrase.isChecked())

    def checkPlugins(self):
        ''' check plugin options saved in file ctg '''
        if self.FSettings.Settings.get_setting('plugins','netcreds_plugin',format=bool):
            self.PopUpPlugins.check_netcreds.setChecked(True)
        if self.FSettings.Settings.get_setting('plugins','responder_plugin',format=bool):
            self.PopUpPlugins.check_responder.setChecked(True)

        if self.FSettings.Settings.get_setting('plugins','dns2proxy_plugin',format=bool):
            self.PopUpPlugins.check_dns2proy.setChecked(True)
        elif self.FSettings.Settings.get_setting('plugins','pumpkinproxy_plugin',format=bool):
            self.PopUpPlugins.check_pumpkinProxy.setChecked(True)
        elif self.FSettings.Settings.get_setting('plugins','sergioproxy_plugin',format=bool):
            self.PopUpPlugins.check_sergioProxy.setChecked(True)
        elif self.FSettings.Settings.get_setting('plugins','bdfproxy_plugin',format=bool):
            self.PopUpPlugins.check_bdfproxy.setChecked(True)
        elif self.FSettings.Settings.get_setting('plugins','noproxy',format=bool):
            self.PopUpPlugins.check_noproxy.setChecked(True)
            self.PopUpPlugins.GroupPluginsProxy.setChecked(False)
            self.PopUpPlugins.tableplugincheckbox.setEnabled(True)
        self.PopUpPlugins.checkGeneralOptions()

    def Started(self,bool):
        if bool:
            self.StatusDhcp.setText("[ON]")
            self.StatusDhcp.setStyleSheet("QLabel {  color : green; }")
        else:
            self.StatusDhcp.setText("[OFF]")
            self.StatusDhcp.setStyleSheet("QLabel {  color : red; }")

    def setAP_name_changer(self,string):
        ''' send text editAPname change to statusbar'''
        self.StatusApname.setText(string)
        self.StatusApname.setStyleSheet("QLabel {border-radius: 2px; background-color: grey; color : #000; }")

    def setAP_channel_changer(self,value):
        ''' send text editAPname change to statusbar'''
        self.StatusApchannel.setText(str(value))
        self.StatusApchannel.setStyleSheet("QLabel {border-radius: 2px; background-color: grey; color : #000; }")

    def set_proxy_statusbar(self,name,disabled=False):
        if not disabled:
            self.status_plugin_proxy_name.setText('[ {} ]'.format(name))
            self.status_plugin_proxy_name.setStyleSheet("QLabel { background-color: #996633; color : #000000; }")
        else:
            self.status_plugin_proxy_name.setText('[ Disabled ]')
            self.status_plugin_proxy_name.setStyleSheet("QLabel {  background-color: #808080; color : #000000; }")

    def set_proxy_scripts(self,bool):
        if bool:
            self.proxy_lstatus.setText("[ON]")
            self.proxy_lstatus.setStyleSheet("QLabel {  color : green; }")
        else:
            self.proxy_lstatus.setText("[OFF]")
            self.proxy_lstatus.setStyleSheet("QLabel {  color : red; }")

    def StatusDHCPRequests(self,mac,user_info):
        ''' get HDCP request data and send for Tab monitor '''
        return self.PumpMonitorTAB.addRequests(mac,user_info,True)

    def GetDHCPRequests(self,data):
        ''' filter: data info sended DHCPD request '''
        if len(data) == 8:
            device = sub(r'[)|(]',r'',data[5])
            if len(device) == 0: device = 'unknown'
            if Refactor.check_is_mac(data[4]):
                if data[4] not in self.APclients.keys():
                    self.APclients[data[4]] = {'IP': data[2],
                    'device': device,'in_tables': False,}
                    self.StatusDHCPRequests(data[4],self.APclients[data[4]])
        elif len(data) == 9:
            device = sub(r'[)|(]',r'',data[6])
            if len(device) == 0: device = 'unknown'
            if Refactor.check_is_mac(data[5]):
                if data[5] not in self.APclients.keys():
                    self.APclients[data[5]] = {'IP': data[2],
                    'device': device,'in_tables': False,}
                    self.StatusDHCPRequests(data[5],self.APclients[data[5]])
        elif len(data) == 7:
            if Refactor.check_is_mac(data[4]):
                if data[4] not in self.APclients.keys():
                    leases = IscDhcpLeases('/var/lib/dhcp/dhcpd.leases')
                    hostname = None
                    try:
                        for item in leases.get():
                            if item.ethernet == data[4]:
                                hostname = item.hostname
                        if hostname == None:
                            item = leases.get_current()
                            hostname = item[data[4]]
                    except:
                        hostname = 'unknown'
                    if hostname == None or len(hostname) == 0:hostname = 'unknown'
                    self.APclients[data[4]] = {'IP': data[2],'device': hostname,
                    'in_tables': False,}
                    self.StatusDHCPRequests(data[4],self.APclients[data[4]])
        self.Add_data_into_QTableWidget(self.APclients)

    def Add_data_into_QTableWidget(self,APclients):
        ''' add clients infors in  tablewidget  '''
        Headers = []
        for mac in APclients.keys():
            if not self.APclients[mac]['in_tables']:
                self.APclients[mac]['in_tables'] = True
                try:
                    d_vendor = EUI(mac)
                    d_vendor = d_vendor.oui.registration().org
                except:
                    d_vendor = 'unknown device'
                self.THeaders['Mac Address'].append(mac)
                self.THeaders['IP Address'].append(APclients[mac]['IP'])
                self.THeaders['Devices'].append(APclients[mac]['device'])
                self.THeaders['Vendors'].append(d_vendor)
                for n, key in enumerate(self.THeaders.keys()):
                    Headers.append(key)
                    for m, item in enumerate(self.THeaders[key]):
                        item = QTableWidgetItem(item)
                        item.setTextAlignment(Qt.AlignVCenter | Qt.AlignCenter)
                        self.TabInfoAP.setItem(m, n, item)
                self.TabInfoAP.setHorizontalHeaderLabels(self.THeaders.keys())
        self.connectedCount.setText(str(len(APclients.keys())))


    def GetDHCPDiscoverInfo(self,message):
        '''get infor client connected with AP '''
        if message['mac_addr'] not in self.APclients.keys():
            self.APclients[message['mac_addr']] = \
            {'IP': message['ip_addr'],
            'device': message['host_name'],'in_tables': False}
            self.StatusDHCPRequests(message['mac_addr'],self.APclients[message['mac_addr']])
            self.Add_data_into_QTableWidget(self.APclients)

    def GetHostapdStatus(self,data):
        ''' get inactivity client from hostapd response'''
        if self.APclients != {}:
            if data in self.APclients.keys():
                self.PumpMonitorTAB.addRequests(data,self.APclients[data],False)
        for row in xrange(0,self.TabInfoAP.rowCount()):
            if self.TabInfoAP.item(row,1) != None:
                if self.TabInfoAP.item(row,1).text() == data:
                    self.TabInfoAP.removeRow(row)
                    if data in self.APclients.keys():
                        del self.APclients[data]
        for mac_tables in self.APclients.keys():self.APclients[mac_tables]['in_tables'] = False
        self.THeaders  = OrderedDict([ ('Devices',[]),('Mac Address',[]),('IP Address',[]),('Vendors',[])])
        self.connectedCount.setText(str(len(self.APclients.keys())))

    def GetErrorhostapdServices(self,data):
        '''check error hostapd on mount AP '''
        self.Stop_PumpAP()
        return QMessageBox.warning(self,'[ERROR] Hostapd',
        'Failed to initiate Access Point. '
        'Please check the output of hostapd.\n\nOutput::\n{}'.format(data))

    def mConfigure(self):
        ''' settings edits default and check tools '''
        self.get_interfaces = Refactor.get_interfaces()
        try:
            self.EditGateway.setText( # get gateway interface connected with internet
            [self.get_interfaces[x] for x in self.get_interfaces.keys() if x == 'gateway'][0])
        except Exception :pass
        self.EditApName.setText(self.FSettings.Settings.get_setting('accesspoint','ssid'))
        self.EditChannel.setValue(self.FSettings.Settings.get_setting('accesspoint','channel',format=int))
        self.ConfigTwin['PortRedirect'] = self.FSettings.redirectport.text()

        # get all Wireless Adapter available and add in comboBox
        interfaces = self.get_interfaces['all']
        wireless = []
        for iface in interfaces:
            if search('wl', iface):
                wireless.append(iface)
        self.selectCard.addItems(wireless)
        interface = self.FSettings.Settings.get_setting('accesspoint','interfaceAP')
        if interface != 'None' and interface in self.get_interfaces['all']:
            self.selectCard.setCurrentIndex(wireless.index(interface))

        # check if a program is installed
        driftnet = popen('which driftnet').read().split('\n')
        dhcpd = popen('which dhcpd').read().split("\n")
        hostapd = popen('which hostapd').read().split("\n")
        xterm = popen('which xterm').read().split("\n")
        lista = [ '', '',driftnet[0],dhcpd[0],'',hostapd[0],xterm[0]]
        for i in lista:self.ConfigTwin['ProgCheck'].append(path.isfile(i))


    def refrash_interface(self):
        ''' get all wireless interface available '''
        self.selectCard.clear()
        n = Refactor.get_interfaces()['all']
        for i,j in enumerate(n):
            if search('wl', j):
                self.selectCard.addItem(n[i])

    def Stop_PumpAP(self):
        ''' stop all thread :Access point attack and restore all settings  '''
        if self.Apthreads['RougeAP'] == []: return
        print('-------------------------------')
        self.ProxyPluginsTAB.GroupSettings.setEnabled(True)
        self.FSettings.Settings.set_setting('accesspoint','statusAP',False)
        self.SessionsAP[self.currentSessionID]['stoped'] = asctime()
        self.FSettings.Settings.set_setting('accesspoint','sessions',dumps(self.SessionsAP))
        # check if dockArea activated and stop dock Area
        if hasattr(self,'dockAreaList'):
            for dock in self.dockAreaList.keys():
                self.dockAreaList[dock].clear()
                self.dockAreaList[dock].stopProcess()
        self.PumpSettingsTAB.GroupArea.setEnabled(True)
        # stop all Thread in create for Access Point
        try:
            for thread in self.Apthreads['RougeAP']:
                thread.stop()
                if hasattr(thread, 'wait'):
                    if not thread.wait(msecs=500):
                        thread.terminate()
        except Exception: pass
        # remove iptables commands and stop dhcpd if pesist in process
        for kill in self.SettingsAP['kill']:
            Popen(kill.split(), stdout=PIPE,shell=False,stderr=PIPE)
        # check if persistent option in Settigs is enable
        if not self.FSettings.Settings.get_setting('accesspoint','persistNetwokManager',format=bool):
            Refactor.settingsNetworkManager(self.ConfigTwin['AP_iface'],Remove=True)
        set_monitor_mode(self.ConfigTwin['AP_iface']).setDisable()
        self.Started(False)
        self.progress.setValue(1)
        self.progress.change_color('')
        self.connectedCount.setText('0')
        self.Apthreads['RougeAP'] = []
        self.APclients = {}
        lines = []
        # save logger in ProxyPlugins request
        if self.ProxyPluginsTAB.log_inject.count()>0:
            with open('logs/AccessPoint/injectionPage.log','w') as injectionlog:
                for index in xrange(self.ProxyPluginsTAB.log_inject.count()):
                    lines.append(str(self.ProxyPluginsTAB.log_inject.item(index).text()))
                for log in lines: injectionlog.write(log+'\n')
                injectionlog.close()
        # clear dhcpd.leases
        with open('/var/lib/dhcp/dhcpd.leases','w') as dhcpLease:
            dhcpLease.write(''),dhcpLease.close()
        self.btn_start_attack.setDisabled(False)
        # disable IP Forwarding in Linux
        Refactor.set_ip_forward(0)
        self.TabInfoAP.clearContents()
        self.THeaders  = OrderedDict([ ('Devices',[]), # restore headers table widet
        ('MAC Address',[]),('IP Address',[]),('Vendors',[])])
        if hasattr(self.FormPopup,'Ftemplates'):
            self.FormPopup.Ftemplates.killThread()
            self.FormPopup.StatusServer(False)
        self.EditApName.setEnabled(True)
        self.EditGateway.setEnabled(True)
        self.selectCard.setEnabled(True)
        self.EditChannel.setEnabled(True)
        self.GroupApPassphrase.setEnabled(True)
        self.PumpSettingsTAB.GroupDHCP.setEnabled(True)
        self.PopUpPlugins.tableplugins.setEnabled(True)
        self.PopUpPlugins.tableplugincheckbox.setEnabled(True)
        self.btn_cancelar.setEnabled(False)

    def delete_logger(self):
        ''' delete all logger file in logs/ '''
        content = Refactor.exportHtml()
        if listdir('logs')!= '':
            resp = QMessageBox.question(self, 'About Delete Logger',
                'Do you want to delete all logs?',QMessageBox.Yes |
                    QMessageBox.No, QMessageBox.No)
            if resp == QMessageBox.Yes:
                Popen(['rm','logs/Caplog/*.cap'], stdout=PIPE,shell=False,stderr=PIPE)
                for keyFile in content['Files']:
                    with open(keyFile,'w') as f:
                        f.write(''),f.close()
                self.FSettings.Settings.set_setting('accesspoint','sessions',dumps({}))
                QMessageBox.information(self,'Logger','All Logger::Output has been removed...')

    def start_dift(self):
        ''' start tool driftnet in Thread '''
        if self.ConfigTwin['ProgCheck'][2]:
            if self.ConfigTwin['ProgCheck'][6]:
                if self.FSettings.Settings.get_setting('accesspoint','statusAP',format=bool):
                    Thread_driftnet = ThreadPopen(['driftnet', '-i',
                    self.ConfigTwin['AP_iface'],'-d','./logs/Tools/Driftnet/',])
                    Thread_driftnet.setObjectName('Tool::Driftnet')
                    self.Apthreads['RougeAP'].append(Thread_driftnet)
                    return Thread_driftnet.start()
                return QMessageBox.information(self,'Accesspoint is not running',
                'The Access Point is not configured, this option requires a running AP...')
            return QMessageBox.information(self,'xterm','xterm is not installed.')
        return QMessageBox.information(self,'driftnet','driftnet is not installed.')

    def CoreSettings(self):
        ''' configure interface and dhcpd for mount Access Point '''
        self.splitcodeURL = self.AreaDockInfo['HTTP-Requests']['splitcode']
        self.splitcodeCRED = self.AreaDockInfo['HTTP-Authentication']['splitcode']
        self.DHCP = self.PumpSettingsTAB.getPumpkinSettings()
        self.ConfigTwin['PortRedirect'] = self.FSettings.Settings.get_setting('settings','redirect_port')
        self.SettingsAP = {
        'interface':
            [
                'ifconfig %s up'%(self.ConfigTwin['AP_iface']),
                'ifconfig %s %s netmask %s'%(self.ConfigTwin['AP_iface'],self.DHCP['router'],self.DHCP['netmask']),
                'ifconfig %s mtu 1400'%(self.ConfigTwin['AP_iface']),
                'route add -net %s netmask %s gw %s'%(self.DHCP['subnet'],
                self.DHCP['netmask'],self.DHCP['router'])
            ],
        'kill':
            [
                'iptables --flush',
                'iptables --table nat --flush',
                'iptables --delete-chain',
                'iptables --table nat --delete-chain',
                'ifconfig %s 0'%(self.ConfigTwin['AP_iface']),
                'killall dhpcd',
            ],
        'hostapd':
            [
                'interface={}\n'.format(str(self.selectCard.currentText())),
                'ssid={}\n'.format(str(self.EditApName.text())),
                'channel={}\n'.format(str(self.EditChannel.value())),
            ],
        'dhcp-server':
            [
                'authoritative;\n',
                'default-lease-time {};\n'.format(self.DHCP['leasetimeDef']),
                'max-lease-time {};\n'.format(self.DHCP['leasetimeMax']),
                'subnet %s netmask %s {\n'%(self.DHCP['subnet'],self.DHCP['netmask']),
                'option routers {};\n'.format(self.DHCP['router']),
                'option subnet-mask {};\n'.format(self.DHCP['netmask']),
                'option broadcast-address {};\n'.format(self.DHCP['broadcast']),
                'option domain-name \"%s\";\n'%(str(self.EditApName.text())),
                'option domain-name-servers {};\n'.format('8.8.8.8'),
                'range {};\n'.format(self.DHCP['range'].replace('/',' ')),
                '}',
            ],
        'dnsmasq':
            [
                'interface=%s\n'%(self.ConfigTwin['AP_iface']),
                'dhcp-range=10.0.0.1,10.0.0.50,12h\n',
                'dhcp-option=3, 10.0.0.1\n',
                'dhcp-option=6, 10.0.0.1\n',
            ]
        }
        print('[*] enable forwarding in iptables...')
        Refactor.set_ip_forward(1)
        for i in self.SettingsAP['kill']: Popen(i.split(), stdout=PIPE,shell=False,stderr=PIPE)
        for i in self.SettingsAP['interface']: Popen(i.split(), stdout=PIPE,shell=False,stderr=PIPE)
        dhcp_select = self.FSettings.Settings.get_setting('accesspoint','dhcp_server')
        if dhcp_select != 'dnsmasq':
            with open('settings/dhcpd.conf','w') as dhcp:
                for i in self.SettingsAP['dhcp-server']:dhcp.write(i)
                dhcp.close()
                if path.isfile('/etc/dhcp/dhcpd.conf'):
                    system('rm /etc/dhcp/dhcpd.conf')
                if not path.isdir('/etc/dhcp/'):mkdir('/etc/dhcp')
                move('settings/dhcpd.conf', '/etc/dhcp/')
        else:
            with open('core/config/dnsmasq.conf','w') as dhcp:
                for i in self.SettingsAP['dnsmasq']:
                    dhcp.write(i)
                dhcp.close()

    def SoftDependencies(self):
        ''' check if Hostapd, isc-dhcp-server is installed '''
        self.hostapd_path = self.FSettings.Settings.get_setting('accesspoint','hostapd_path')
        if not path.isfile(self.hostapd_path):
            return QMessageBox.information(self,'hostapd','hostapd is not installed')
        if self.FSettings.Settings.get_setting('accesspoint','dhcpd_server',format=bool):
            if not self.ConfigTwin['ProgCheck'][3]:
                return QMessageBox.warning(self,'dhcpd','isc-dhcp-server (dhcpd) is not installed')
        return True

    def checkWirelessSecurity(self):
        '''check if user add security password on AP'''
        if self.GroupApPassphrase.isChecked():
            self.confgSecurity = []
            if 1 <= self.WPAtype_spinbox.value() <= 2:
                self.confgSecurity.append('wpa={}\n'.format(str(self.WPAtype_spinbox.value())))
                self.confgSecurity.append('wpa_key_mgmt=WPA-PSK\n')
                self.confgSecurity.append('wpa_passphrase={}\n'.format(self.editPasswordAP.text()))
                if '+' in self.wpa_pairwiseCB.currentText():
                    self.confgSecurity.append('wpa_pairwise=TKIP CCMP\n')
                else:
                    self.confgSecurity.append('wpa_pairwise={}\n'.format(self.wpa_pairwiseCB.currentText()))

            if self.WPAtype_spinbox.value() == 0:
                self.confgSecurity.append('auth_algs=1\n')
                self.confgSecurity.append('wep_default_key=0\n')
                if len(self.editPasswordAP.text()) == 5 or len(self.editPasswordAP.text()) == 13:
                    self.confgSecurity.append('wep_key0="{}"\n'.format(self.editPasswordAP.text()))
                else:
                    self.confgSecurity.append('wep_key0={}\n'.format(self.editPasswordAP.text()))

            for config in self.confgSecurity:
                self.SettingsAP['hostapd'].append(config)
            self.FSettings.Settings.set_setting('accesspoint','WPA_SharedKey',self.editPasswordAP.text())
            self.FSettings.Settings.set_setting('accesspoint','WPA_Algorithms',self.wpa_pairwiseCB.currentText())
            self.FSettings.Settings.set_setting('accesspoint','WPA_type',self.WPAtype_spinbox.value())

    def show_key_warning(self):
        return QMessageBox.warning(self, 'Security Key',
                                   'This Key can not be used.\n'
                                   'The requirements for a valid key are:\n\n'
                                   'WPA:\n'
                                   '- 8 to 63 ASCII characters\n\n'
                                   'WEP:\n'
                                   '- 5/13 ASCII characters or 13/26 hexadecimal characters')

    def Start_PumpAP(self):
        ''' start Access Point and settings plugins  '''
        if len(self.selectCard.currentText()) == 0:
            return QMessageBox.warning(self,'Interface ','Network interface was not found')
        if not type(self.SoftDependencies()) is bool: return

        # check if interface has been support AP mode (necessary for hostapd)
        if self.FSettings.Settings.get_setting('accesspoint','check_support_ap_mode',format=bool):
            if not 'AP' in Refactor.get_supported_interface(self.selectCard.currentText())['Supported']:
                return QMessageBox.warning(self,'Access Point',
                "<strong>Warning: </strong>, Monitor Mode is not supported by this device -><strong>({})</strong>."
                "Your adapter does not support creating Access Points."
                " ".format(self.selectCard.currentText()))

        # check connection with internet
        self.interfacesLink = Refactor.get_interfaces()
        if len(self.EditGateway.text()) == 0 or self.interfacesLink['activated'][0] == None:
            return QMessageBox.warning(self,'Internet Connection','No Internet Connection was found.'
            'Sorry, WiFi-Pumpkin requires an Internet Connection to execute MITM attacks.'
            'Check your connection and try again.')

        # check if Wireless interface is being used
        if str(self.selectCard.currentText()) == self.interfacesLink['activated'][0]:
            iwconfig = Popen(['iwconfig'], stdout=PIPE,shell=False,stderr=PIPE)
            for line in iwconfig.stdout.readlines():
                if str(self.selectCard.currentText()) in line:
                    return QMessageBox.warning(self,'Wireless Interface',
                    'A connection has been detected! You may need to use another Wi-Fi Adapter'
                    ' for creating an Access Point or you need to use Ethernet to connect yourself to the Internet'.format(
                    str(self.selectCard.currentText()),line))

        # check if kali linux is using wireless interface for share internet
        if  self.interfacesLink['activated'][1] == 'wireless' and dist()[0] == 'Kali':
            return QMessageBox.information(self,'Network Information',
            "Kali Linux doesn't have support for 2 WiFi Adapters or more"
            "because it doesn't exclude the adapter correctly"
            "in '/etc/NetworkManager/NetworkManager.conf'.\n\n"
            "(if you have any solution for this send me feedback)")

        # check if range ip class is same
        dh, gateway = self.PumpSettingsTAB.getPumpkinSettings()['router'],str(self.EditGateway.text())
        if dh[:len(dh)-len(dh.split('.').pop())] == gateway[:len(gateway)-len(gateway.split('.').pop())]:
            return QMessageBox.warning(self,'DHCP Server Settings',
                'The DHCP Server checks if the Access Point tries to use the same address.'
                'as the network you are connected to. It would work, but does not share the'
                'Internet in some cases. To fix this, you need to change the used address range'
                'in Settings->DHCP Settings->Class Ranges')

        # Check the key
        if self.GroupApPassphrase.isChecked():
            if 1 <= self.WPAtype_spinbox.value() <= 2:
                if not (8 <= len(self.editPasswordAP.text()) <= 63 and self.is_ascii(str(self.editPasswordAP.text()))):
                    return self.show_key_warning()
            if self.WPAtype_spinbox.value() == 0:
                if not (len(self.editPasswordAP.text()) == 5 or len(self.editPasswordAP.text()) == 13) and self.is_ascii(str(self.editPasswordAP.text()))\
                        and not ((len(self.editPasswordAP.text()) == 10 or len(self.editPasswordAP.text()) == 24) and self.is_hexadecimal(str(self.editPasswordAP.text()))):
                    return self.show_key_warning()

        print('\n[*] Loading debugging mode')
        # create session ID to logging process
        self.currentSessionID = self.sessionGenerate()
        self.SessionsAP.update({self.currentSessionID : {'started': None,'stoped': None}})
        self.SessionsAP[self.currentSessionID]['started'] = asctime()
        print('[*] Current Session::ID [{}]'.format(self.currentSessionID))

        # check if using ethernet or wireless connection
        print('[*] Configuring hostapd...')
        self.ConfigTwin['AP_iface'] = str(self.selectCard.currentText())
        set_monitor_mode(self.ConfigTwin['AP_iface']).setDisable()
        if self.interfacesLink['activated'][1] == 'ethernet' or self.interfacesLink['activated'][1] == 'ppp':
            # change Wi-Fi state card
            Refactor.kill_procInterfaceBusy() # killing network process
            try:
                check_output(['nmcli','radio','wifi',"off"]) # old version
            except Exception:
                try:
                    check_output(['nmcli','nm','wifi',"off"]) # new version
                except Exception as error:
                    return QMessageBox.warning(self,'Error nmcli',str(error))
            finally:
                call(['rfkill', 'unblock' ,'wifi'])
        elif self.interfacesLink['activated'][1] == 'wireless':
            # exclude USB wireless adapter in file NetworkManager
            if not Refactor.settingsNetworkManager(self.ConfigTwin['AP_iface'],Remove=False):
                return QMessageBox.warning(self,'Network Manager',
                'The file /etc/NetworkManager/NetworkManager.conf was not found')

        # create dhcpd.leases and set permission for acesss DHCPD
        leases = '/var/lib/dhcp/dhcpd.leases'
        if not path.exists(leases[:-12]):
            mkdir(leases[:-12])
        if not path.isfile(leases):
            with open(leases,'wb') as leaconf:
                leaconf.close()
        uid = getpwnam('root').pw_uid
        gid = getgrnam('root').gr_gid
        chown(leases, uid, gid)

        # get Tab-Hostapd conf and configure hostapd
        self.CoreSettings()
        self.checkWirelessSecurity() # check if user set wireless password
        ignore = ('interface=','ssid=','channel=')
        with open('settings/hostapd.conf','w') as apconf:
            for i in self.SettingsAP['hostapd']:apconf.write(i)
            for config in str(self.FSettings.ListHostapd.toPlainText()).split('\n'):
                if not config.startswith('#') and len(config) > 0:
                    if not config.startswith(ignore):
                        apconf.write(config+'\n')
            apconf.close()

        # create thread for hostapd and connect GetHostapdStatus function
        self.Thread_hostapd = ProcessHostapd({self.hostapd_path:[getcwd()+'/settings/hostapd.conf']}, self.currentSessionID)
        self.Thread_hostapd.setObjectName('hostapd')
        self.Thread_hostapd.statusAP_connected.connect(self.GetHostapdStatus)
        self.Thread_hostapd.statusAPError.connect(self.GetErrorhostapdServices)
        self.Apthreads['RougeAP'].append(self.Thread_hostapd)

        # disable options when started AP
        self.btn_start_attack.setDisabled(True)
        self.EditApName.setEnabled(False)
        self.EditGateway.setEnabled(False)
        self.selectCard.setEnabled(False)
        self.EditChannel.setEnabled(False)
        self.GroupApPassphrase.setEnabled(False)
        self.PumpSettingsTAB.GroupDHCP.setEnabled(False)
        self.PopUpPlugins.tableplugins.setEnabled(False)
        self.PopUpPlugins.tableplugincheckbox.setEnabled(False)
        self.btn_cancelar.setEnabled(True)

        # create thread dhcpd and connect fuction GetDHCPRequests
        print('[*] Configuring dhcpd...')
        if  self.FSettings.Settings.get_setting('accesspoint','dhcpd_server',format=bool):
            self.Thread_dhcp = ThRunDhcp(['dhcpd','-d','-f','-lf','/var/lib/dhcp/dhcpd.leases','-cf',
            '/etc/dhcp/dhcpd.conf',self.ConfigTwin['AP_iface']],self.currentSessionID)
            self.Thread_dhcp.sendRequest.connect(self.GetDHCPRequests)
            self.Thread_dhcp.setObjectName('DHCP')
            self.Apthreads['RougeAP'].append(self.Thread_dhcp)
            self.PopUpPlugins.checkGeneralOptions() # check rules iptables

        elif self.FSettings.Settings.get_setting('accesspoint','pydhcp_server',format=bool):
            #self.ThreadDNSServer = DNSServer(self.ConfigTwin['AP_iface'],self.DHCP['router'])
            #self.ThreadDNSServer.setObjectName('DNSServer')
            # I change DNSServer for dns2proxy for now.
            self.ThreadDNSServer = ProcessThread({'python':['plugins/external/dns2proxy/dns2proxy.py','-i',
            str(self.selectCard.currentText()),'-k',self.currentSessionID]})
            self.ThreadDNSServer._ProcssOutput.connect(self.get_dns2proxy_output)
            self.ThreadDNSServer.setObjectName('DNSServer')

            if not self.PopUpPlugins.check_dns2proy.isChecked():
                self.Apthreads['RougeAP'].append(self.ThreadDNSServer)
                #self.PopUpPlugins.set_Dns2proxyRule() # disabled :: redirect UDP port 53

            self.ThreadDHCPserver = DHCPServer(self.ConfigTwin['AP_iface'],self.DHCP)
            self.ThreadDHCPserver.sendConnetedClient.connect(self.GetDHCPDiscoverInfo)
            self.ThreadDHCPserver.setObjectName('DHCPServer')
            self.Apthreads['RougeAP'].append(self.ThreadDHCPserver)

        self.Started(True)
        self.ProxyPluginsTAB.GroupSettings.setEnabled(False)
        self.FSettings.Settings.set_setting('accesspoint','statusAP',True)
        self.FSettings.Settings.set_setting('accesspoint','interfaceAP',str(self.selectCard.currentText()))


        # check plugins that use sslstrip
        if self.PopUpPlugins.check_dns2proy.isChecked() or self.PopUpPlugins.check_sergioProxy.isChecked():
            # load ProxyPLugins
            self.plugin_classes = Plugin.PluginProxy.__subclasses__()
            self.plugins = {}
            for p in self.plugin_classes:
                self.plugins[p._name] = p()
            # check if twisted is started
            if not self.THReactor.isRunning():
                self.THReactor.start()

        if self.PopUpPlugins.check_netcreds.isChecked():
            self.Thread_netcreds = ProcessThread({'python':['plugins/external/net-creds/net-creds.py','-i',
            str(self.selectCard.currentText()),'-k',self.currentSessionID]})
            self.Thread_netcreds._ProcssOutput.connect(self.get_netcreds_output)
            self.Thread_netcreds.setObjectName('Net-Creds')
            self.Apthreads['RougeAP'].append(self.Thread_netcreds)

        if self.PopUpPlugins.check_responder.isChecked():
            # create thread for plugin responder
            setup_logger('responder', 'logs/AccessPoint/responder.log',self.currentSessionID)
            self.responderlog = getLogger('responder')
            self.Thread_responder = ProcessThread({'python':['plugins/external/Responder/Responder.py','-I',
            str(self.selectCard.currentText()),'-wrFbv']})
            self.Thread_responder._ProcssOutput.connect(self.get_responder_output)
            self.Thread_responder.setObjectName('Responder')
            self.Apthreads['RougeAP'].append(self.Thread_responder)

        if self.PopUpPlugins.check_dns2proy.isChecked():
            # create thread for plugin DNS2proxy
            self.Thread_dns2proxy = ProcessThread({'python':['plugins/external/dns2proxy/dns2proxy.py','-i',
            str(self.selectCard.currentText()),'-k',self.currentSessionID]})
            self.Thread_dns2proxy._ProcssOutput.connect(self.get_dns2proxy_output)
            self.Thread_dns2proxy.setObjectName('Dns2Proxy')
            self.Apthreads['RougeAP'].append(self.Thread_dns2proxy)

            # create thread for plugin SSLstrip
            self.Threadsslstrip = Thread_sslstrip(self.ConfigTwin['PortRedirect'],
            self.plugins,self.ProxyPluginsTAB._PluginsToLoader,self.currentSessionID)
            self.Threadsslstrip.setObjectName("sslstrip2")
            self.Apthreads['RougeAP'].append(self.Threadsslstrip)

        elif self.PopUpPlugins.check_sergioProxy.isChecked():
            # create thread for plugin Sergio-proxy
            self.Threadsslstrip = Thread_sergioProxy(self.ConfigTwin['PortRedirect'],
            self.plugins,self.ProxyPluginsTAB._PluginsToLoader,self.currentSessionID)
            self.Threadsslstrip.setObjectName("sslstrip")
            self.Apthreads['RougeAP'].append(self.Threadsslstrip)

        elif self.PopUpPlugins.check_bdfproxy.isChecked():
            # create thread for plugin BDFproxy-ng
            self.Thread_bdfproxy = ProcessThread({'python':
            ['plugins/external/BDFProxy-ng/bdf_proxy.py','-k',self.currentSessionID]})
            self.Thread_bdfproxy._ProcssOutput.connect(self.get_bdfproxy_output)
            self.Thread_bdfproxy.setObjectName('BDFProxy-ng')
            self.Apthreads['RougeAP'].append(self.Thread_bdfproxy)

        elif self.PopUpPlugins.check_pumpkinProxy.isChecked():
            # create thread for plugin Pumpkin-Proxy
            setup_logger('pumpkinproxy', 'logs/AccessPoint/pumpkin-proxy.log',self.currentSessionID)
            self.Thread_PumpkinProxy = ThreadPumpkinProxy(self.currentSessionID)
            self.Thread_PumpkinProxy.send.connect(self.get_PumpkinProxy_output)
            self.Thread_PumpkinProxy.setObjectName('Pumpkin-Proxy')
            self.Apthreads['RougeAP'].append(self.Thread_PumpkinProxy)
            self.LogPumpkinproxy = getLogger('pumpkinproxy')

        iptables = []
        # get all rules in settings->iptables
        for index in xrange(self.FSettings.ListRules.count()):
           iptables.append(str(self.FSettings.ListRules.item(index).text()))
        for rulesetfilter in iptables:
            if '$inet' in rulesetfilter:
                rulesetfilter = rulesetfilter.replace('$inet',str(Refactor.get_interfaces()['activated'][0]))
            if '$wlan' in rulesetfilter:
                rulesetfilter = rulesetfilter.replace('$wlan',self.ConfigTwin['AP_iface'])
            popen(rulesetfilter)
        print('[*] Sharing Internet Connections with NAT...')

        # start all Thread in sessions
        self.progress.change_color('#FFA500')
        for thread in self.Apthreads['RougeAP']:
            self.progress.update_bar_simple(20)
            QThread.sleep(1)
            thread.start()
        self.progress.setValue(100)
        self.progress.change_color('#FFA500')
        # check if Advanced mode is enable
        if self.FSettings.Settings.get_setting('dockarea','advanced',format=bool):
            self.PumpSettingsTAB.doCheckAdvanced()

        print('-------------------------------')
        print('AP::[{}] Running...'.format(self.EditApName.text()))
        print('AP::BSSID::[{}] CH {}'.format(Refactor.get_interface_mac(
        self.selectCard.currentText()),self.EditChannel.value()))
        self.FSettings.Settings.set_setting('accesspoint','ssid',str(self.EditApName.text()))
        self.FSettings.Settings.set_setting('accesspoint','channel',str(self.EditChannel.value()))

    def get_netcreds_output(self,data):
        ''' get std_ouput the thread Netcreds and add in DockArea '''
        if self.FSettings.Settings.get_setting('accesspoint','statusAP',format=bool):
            if hasattr(self,'dockAreaList'):
                if self.PumpSettingsTAB.dockInfo['HTTP-Requests']['active'] and self.splitcodeURL in data:
                    self.dockAreaList['HTTP-Requests'].writeModeData(str(data).split(self.splitcodeURL)[1])
                if self.PumpSettingsTAB.dockInfo['HTTP-Authentication']['active'] and self.splitcodeCRED in data:
                    self.dockAreaList['HTTP-Authentication'].writeModeData(data)

    def get_dns2proxy_output(self,data):
        ''' get std_ouput the thread dns2proxy and add in DockArea '''
        if self.FSettings.Settings.get_setting('accesspoint','statusAP',format=bool):
            if hasattr(self,'dockAreaList'):
                if self.PumpSettingsTAB.dockInfo['Dns2Proxy']['active']:
                    try:
                        data = str(data).split(' : ')[1]
                        for line in data.split('\n'):
                            if len(line) > 2 and not self.currentSessionID in line:
                                self.dockAreaList['Dns2Proxy'].writeModeData(line)
                    except IndexError:
                        return None

    def get_responder_output(self,data):
        ''' get std_ouput the thread responder and add in DockArea '''
        if self.FSettings.Settings.get_setting('accesspoint','statusAP',format=bool):
            if hasattr(self,'dockAreaList'):
                if self.PumpSettingsTAB.dockInfo['Responder']['active']:
                    for line in data.split('\n'):
                        self.dockAreaList['Responder'].writeModeData(line)
                        self.responderlog.info(line)

    def get_bdfproxy_output(self,data):
        ''' get std_ouput the thread bdfproxy and add in DockArea '''
        if self.FSettings.Settings.get_setting('accesspoint','statusAP',format=bool):
            if hasattr(self,'dockAreaList'):
                if self.PumpSettingsTAB.dockInfo['BDFProxy']['active']:
                    try:
                        data = str(data).split(' : ')[1]
                        for line in data.split('\n'):
                            if len(line) > 2:
                                self.dockAreaList['BDFProxy'].writeModeData(line)
                    except IndexError:
                        return None

    def get_PumpkinProxy_output(self,data):
        ''' get std_ouput the thread Pumpkin-Proxy and add in DockArea '''
        if self.FSettings.Settings.get_setting('accesspoint','statusAP',format=bool):
            if hasattr(self,'dockAreaList'):
                if self.PumpSettingsTAB.dockInfo['PumpkinProxy']['active']:
                    self.dockAreaList['PumpkinProxy'].writeModeData(data)
                    self.LogPumpkinproxy.info(data)

    def create_sys_tray(self):
        ''' configure system tray icon for quick access '''
        self.sysTray = QSystemTrayIcon(self)
        self.sysTray.setIcon(QIcon('icons/icon.ico'))
        self.sysTray.setVisible(True)
        self.connect(self.sysTray,
        SIGNAL('activated(QSystemTrayIcon::ActivationReason)'),
        self.on_sys_tray_activated)
        self.sysTrayMenu = QMenu(self)
        self.sysTrayMenu.addAction('FOO')

    def on_sys_tray_activated(self, reason):
        ''' get status reason click in Icon '''
        if reason == 3:self.showNormal()
        elif reason == 2:self.showMinimized()

    def about(self):
        ''' open about GUI interface '''
        self.Fabout = frmAbout(author,emails,
        version,update,license,desc)
        self.Fabout.show()

    def issue(self):
        ''' open issue in github page the project '''
        url = QUrl('https://github.com/P0cL4bs/WiFi-Pumpkin/issues/new')
        if not QDesktopServices.openUrl(url):
            QMessageBox.warning(self, 'Open Url', 'Could not open url: {}'.format(url))

    def donate(self):
        ''' open page donation the project '''
        if not QDesktopServices.openUrl(self.donatelink):
            QMessageBox.warning(self, 'Open Url', 'Could not open url: {}'.format(self.donatelink))

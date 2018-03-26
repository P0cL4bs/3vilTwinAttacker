from logging import getLogger,ERROR
getLogger('scapy.runtime').setLevel(ERROR)
from PyQt4 import QtGui
from PyQt4 import QtCore
from json import dumps,loads
from pwd import getpwnam
from grp import getgrnam
from time import asctime
from shutil import move
from re import search,sub
from platform import dist
from netaddr import EUI
from collections import OrderedDict
from shlex import split

from os import (
    system,path,getcwd,
    popen,listdir,mkdir,chown
)
from subprocess import (
    Popen,PIPE,call,check_output,
)

from core.utils import (
    Refactor,set_monitor_mode,waiterSleepThread,
    setup_logger,is_ascii,is_hexadecimal,exec_bash,del_item_folder
)
from core.widgets.tabmodels import (
    ProxySSLstrip,PumpkinMitmproxy,PumpkinMonitor,
    PumpkinSettings,PacketsSniffer,ImageCapture,StatusAccessPoint
)

from core.widgets.popupmodels import (
    PopUpPlugins
)

from core.utility.threads import  (
    ProcessHostapd,Thread_sergioProxy,
    ThRunDhcp,Thread_sslstrip,ProcessThread,
    ThreadReactor,ThreadPopen,ThreadPumpkinProxy
)

from core.widgets.customiseds import AutoTableWidget
from plugins.external.scripts import *
import modules as GUIModules
from core.helpers.about import frmAbout
from core.helpers.update import frm_githubUpdate
from core.utility.settings import frm_Settings
import core.utility.constants as C
from core.helpers.update import ProgressBarWid
from core.helpers.report import frm_ReportLogger
from core.packets.dhcpserver import DHCPServer,DNSServer
from core.widgets.notifications import ServiceNotify
from isc_dhcp_leases.iscdhcpleases import IscDhcpLeases
from netfilterqueue import NetfilterQueue
from core.servers.proxy.tcp.intercept import ThreadSniffingPackets

pump_proxy_lib = True #check package is installed
try:
    from mitmproxy import proxy, flow, options
    from mitmproxy.proxy.server import ProxyServer
except ImportError as e:
    pump_proxy_lib = False

"""
Description:
    This program is a core for wifi-pumpkin.py. file which includes functionality
    for mount Access point.

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


author      = 'Marcos Nesster (@mh4x0f)  P0cl4bs Team'
emails      = ['mh4root@gmail.com','p0cl4bs@gmail.com']
license     = ' GNU GPL 3'
version     = '0.8.5'
update      = '04/05/2017' # This is Brasil :D
desc        = ['Framework for Rogue Wi-Fi Access Point Attacks']

class Initialize(QtGui.QMainWindow):
    ''' Main window settings multi-window opened'''
    def __init__(self, parent=None):
        super(Initialize, self).__init__(parent)
        self.FSettings      = frm_Settings()

        # check mitmproxy lib is installed
        if not pump_proxy_lib and self.FSettings.Settings.get_setting('plugins',
            'pumpkinproxy_plugin', format=bool):
            self.FSettings.Settings.set_setting('plugins', 'pumpkinproxy_plugin', False)
            self.FSettings.Settings.set_setting('plugins', 'dns2proxy_plugin', True)
        self.form_widget    = WifiPumpkin(self)

        #for exclude USB adapter if the option is checked in settings tab
        self.networkcontrol = None
        # create advanced mode support
        dock = QtGui.QDockWidget()
        dock.setTitleBarWidget(QtGui.QWidget())
        dock.setWidget(self.form_widget)
        dock.setSizePolicy(QtGui.QSizePolicy.Preferred, QtGui.QSizePolicy.Preferred)
        dock.setFeatures(QtGui.QDockWidget.NoDockWidgetFeatures)
        dock.setAllowedAreas(QtCore.Qt.AllDockWidgetAreas)
        self.addDockWidget(QtCore.Qt.LeftDockWidgetArea, dock)
        # set window title
        self.setWindowTitle('WiFi-Pumpkin v' + version)
        self.setGeometry(0, 0, C.GEOMETRYH, C.GEOMETRYW) # set geometry window
        self.loadtheme(self.FSettings.get_theme_qss())

    def loadtheme(self,theme):
        ''' load Theme from file .qss '''
        sshFile=("core/%s.qss"%(theme))
        with open(sshFile,"r") as fh:
            self.setStyleSheet(fh.read())

    def center(self):
        ''' set Window center desktop '''
        frameGm = self.frameGeometry()
        centerPoint = QtGui.QDesktopWidget().availableGeometry().center()
        frameGm.moveCenter(centerPoint)
        self.move(frameGm.topLeft())

    def closeEvent(self, event):
        ''' When the user clicks on the X button '''
        if self.form_widget.THReactor.isRunning():
            self.form_widget.THReactor.stop()

        # remove card apdater from network-manager conf
        if not self.form_widget.FSettings.Settings.get_setting(
            'accesspoint','persistNetwokManager',format=bool):
            if self.networkcontrol != None:
                self.networkcontrol.remove_settingsNM()

        # check if any wireless card is enable as Monitor mode
        iwconfig = Popen(['iwconfig'], stdout=PIPE,shell=False,stderr=PIPE)
        for i in iwconfig.stdout.readlines():
            if search('Mode:Monitor',i):
                self.reply = QtGui.QMessageBox.question(self,
                'About Exit','Are you sure to quit?', QtGui.QMessageBox.Yes |
                QtGui.QMessageBox.No, QtGui.QMessageBox.No)
                if self.reply == QtGui.QMessageBox.Yes:
                    set_monitor_mode(i.split()[0]).setDisable()
                    return event.accept()
                return event.ignore()

        # check is Rouge AP is running
        if self.form_widget.Apthreads['RougeAP'] != []:
            self.reply = QtGui.QMessageBox.question(self,
            'About Access Point','Are you sure to stop all threads AP ?', QtGui.QMessageBox.Yes |
            QtGui.QMessageBox.No, QtGui.QMessageBox.No)
            if self.reply == QtGui.QMessageBox.Yes:
                print('killing all threads...')
                self.form_widget.stop_access_point()
                return event.accept()
            return event.ignore()
        return event.accept()

class WifiPumpkin(QtGui.QWidget):
    ''' load main window class'''
    def __init__(self, mainWindow):
        QtGui.QWidget.__init__(self)
        self.mainWindow = mainWindow
        self.InternetShareWiFi = True # share internet options

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
        self.MainControl    = QtGui.QVBoxLayout()
        self.TabControl     = QtGui.QTabWidget()
        self.Tab_Default    = QtGui.QWidget()
        self.Tab_Injector   = QtGui.QWidget()
        self.Tab_PumpkinPro = QtGui.QWidget()
        self.Tab_Packetsniffer = QtGui.QWidget()
        self.Tab_statusAP   = QtGui.QWidget()
        self.Tab_imageCap   = QtGui.QWidget()
        self.Tab_Settings   = QtGui.QWidget()
        self.Tab_ApMonitor  = QtGui.QWidget()
        self.Tab_Plugins    = QtGui.QWidget()
        self.Tab_dock       = QtGui.QMainWindow() # for dockarea
        self.FSettings      = self.mainWindow.FSettings

        # create dockarea in Widget class
        self.dock = QtGui.QDockWidget()
        self.dock.setTitleBarWidget(QtGui.QWidget())
        self.dock.setSizePolicy(QtGui.QSizePolicy.Preferred, QtGui.QSizePolicy.Preferred)
        self.dock.setFeatures(QtGui.QDockWidget.NoDockWidgetFeatures)
        self.dock.setAllowedAreas(QtCore.Qt.AllDockWidgetAreas)

        # icons menus left widgets
        self.TabListWidget_Menu = QtGui.QListWidget()
        self.item_home = QtGui.QListWidgetItem()
        self.item_home.setText('Home')
        self.item_home.setSizeHint(QtCore.QSize(30,30))
        self.item_home.setIcon(QtGui.QIcon('icons/home.png'))
        self.TabListWidget_Menu.addItem(self.item_home)

        self.item_settings = QtGui.QListWidgetItem()
        self.item_settings.setText('Settings')
        self.item_settings.setSizeHint(QtCore.QSize(30,30))
        self.item_settings.setIcon(QtGui.QIcon('icons/settings-AP.png'))
        self.TabListWidget_Menu.addItem(self.item_settings)

        self.item_plugins =QtGui.QListWidgetItem()
        self.item_plugins.setText('Plugins')
        self.item_plugins.setSizeHint(QtCore.QSize(30,30))
        self.item_plugins.setIcon(QtGui.QIcon('icons/plugins-new.png'))
        self.TabListWidget_Menu.addItem(self.item_plugins)

        self.item_injector = QtGui.QListWidgetItem()
        self.item_injector.setText('SSLstrip-Proxy')
        self.item_injector.setSizeHint(QtCore.QSize(30,30))
        self.item_injector.setIcon(QtGui.QIcon('icons/mac.png'))
        self.TabListWidget_Menu.addItem(self.item_injector)

        self.item_pumpkinProxy = QtGui.QListWidgetItem()
        self.item_pumpkinProxy.setText('Pumpkin-Proxy')
        self.item_pumpkinProxy.setSizeHint(QtCore.QSize(30,30))
        self.item_pumpkinProxy.setIcon(QtGui.QIcon('icons/pumpkinproxy.png'))
        self.TabListWidget_Menu.addItem(self.item_pumpkinProxy)

        self.item_packetsniffer = QtGui.QListWidgetItem()
        self.item_packetsniffer.setText('TCP-Proxy')
        self.item_packetsniffer.setSizeHint(QtCore.QSize(30,30))
        self.item_packetsniffer.setIcon(QtGui.QIcon('icons/tcpproxy.png'))
        self.TabListWidget_Menu.addItem(self.item_packetsniffer)

        self.item_imageCapture = QtGui.QListWidgetItem()
        self.item_imageCapture.setText('Images-Cap')
        self.item_imageCapture.setSizeHint(QtCore.QSize(30,30))
        self.item_imageCapture.setIcon(QtGui.QIcon('icons/image.png'))
        self.TabListWidget_Menu.addItem(self.item_imageCapture)

        self.item_dock = QtGui.QListWidgetItem()
        self.item_dock.setText('Activity-Monitor')
        self.item_dock.setSizeHint(QtCore.QSize(30,30))
        self.item_dock.setIcon(QtGui.QIcon('icons/activity-monitor.png'))
        self.TabListWidget_Menu.addItem(self.item_dock)

        self.item_monitor = QtGui.QListWidgetItem()
        self.item_monitor.setText('Stations')
        self.item_monitor.setSizeHint(QtCore.QSize(30,30))
        self.item_monitor.setIcon(QtGui.QIcon('icons/stations.png'))
        self.TabListWidget_Menu.addItem(self.item_monitor)

        self.Stack = QtGui.QStackedWidget(self)
        self.Stack.setSizePolicy(QtGui.QSizePolicy.Preferred, QtGui.QSizePolicy.Preferred)
        self.Tab_Default.setSizePolicy(QtGui.QSizePolicy.Preferred, QtGui.QSizePolicy.Preferred)
        self.Stack.addWidget(self.Tab_Default)
        self.TabListWidget_Menu.currentRowChanged.connect(self.set_index_leftMenu)
        self.TabListWidget_Menu.setFixedWidth(140)
        self.TabListWidget_Menu.setStyleSheet(C.MENU_STYLE)
        # add in Tab default widget TABs

        # create Layout for add contents widgets TABs
        self.ContentTabHome    = QtGui.QVBoxLayout(self.Tab_Default)
        self.ContentTabsettings= QtGui.QVBoxLayout(self.Tab_Settings)
        self.ContentTabInject  = QtGui.QVBoxLayout(self.Tab_Injector)
        self.ContentTabPumpPro = QtGui.QVBoxLayout(self.Tab_PumpkinPro)
        self.ContentTabPackets = QtGui.QVBoxLayout(self.Tab_Packetsniffer)
        self.ContentImageCap   = QtGui.QHBoxLayout(self.Tab_imageCap)
        self.ContentTabMonitor = QtGui.QVBoxLayout(self.Tab_ApMonitor)
        self.ContentTabPlugins = QtGui.QVBoxLayout(self.Tab_Plugins)
        self.ContentTabStatus  = QtGui.QVBoxLayout(self.Tab_statusAP)
        self.Stack.addWidget(self.Tab_Settings)
        self.Stack.addWidget(self.Tab_Plugins)
        self.Stack.addWidget(self.Tab_Injector)
        self.Stack.addWidget(self.Tab_PumpkinPro)
        self.Stack.addWidget(self.Tab_Packetsniffer)
        self.Stack.addWidget(self.Tab_imageCap)
        self.Stack.addWidget(self.Tab_dock)
        self.Stack.addWidget(self.Tab_ApMonitor)

        self.Apthreads      = {'RougeAP': []}
        self.APclients      = {}
        # settings advanced mode status
        self.AreaDockInfo = {
            'HTTP-Requests': { # netcreds url requests
                'active' : self.FSettings.Settings.get_setting('dockarea',
                'dock_urlmonitor',format=bool),
            },
            'HTTP-Authentication': { # netcreds passwords logins
                'active' : self.FSettings.Settings.get_setting('dockarea',
                'dock_credencials',format=bool),
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
        self.SettingsEnable     = {
        'ProgCheck':[],'AP_iface': None,'PortRedirect': None, 'interface':'None'}
        self.THeaders  = OrderedDict([ ('Devices',[]),('IP Address',[]),('Mac Address',[]),('Vendors',[])])
        # load all session saved in file ctg
        self.status_plugin_proxy_name = QtGui.QLabel('') # status name proxy activated
        self.SessionsAP     = loads(str(self.FSettings.Settings.get_setting('accesspoint','sessions')))
        self.PopUpPlugins   = PopUpPlugins(self.FSettings,self) # create popupPlugins
        self.PopUpPlugins.sendSingal_disable.connect(self.get_disable_proxy_status)
        self.THReactor = ThreadReactor() # thread reactor for sslstrip
        self.window_phishing = GUIModules.frm_PhishingManager()
        self.initial_GUI_loader()

    def initial_GUI_loader(self):
        ''' configure GUI default window '''
        self.default_TAB_Content()
        self.injector_TAB_Content()
        self.pumpkinProxy_TAB_Content()
        self.tcpproxy_TAB_Content()
        self.imageCapture_TAB_Content()
        self.settings_TAB_Content()
        self.apMonitor_Tab_Content()
        self.plugins_TAB_Content()
        self.statusAP_TAB_Content()

        self.layout.addLayout(self.StatusAPTAB)  # add info tab in home page
        self.StatusAPTAB.scroll.setFixedHeight(210)
        self.check_plugins_enable() # check plugins activated

        self.myQMenuBar = QtGui.QMenuBar(self)
        Menu_file = self.myQMenuBar.addMenu('&File')
        exportAction = QtGui.QAction('Report Logger...', self)
        deleteAction = QtGui.QAction('Clear Logger', self)
        deleteAction.setIcon(QtGui.QIcon('icons/delete.png'))
        exportAction.setIcon(QtGui.QIcon('icons/export.png'))
        Menu_file.addAction(exportAction)
        Menu_file.addAction(deleteAction)
        deleteAction.triggered.connect(self.clean_all_loggers)
        exportAction.triggered.connect(self.show_exportlogger)
        action_settings = QtGui.QAction('Settings...',self)
        Menu_file.addAction(action_settings)

        Menu_View = self.myQMenuBar.addMenu('&View')
        self.statusap_action = QtGui.QAction('Status Dashboard', self.myQMenuBar, checkable=True)
        self.statusap_action.setChecked(self.FSettings.Settings.get_setting('settings',
        'show_dashboard_info', format=bool))
        self.check_status_ap_dashboard()
        #connect
        self.statusap_action.triggered.connect(self.check_status_ap_dashboard)

        Menu_View.addAction(self.statusap_action)

        #tools Menu
        Menu_tools = self.myQMenuBar.addMenu('&Tools')
        btn_drift = QtGui.QAction('Active DriftNet', self)
        btn_drift.setShortcut('Ctrl+Y')
        btn_drift.triggered.connect(self.show_driftnet)
        btn_drift.setIcon(QtGui.QIcon('icons/capture.png'))
        Menu_tools.addAction(btn_drift)

        # server Menu
        Menu_Server = self.myQMenuBar.addMenu('&Server')
        btn_phishing = QtGui.QAction('Phishing Manager',self)
        btn_winup = QtGui.QAction('Windows Update',self)
        btn_winup.setShortcut('Ctrl+N')
        btn_phishing.setShortcut('ctrl+Z')
        Menu_Server.addAction(btn_phishing)
        Menu_Server.addAction(btn_winup)

        #menu module
        Menu_module = self.myQMenuBar.addMenu('&Modules')
        btn_deauth = QtGui.QAction('Wi-Fi deauthentication', self)
        btn_probe = QtGui.QAction('Wi-Fi Probe Request',self)
        btn_dhcpStar = QtGui.QAction('DHCP Starvation',self)
        btn_arp = QtGui.QAction('ARP Poisoner ',self)
        btn_dns = QtGui.QAction('DNS Spoofer ',self)

        # Shortcut modules
        btn_deauth.setShortcut('Ctrl+W')
        btn_probe.setShortcut('Ctrl+K')
        btn_dhcpStar.setShortcut('Ctrl+H')
        btn_dns.setShortcut('ctrl+D')
        btn_arp.setShortcut('ctrl+Q')
        action_settings.setShortcut('Ctrl+X')

        #connect buttons
        btn_probe.triggered.connect(self.showProbe)
        btn_deauth.triggered.connect(self.showDauth)
        btn_dhcpStar.triggered.connect(self.show_dhcpDOS)
        btn_winup.triggered.connect(self.show_windows_update)
        btn_arp.triggered.connect(self.show_arp_posion)
        btn_dns.triggered.connect(self.show_dns_spoof)
        btn_phishing.triggered.connect(self.show_PhishingManager)
        action_settings.triggered.connect(self.show_settings)

        #icons modules
        btn_arp.setIcon(QtGui.QIcon('icons/arp_.png'))
        btn_winup.setIcon(QtGui.QIcon('icons/arp.png'))
        btn_dhcpStar.setIcon(QtGui.QIcon('icons/dhcp.png'))
        btn_probe.setIcon(QtGui.QIcon('icons/probe.png'))
        btn_deauth.setIcon(QtGui.QIcon('icons/deauth.png'))
        btn_dns.setIcon(QtGui.QIcon('icons/dns_spoof.png'))
        btn_phishing.setIcon(QtGui.QIcon('icons/page.png'))
        action_settings.setIcon(QtGui.QIcon('icons/setting.png'))

        # add modules menu
        Menu_module.addAction(btn_deauth)
        Menu_module.addAction(btn_probe)
        Menu_module.addAction(btn_dhcpStar)
        Menu_module.addAction(btn_arp)
        Menu_module.addAction(btn_dns)

        #menu extra
        Menu_extra= self.myQMenuBar.addMenu('&Help')
        Menu_update = QtGui.QAction('Check for Updates',self)
        Menu_about = QtGui.QAction('About WiFi-Pumpkin',self)
        Menu_issue = QtGui.QAction('Submit issue',self)
        Menu_donate = QtGui.QAction('Donate',self)
        Menu_about.setIcon(QtGui.QIcon('icons/about.png'))
        Menu_issue.setIcon(QtGui.QIcon('icons/report.png'))
        Menu_update.setIcon(QtGui.QIcon('icons/update.png'))
        Menu_donate.setIcon(QtGui.QIcon('icons/donate.png'))
        Menu_about.triggered.connect(self.about)
        Menu_issue.triggered.connect(self.issue)
        Menu_donate.triggered.connect(self.donate)
        Menu_update.triggered.connect(self.show_update)
        Menu_extra.addAction(Menu_donate)
        Menu_extra.addAction(Menu_issue)
        Menu_extra.addAction(Menu_update)
        Menu_extra.addAction(Menu_about)
        # create box default Form
        self.boxHome = QtGui.QVBoxLayout(self)
        self.boxHome.addWidget(self.myQMenuBar)

        # create Horizontal widgets
        hbox = QtGui.QHBoxLayout()
        self.hBoxbutton.addWidget(self.TabListWidget_Menu)
        self.hBoxbutton.addWidget(self.progress)
        # add button start and stop
        hbox.addLayout(self.hBoxbutton)
        hbox.addWidget(self.Stack)
        self.boxHome.addLayout(hbox)
        self.boxHome.addWidget(self.StatusBar)
        self.TabListWidget_Menu.setCurrentRow(0)
        self.setLayout(self.boxHome)

    def injector_TAB_Content(self):
        ''' add Layout page Pump-Proxy in dashboard '''
        self.ProxyPluginsTAB = ProxySSLstrip(self.PopUpPlugins,self,self.FSettings)
        self.ProxyPluginsTAB.sendError.connect(self.get_Error_Injector_tab)
        self.ContentTabInject.addLayout(self.ProxyPluginsTAB)

    def pumpkinProxy_TAB_Content(self):
        ''' add Layout page PumpkinProxy in dashboard '''
        self.PumpkinProxyTAB = PumpkinMitmproxy(self)
        if not pump_proxy_lib:
            infoLabel = ServiceNotify(C.PUMPKINPROXY_notify,title='Package Requirement')
            self.ContentTabPumpPro.addWidget(infoLabel)
        self.ContentTabPumpPro.addLayout(self.PumpkinProxyTAB)

    def statusAP_TAB_Content(self):
        ''' add Layout page PumpkinProxy in dashboard '''
        self.StatusAPTAB = StatusAccessPoint(self)
        #self.ContentTabStatus.addLayout(self.StatusAPTAB)

    def tcpproxy_TAB_Content(self):
        ''' add Layout page PumpkinProxy in dashboard '''
        self.PacketSnifferTAB = PacketsSniffer(self)
        self.ContentTabPackets.addLayout(self.PacketSnifferTAB)

    def imageCapture_TAB_Content(self):
        ''' add Layout page PumpkinProxy in dashboard '''
        self.ImageCapTAB = ImageCapture(self)
        self.ContentImageCap.addLayout(self.ImageCapTAB)

    def apMonitor_Tab_Content(self):
        ''' add Layout page Pump-Monitor in dashboard '''
        self.PumpMonitorTAB = PumpkinMonitor(self.FSettings)
        self.ContentTabMonitor.addLayout(self.PumpMonitorTAB)

    def settings_TAB_Content(self):
        ''' add Layout page Pump-settings in dashboard '''
        widgets = {'SettingsAP': self.slipt, 'DockInfo': self.AreaDockInfo,
        'Tab_dock': self.Tab_dock, 'Settings': self.FSettings,'Network': self.GroupAdapter}
        self.PumpSettingsTAB = PumpkinSettings(None,widgets)
        self.PumpSettingsTAB.checkDockArea.connect(self.get_Content_Tab_Dock)
        self.PumpSettingsTAB.sendMensage.connect(self.set_dhcp_setings_ap)
        self.DHCP = self.PumpSettingsTAB.getPumpkinSettings()
        self.ContentTabsettings.addLayout(self.PumpSettingsTAB)
        self.deleteObject(widgets)

    def plugins_TAB_Content(self):
        ''' add Layout page Pump-plugins in dashboard '''
        self.ContentTabPlugins.addLayout(self.PopUpPlugins)

    def default_TAB_Content(self):
        ''' configure all widget in home page '''
        self.StatusBar = QtGui.QStatusBar()
        self.StatusBar.setFixedHeight(23)
        self.connectedCount = QtGui.QLabel('')
        self.status_ap_runing = QtGui.QLabel('')
        self.connected_status = QtGui.QLabel('')

        # add widgets in status bar
        self.StatusBar.addWidget(QtGui.QLabel('Connection:'))
        self.StatusBar.addWidget(self.connected_status)
        self.StatusBar.addWidget(QtGui.QLabel('Plugin:'))
        self.StatusBar.addWidget(self.status_plugin_proxy_name)
        self.StatusBar.addWidget(QtGui.QLabel("Status-AP:"))
        self.StatusBar.addWidget(self.status_ap_runing)

        self.set_status_label_AP(False)
        self.progress = ProgressBarWid(total=101)
        self.progress.setFixedHeight(13)
        self.progress.setFixedWidth(140)

        self.StatusBar.addWidget(QtGui.QLabel(''),20)
        self.StatusBar.addWidget(QtGui.QLabel("Clients:"))
        self.connectedCount.setText("0")
        self.connectedCount.setStyleSheet("QLabel {  color : yellow; }")
        self.StatusBar.addWidget(self.connectedCount)
        self.EditGateway = QtGui.QLineEdit(self)
        self.EditApName = QtGui.QLineEdit(self)
        self.EditBSSID  = QtGui.QLineEdit(self)
        self.btn_random_essid = QtGui.QPushButton(self)
        self.EditChannel =QtGui.QSpinBox(self)
        self.EditChannel.setMinimum(1)
        self.EditChannel.setMaximum(13)
        self.EditChannel.setFixedWidth(50)
        self.EditGateway.setFixedWidth(120)
        self.EditGateway.setHidden(True) # disable Gateway
        self.selectCard = QtGui.QComboBox(self)
        self.btn_random_essid.clicked.connect(self.setAP_essid_random)
        self.btn_random_essid.setIcon(QtGui.QIcon('icons/refresh.png'))

        # table information AP connected
        self.TabInfoAP = AutoTableWidget()
        self.TabInfoAP.setRowCount(50)
        self.TabInfoAP.resizeRowsToContents()
        self.TabInfoAP.setSizePolicy(QtGui.QSizePolicy.Preferred, QtGui.QSizePolicy.Preferred)
        self.TabInfoAP.horizontalHeader().setStretchLastSection(True)
        self.TabInfoAP.setSelectionMode(QtGui.QAbstractItemView.NoSelection)
        self.TabInfoAP.setEditTriggers(QtGui.QAbstractItemView.NoEditTriggers)
        self.TabInfoAP.verticalHeader().setVisible(False)
        self.TabInfoAP.setHorizontalHeaderLabels(self.THeaders.keys())
        self.TabInfoAP.verticalHeader().setDefaultSectionSize(23)
        self.TabInfoAP.horizontalHeader().resizeSection(3,158)
        self.TabInfoAP.horizontalHeader().resizeSection(0,150)
        self.TabInfoAP.horizontalHeader().resizeSection(2,120)
        self.TabInfoAP.horizontalHeader().resizeSection(1,120)
        self.TabInfoAP.setSortingEnabled(True)
        self.TabInfoAP.setObjectName('table_clients')

        #edits
        self.set_initials_configsGUI()
        self.FormGroup2 = QtGui.QFormLayout()
        self.FormGroup3 = QtGui.QGridLayout()

        # popupMenu HTTP server quick start

        # grid network adapter fix
        self.btrn_refresh = QtGui.QPushButton('Refresh')
        self.btrn_refresh.setIcon(QtGui.QIcon('icons/refresh.png'))
        self.btrn_refresh.clicked.connect(self.set_interface_wireless)
        self.btrn_refresh.setFixedWidth(90)
        self.btrn_refresh.setFixedHeight(25)

        self.btrn_find_Inet = QtGui.QPushButton('Check Network Connection')
        self.btrn_find_Inet.setIcon(QtGui.QIcon('icons/router2.png'))
        self.btrn_find_Inet.clicked.connect(self.check_NetworkConnection)
        self.btrn_find_Inet.setFixedHeight(25)
        self.btrn_find_Inet.setFixedWidth(220)

        # group for list network adapters
        self.GroupAdapter = QtGui.QGroupBox()
        self.layoutNetworkAd = QtGui.QHBoxLayout()
        self.GroupAdapter.setTitle('Network Adapter')
        self.layoutNetworkAd.addWidget(self.selectCard)
        self.layoutNetworkAd.addWidget(self.btrn_refresh)
        self.layoutNetworkAd.addWidget(self.btrn_find_Inet)
        self.GroupAdapter.setLayout(self.layoutNetworkAd)

        # settings info access point
        self.GroupAP = QtGui.QGroupBox()
        self.GroupAP.setTitle('Access Point')
        self.FormGroup3.addWidget(QtGui.QLabel("SSID:"),0,0)
        self.FormGroup3.addWidget(self.EditApName,0,1)
        self.FormGroup3.addWidget(QtGui.QLabel("BSSID:"), 1, 0)
        self.FormGroup3.addWidget(self.EditBSSID, 1, 1)
        self.FormGroup3.addWidget(self.btn_random_essid, 1, 2)
        self.FormGroup3.addWidget(QtGui.QLabel("Channel:"),2,0)
        self.FormGroup3.addWidget(self.EditChannel,2,1)
        self.GroupAP.setLayout(self.FormGroup3)
        self.GroupAP.setFixedWidth(260)

        # create widgets for Wireless Security options
        self.GroupApPassphrase = QtGui.QGroupBox()
        self.GroupApPassphrase.setTitle('Enable Wireless Security')
        self.GroupApPassphrase.setCheckable(True)
        self.GroupApPassphrase.setChecked(self.FSettings.Settings.get_setting('accesspoint','enable_Security',format=bool))
        self.GroupApPassphrase.clicked.connect(self.check_StatusWPA_Security)
        self.layoutNetworkPass  = QtGui.QGridLayout()
        self.editPasswordAP     = QtGui.QLineEdit(self.FSettings.Settings.get_setting('accesspoint','WPA_SharedKey'))
        self.WPAtype_spinbox    = QtGui.QSpinBox()
        self.wpa_pairwiseCB     = QtGui.QComboBox()
        self.lb_type_security   = QtGui.QLabel()
        wpa_algotims = self.FSettings.Settings.get_setting('accesspoint','WPA_Algorithms')
        self.wpa_pairwiseCB.addItems(C.ALGORITMS)
        self.wpa_pairwiseCB.setCurrentIndex(C.ALGORITMS.index(wpa_algotims))
        self.WPAtype_spinbox.setMaximum(2)
        self.WPAtype_spinbox.setMinimum(0)
        self.WPAtype_spinbox.setValue(self.FSettings.Settings.get_setting('accesspoint','WPA_type',format=int))
        self.editPasswordAP.setFixedWidth(150)
        self.editPasswordAP.textChanged.connect(self.update_security_settings)
        self.WPAtype_spinbox.valueChanged.connect(self.update_security_settings)
        self.update_security_settings()

        # add widgets on layout Group
        self.layoutNetworkPass.addWidget(QtGui.QLabel('Security type:'),0,0)
        self.layoutNetworkPass.addWidget(self.WPAtype_spinbox, 0, 1)
        self.layoutNetworkPass.addWidget(self.lb_type_security, 0, 2)
        self.layoutNetworkPass.addWidget(QtGui.QLabel('WPA Algorithms:'), 1, 0)
        self.layoutNetworkPass.addWidget(self.wpa_pairwiseCB, 1, 1)
        self.layoutNetworkPass.addWidget(QtGui.QLabel('Security Key:'), 2, 0)
        self.layoutNetworkPass.addWidget(self.editPasswordAP, 2, 1)
        self.GroupApPassphrase.setLayout(self.layoutNetworkPass)

        self.btn_start_attack = QtGui.QPushButton('Start', self)
        self.btn_start_attack.setIcon(QtGui.QIcon('icons/start.png'))
        self.btn_cancelar = QtGui.QPushButton('Stop', self)
        self.btn_cancelar.setIcon(QtGui.QIcon('icons/Stop.png'))
        self.btn_cancelar.clicked.connect(self.stop_access_point)
        self.btn_start_attack.clicked.connect(self.start_access_point)
        self.btn_cancelar.setEnabled(False)

        self.hBoxbutton =QtGui.QVBoxLayout()
        self.Formbuttons  = QtGui.QFormLayout()
        self.Formbuttons.addRow(self.btn_start_attack,self.btn_cancelar)
        self.hBoxbutton.addLayout(self.Formbuttons)

        self.Main_  = QtGui.QVBoxLayout()
        self.slipt = QtGui.QHBoxLayout()
        self.slipt.addWidget(self.GroupAP)
        self.slipt.addWidget(self.GroupApPassphrase)

        self.donatelink = C.DONATE
        self.donateLabel = ServiceNotify(C.DONATE_TXT,title='Support development',
        link=self.donatelink,timeout=15000)
        # set main page Tool
        self.widget = QtGui.QWidget()
        self.layout = QtGui.QVBoxLayout(self.widget)
        self.layout.addWidget(self.donateLabel)
        self.layout.addWidget(self.TabInfoAP)
        self.Main_.addWidget(self.widget)
        self.ContentTabHome.addLayout(self.Main_)

    def show_arp_posion(self):
        ''' call GUI Arp Poison module '''
        if not self.FSettings.Settings.get_setting('accesspoint','statusAP',format=bool):
            self.Farp_posion = GUIModules.frm_Arp_Poison(self.window_phishing)
            self.Farp_posion.setGeometry(0, 0, 450, 300)
            return self.Farp_posion.show()
            QtGui.QMessageBox.information(self,'ARP Poison Attack','this module not work with AP mode enabled. ')
    def show_update(self):
        ''' call GUI software Update '''
        self.FUpdate = self.UpdateSoftware
        self.FUpdate.show()
    def show_exportlogger(self):
        ''' call GUI Report Logger files '''
        self.SessionsAP= loads(str(self.FSettings.Settings.get_setting('accesspoint','sessions')))
        self.FrmLogger =  frm_ReportLogger(self.SessionsAP)
        self.FrmLogger.show()
    def show_settings(self):
        self.FSettings.show()
    def show_windows_update(self):
        ''' call GUI Windows Phishing Page module '''
        self.FWinUpdate = GUIModules.frm_update_attack()
        self.FWinUpdate.setGeometry(QtCore.QRect(100, 100, 300, 300))
        self.FWinUpdate.show()
    def show_dhcpDOS(self):
        ''' call GUI DHCP attack module '''
        self.Fstar = GUIModules.frm_dhcp_Attack()
        self.Fstar.setGeometry(QtCore.QRect(100, 100, 450, 200))
        self.Fstar.show()
    def showProbe(self):
        ''' call GUI Probe Request monitor module '''
        self.Fprobe = GUIModules.frm_PMonitor()
        self.Fprobe.show()
    def showDauth(self):
        ''' call GUI deauth module '''
        self.Fdeauth =GUIModules.frm_deauth()
        self.Fdeauth.setGeometry(QtCore.QRect(100, 100, 200, 200))
        self.Fdeauth.show()
    def show_dns_spoof(self):
        ''' call GUI DnsSpoof module '''
        if  self.FSettings.Settings.get_setting('accesspoint','statusAP',format=bool):
            if self.PopUpPlugins.GroupPluginsProxy.isChecked():
                return QtGui.QMessageBox.information(self,'DnsSpoof with AP','if you want to use the module'
                ' Dns Spoof Attack with AP started, you need to disable Proxy Server. You can change this in plugins tab'
                ' and only it necessary that the option "Enable Proxy Server"  be unmarked and '
                'restart the AP(Access Point).')
        self.Fdns = GUIModules.frm_DnsSpoof(self.window_phishing)
        self.Fdns.setGeometry(QtCore.QRect(100, 100, 450, 500))
        self.Fdns.show()
    def show_PhishingManager(self):
        ''' call GUI phishing attack  '''
        self.FPhishingManager = self.window_phishing
        self.FPhishingManager.txt_redirect.setText('0.0.0.0')
        self.FPhishingManager.show()
    def show_driftnet(self):
        ''' start tool driftnet in Thread '''
        if self.SettingsEnable['ProgCheck'][2]:
            if self.SettingsEnable['ProgCheck'][6]:
                if self.FSettings.Settings.get_setting('accesspoint','statusAP',format=bool):
                    Thread_driftnet = ThreadPopen(['driftnet', '-i',
                    self.SettingsEnable['AP_iface'],'-d','./logs/Tools/Driftnet/',])
                    Thread_driftnet.setObjectName('Tool::Driftnet')
                    self.Apthreads['RougeAP'].append(Thread_driftnet)
                    return Thread_driftnet.start()
                return QtGui.QMessageBox.information(self,'Accesspoint is not running',
                'The access point is not configured, this option require AP is running...')
            return QtGui.QMessageBox.information(self,'xterm','xterm is not installed.')
        return QtGui.QMessageBox.information(self,'driftnet','driftnet is not found.')


    def check_status_ap_dashboard(self):
        ''' show/hide dashboard infor '''
        if self.statusap_action.isChecked():
            self.StatusAPTAB.scroll.setHidden(False)
            return self.FSettings.Settings.set_setting('settings', 'show_dashboard_info', True)
        self.FSettings.Settings.set_setting('settings', 'show_dashboard_info', False)
        self.StatusAPTAB.scroll.setHidden(True)

    def check_StatusWPA_Security(self):
        '''simple connect for get status security wireless click'''
        self.FSettings.Settings.set_setting('accesspoint',
        'enable_security',self.GroupApPassphrase.isChecked())

    def check_NetworkConnection(self):
        ''' update inferfaces '''
        self.btrn_find_Inet.setEnabled(False)
        interfaces = Refactor.get_interfaces()
        self.set_StatusConnected_Iface(False,'checking...',check=True)
        QtCore.QTimer.singleShot(3000, lambda: self.set_backgroud_Network(interfaces))

    def check_plugins_enable(self):
        ''' check plugin options saved in file ctg '''
        if self.FSettings.Settings.get_setting('plugins','tcpproxy_plugin',format=bool):
            self.PopUpPlugins.check_tcpproxy.setChecked(True)
        self.PopUpPlugins.checkBoxTCPproxy()
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
        if not pump_proxy_lib:
            self.PopUpPlugins.check_pumpkinProxy.setDisabled(True)
        self.PopUpPlugins.checkGeneralOptions()

    def check_key_security_invalid(self):
        return QtGui.QMessageBox.warning(self, 'Security Key',
                                   'This Key can not be used.\n'
                                   'The requirements for a valid key are:\n\n'
                                   'WPA:\n'
                                   '- 8 to 63 ASCII characters\n\n'
                                   'WEP:\n'
                                   '- 5/13 ASCII characters or 13/26 hexadecimal characters')

    def check_Wireless_Security(self):
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


    def add_DHCP_Requests_clients(self,mac,user_info):
        ''' get HDCP request data and send for Tab monitor '''
        return self.PumpMonitorTAB.addRequests(mac,user_info,True)

    def add_data_into_QTableWidget(self,client):
        self.TabInfoAP.addNextWidget(client)

    def add_avaliableIterfaces(self,ifaces):
        for index,item in enumerate(ifaces):
            if search('wl', item):
                self.selectCard.addItem(ifaces[index])
        return self.btrn_refresh.setEnabled(True)


    def set_dhcp_setings_ap(self,data):
        ''' get message dhcp configuration '''
        QtGui.QMessageBox.information(self,'settings DHCP',data)

    def set_index_leftMenu(self,i):
        ''' show content tab index TabMenuListWidget '''
        self.Stack.setCurrentIndex(i)

    def set_backgroud_Network(self,get_interfaces):
        ''' check interfaces on background '''
        if get_interfaces['activated'][0] != None:
            self.InternetShareWiFi = True
            self.btrn_find_Inet.setEnabled(True)
            return self.set_StatusConnected_Iface(True, get_interfaces['activated'][0])
        self.InternetShareWiFi = False
        self.btrn_find_Inet.setEnabled(True)
        return self.set_StatusConnected_Iface(False,'')

    def set_status_label_AP(self,bool):
        if bool:
            self.status_ap_runing.setText("[ON]")
            self.status_ap_runing.setStyleSheet("QLabel {  color : green; }")
        else:
            self.status_ap_runing.setText("[OFF]")
            self.status_ap_runing.setStyleSheet("QLabel {  color : #df1f1f; }")

    def setAP_essid_random(self):
        ''' set random mac 3 last digits  '''
        prefix = []
        for item in [x for x in str(self.EditBSSID.text()).split(':')]:
            prefix.append(int(item,16))
        self.EditBSSID.setText(Refactor.randomMacAddress([prefix[0],prefix[1],prefix[2]]).upper())

    def set_proxy_statusbar(self,name,disabled=False):
        if not disabled:
            self.status_plugin_proxy_name.setText('[ {} ]'.format(name))
            self.status_plugin_proxy_name.setStyleSheet("QLabel { background-color: #996633; color : #000000; }")
        else:
            self.status_plugin_proxy_name.setText('[ Disabled ]')
            self.status_plugin_proxy_name.setStyleSheet("QLabel {  background-color: #808080; color : #000000; }")

    def set_StatusConnected_Iface(self,bool,txt='',check=False):
        if bool:
            self.connected_status.setText('[{}]'.format(txt))
            self.connected_status.setStyleSheet("QLabel {  background-color: #996633; color : #000000; }")
        elif bool == False and check == True:
            self.connected_status.setText('[{}]'.format(txt))
            self.connected_status.setStyleSheet("QLabel {  background-color: #808080; color : #000000; }")
        elif bool == False:
            self.connected_status.setText('[None]')
            self.connected_status.setStyleSheet("QLabel {  background-color: #808080; color : #000000; }")

    def set_initials_configsGUI(self):
        ''' settings edits default and check tools '''
        self.get_interfaces = Refactor.get_interfaces()
        self.EditApName.setText(self.FSettings.Settings.get_setting('accesspoint','ssid'))
        self.EditBSSID.setText(self.FSettings.Settings.get_setting('accesspoint','bssid'))
        self.EditChannel.setValue(self.FSettings.Settings.get_setting('accesspoint','channel',format=int))
        self.SettingsEnable['PortRedirect'] = self.FSettings.redirectport.text()

        # get all Wireless Adapter available and add in comboBox
        interfaces = self.get_interfaces['all']
        wireless = []
        for iface in interfaces:
            if search('wl', iface):
                wireless.append(iface)
        self.selectCard.addItems(wireless)

        if  self.get_interfaces['activated'][0]:
            self.set_StatusConnected_Iface(True,self.get_interfaces['activated'][0])
        else:
            self.InternetShareWiFi = False
            self.set_StatusConnected_Iface(False,'')

        interface = self.FSettings.Settings.get_setting('accesspoint','interfaceAP')
        if interface != 'None' and interface in self.get_interfaces['all']:
            self.selectCard.setCurrentIndex(wireless.index(interface))

        # check if a program is installed
        lista = [ '', '',popen('which driftnet').read().split('\n')[0],
        popen('which dhcpd').read().split("\n")[0],'',popen('which hostapd').read().split("\n")[0],
        popen('which xterm').read().split("\n")[0]]
        for i in lista:self.SettingsEnable['ProgCheck'].append(path.isfile(i))
        # delete obj
        self.deleteObject(lista)
        self.deleteObject(wireless)

    def set_interface_wireless(self):
        ''' get all wireless interface available '''
        self.selectCard.clear()
        self.btrn_refresh.setEnabled(False)
        ifaces = Refactor.get_interfaces()['all']
        QtCore.QTimer.singleShot(3000, lambda : self.add_avaliableIterfaces(ifaces))
        self.deleteObject(ifaces)

    def set_security_type_text(self,string=str):
        self.lb_type_security.setText(string)
        self.lb_type_security.setFixedWidth(60)
        self.lb_type_security.setStyleSheet("QLabel {border-radius: 2px;"
        "padding-left: 10px; background-color: #3A3939; color : silver; } "
        "QWidget:disabled{ color: #404040;background-color: #302F2F; } ")

    def update_security_settings(self):
        if 1 <= self.WPAtype_spinbox.value() <= 2:
            self.set_security_type_text('WPA')
            if 8 <= len(self.editPasswordAP.text()) <= 63 and is_ascii(str(self.editPasswordAP.text())):
                self.editPasswordAP.setStyleSheet("QLineEdit { border: 1px solid green;}")
            else:
                self.editPasswordAP.setStyleSheet("QLineEdit { border: 1px solid red;}")
            self.wpa_pairwiseCB.setEnabled(True)
            if self.WPAtype_spinbox.value() == 2:
                self.set_security_type_text('WPA2')
        if self.WPAtype_spinbox.value() == 0:
            self.set_security_type_text('WEP')
            if (len(self.editPasswordAP.text()) == 5 or len(self.editPasswordAP.text()) == 13) and \
                    is_ascii(str(self.editPasswordAP.text())) or (len(self.editPasswordAP.text()) == 10 or len(self.editPasswordAP.text()) == 26) and \
                    is_hexadecimal(str(self.editPasswordAP.text())):
                self.editPasswordAP.setStyleSheet("QLineEdit { border: 1px solid green;}")
            else:
                self.editPasswordAP.setStyleSheet("QLineEdit { border: 1px solid red;}")
            self.wpa_pairwiseCB.setEnabled(False)


    def get_Session_ID(self):
        ''' get key id for session AP '''
        session_id = Refactor.generateSessionID()
        while session_id in self.SessionsAP.keys():
            session_id = Refactor.generateSessionID()
        self.window_phishing.session = session_id
        return session_id

    def get_disable_proxy_status(self,status):
        ''' check if checkbox proxy-server is enable '''
        self.PopUpPlugins.check_noproxy.setChecked(status)
        self.PopUpPlugins.checkGeneralOptions()

    def get_Content_Tab_Dock(self,docklist):
        ''' get tab activated in Advanced mode '''
        self.dockAreaList = docklist

    def get_Error_Injector_tab(self,data):
        ''' get error when ssslstrip or plugin args is not exist '''
        QtGui.QMessageBox.warning(self,'Error Module::Proxy',data)

    def get_status_new_commits(self,flag):
        ''' checks for commits in repository on Github '''
        if flag and self.UpdateSoftware.checkHasCommits:
            reply = QtGui.QMessageBox.question(self, 'Update WiFi-Pumpkin',
                'would you like to update commits from (github)??', QtGui.QMessageBox.Yes |
                                               QtGui.QMessageBox.No, QtGui.QMessageBox.No)
            if reply == QtGui.QMessageBox.Yes:
                self.UpdateSoftware.show()
        self.Timer.terminate()

    def get_DHCP_Requests_clients(self,data):
        ''' filter: data info sended DHCPD request '''
        self.APclients = {}
        if len(data) == 8:
            device = sub(r'[)|(]',r'',data[5])
            if len(device) == 0: device = 'unknown'
            if Refactor.check_is_mac(data[4]):
                if data[4] not in self.TabInfoAP.APclients.keys():
                    self.APclients[data[4]] = {'IP': data[2],
                    'device': device,'MAC': data[4],'Vendors' : self.get_mac_vendor(data[4])}
                    self.add_DHCP_Requests_clients(data[4],self.APclients[data[4]])
        elif len(data) == 9:
            device = sub(r'[)|(]',r'',data[6])
            if len(device) == 0: device = 'unknown'
            if Refactor.check_is_mac(data[5]):
                if data[5] not in self.TabInfoAP.APclients.keys():
                    self.APclients[data[5]] = {'IP': data[2],
                    'device': device,'MAC': data[5],'Vendors' : self.get_mac_vendor(data[5])}
                    self.add_DHCP_Requests_clients(data[5],self.APclients[data[5]])
        elif len(data) == 7:
            if Refactor.check_is_mac(data[4]):
                if data[4] not in self.TabInfoAP.APclients.keys():
                    leases = IscDhcpLeases(C.DHCPLEASES_PATH)
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
                                               'MAC': data[4], 'Vendors': self.get_mac_vendor(data[4])}
                    self.add_DHCP_Requests_clients(data[4],self.APclients[data[4]])
        if self.APclients != {}:
            self.add_data_into_QTableWidget(self.APclients)
            self.connectedCount.setText(str(len(self.TabInfoAP.APclients.keys())))

    def get_mac_vendor(self,mac):
        ''' discovery mac vendor by mac address '''
        try:
            d_vendor = EUI(mac)
            d_vendor = d_vendor.oui.registration().org
        except:
            d_vendor = 'unknown mac'
        return d_vendor

    def get_DHCP_Discover_clients(self,message):
        '''get infor client connected with AP '''
        self.APclients = {}
        if message['mac_addr'] not in self.TabInfoAP.APclients.keys():
            self.APclients[message['mac_addr']] = \
            {'IP': message['ip_addr'],
            'device': message['host_name'],
             'MAC': message['mac_addr'],
             'Vendors' : self.get_mac_vendor(message['mac_addr'])}

            self.add_DHCP_Requests_clients(message['mac_addr'],self.APclients[message['mac_addr']])
            self.add_data_into_QTableWidget(self.APclients)
            self.connectedCount.setText(str(len(self.TabInfoAP.APclients.keys())))

    def get_Hostapd_Response(self,data):
        ''' get inactivity client from hostapd response'''
        if self.TabInfoAP.APclients != {}:
            if data in self.TabInfoAP.APclients.keys():
                self.PumpMonitorTAB.addRequests(data,self.TabInfoAP.APclients[data],False)
            self.TabInfoAP.delete_item(data)
            self.connectedCount.setText(str(len(self.TabInfoAP.APclients.keys())))

    def get_error_hostapdServices(self,data):
        '''check error hostapd on mount AP '''
        self.stop_access_point()
        return QtGui.QMessageBox.warning(self,'[ERROR] Hostpad',
        'Failed to initiate Access Point, '
        'check output process hostapd.\n\nOutput::\n{}'.format(data))

    def get_soft_dependencies(self):
        ''' check if Hostapd, isc-dhcp-server is installed '''
        self.hostapd_path = self.FSettings.Settings.get_setting('accesspoint','hostapd_path')
        if not path.isfile(self.hostapd_path):
            return QtGui.QMessageBox.information(self,'Error Hostapd','hostapd is not installed')
        if self.FSettings.Settings.get_setting('accesspoint','dhcpd_server',format=bool):
            if not self.SettingsEnable['ProgCheck'][3]:
                return QtGui.QMessageBox.warning(self,'Error dhcpd','isc-dhcp-server (dhcpd) is not installed')
        return True

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
            self.PumpkinProxyTAB.tableLogging.writeModeData(data)
            self.LogPumpkinproxy.info(data)

    def get_TCPproxy_output(self,data):
        ''' get std_output from thread TCPproxy module and add in DockArea'''
        if self.FSettings.Settings.get_setting('accesspoint', 'statusAP', format=bool):
            if hasattr(self,'dockAreaList'):
                if data.keys()[0] == 'urlsCap':
                    if self.PumpSettingsTAB.dockInfo['HTTP-Requests']['active']:
                        self.dockAreaList['HTTP-Requests'].writeModeData(data)
                        self.LogUrlMonitor.info('[ {0[src]} > {0[dst]} ] {1[Method]} {1[Host]}{1[Path]}'.format(
                            data['urlsCap']['IP'], data['urlsCap']['Headers']))
                elif data.keys()[0] == 'POSTCreds':
                    if self.PumpSettingsTAB.dockInfo['HTTP-Authentication']['active']:
                        self.dockAreaList['HTTP-Authentication'].writeModeData(data)
                        self.LogCredsMonitor.info('URL: {}'.format(data['POSTCreds']['Url']))
                        self.LogCredsMonitor.info('UserName: {}'.format(data['POSTCreds']['User']))
                        self.LogCredsMonitor.info('UserName: {}'.format(data['POSTCreds']['Pass']))
                        self.LogCredsMonitor.info('Packets: {}'.format(data['POSTCreds']['Destination']))
                elif data.keys()[0] == 'image':
                    self.ImageCapTAB.SendImageTableWidgets(data['image'])
                else:
                    self.PacketSnifferTAB.tableLogging.writeModeData(data)
                    self.LogTcpproxy.info('[{}] {}'.format(data.keys()[0],data[data.keys()[0]]))


    def deleteObject(self,obj):
        ''' reclaim memory '''
        del obj

    def clean_all_loggers(self):
        ''' delete all logger file in logs/ '''
        content = Refactor.exportHtml()
        resp = QtGui.QMessageBox.question(self, 'About Delete Logger',
            'do you want to delete logs?',QtGui.QMessageBox.Yes |
                                          QtGui.QMessageBox.No, QtGui.QMessageBox.No)
        if resp == QtGui.QMessageBox.Yes:
            del_item_folder(['logs/Caplog/*','logs/ImagesCap/*'])
            for keyFile in content['Files']:
                with open(keyFile,'w') as f:
                    f.write(''),f.close()
            self.FSettings.Settings.set_setting('accesspoint','sessions',dumps({}))
            QtGui.QMessageBox.information(self,'Logger','All Looger::Output has been Removed...')
        self.deleteObject(content)
        self.deleteObject(resp)

    def configure_network_AP(self):
        ''' configure interface and dhcpd for mount Access Point '''
        self.DHCP = self.PumpSettingsTAB.getPumpkinSettings()
        self.SettingsEnable['PortRedirect'] = self.FSettings.Settings.get_setting('settings','redirect_port')
        self.SettingsAP = {
        'interface':
            [
                'ifconfig %s up'%(self.SettingsEnable['AP_iface']),
                'ifconfig %s %s netmask %s'%(self.SettingsEnable['AP_iface'],self.DHCP['router'],self.DHCP['netmask']),
                'ifconfig %s mtu 1400'%(self.SettingsEnable['AP_iface']),
                'route add -net %s netmask %s gw %s'%(self.DHCP['subnet'],
                self.DHCP['netmask'],self.DHCP['router'])
            ],
        'kill':
            [
                'iptables --flush',
                'iptables --table nat --flush',
                'iptables --delete-chain',
                'iptables --table nat --delete-chain',
                'ifconfig %s 0'%(self.SettingsEnable['AP_iface']),
                'killall dhpcd 2>/dev/null',
            ],
        'hostapd':
            [
                'interface={}\n'.format(str(self.selectCard.currentText())),
                'ssid={}\n'.format(str(self.EditApName.text())),
                'channel={}\n'.format(str(self.EditChannel.value())),
                'bssid={}\n'.format(str(self.EditBSSID.text())),
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
        }
        print('[*] Enable forwarding in iptables...')
        Refactor.set_ip_forward(1)
        # clean iptables settings
        for line in self.SettingsAP['kill']: exec_bash(line)
        # set interface using ifconfig
        for line in self.SettingsAP['interface']: exec_bash(line)
        # check if dhcp option is enabled.
        if self.FSettings.Settings.get_setting('accesspoint','dhcp_server',format=bool):
            with open(C.DHCPCONF_PATH,'w') as dhcp:
                for line in self.SettingsAP['dhcp-server']:dhcp.write(line)
                dhcp.close()
                if not path.isdir('/etc/dhcp/'): mkdir('/etc/dhcp')
                move(C.DHCPCONF_PATH, '/etc/dhcp/')

    def start_access_point(self):
        ''' start Access Point and settings plugins  '''
        if len(self.selectCard.currentText()) == 0:
            return QtGui.QMessageBox.warning(self,'Error interface ','Network interface is not found')
        if not type(self.get_soft_dependencies()) is bool: return

        # check if interface has been support AP mode (necessary for hostapd)
        if self.FSettings.Settings.get_setting('accesspoint','check_support_ap_mode',format=bool):
            if not 'AP' in Refactor.get_supported_interface(self.selectCard.currentText())['Supported']:
                return QtGui.QMessageBox.warning(self,'No Network Supported failed',
                "<strong>failed AP mode: warning interface </strong>, the feature "
                "Access Point Mode is Not Supported By This Device -><strong>({})</strong>.<br><br>"
                "Your adapter does not support for create Access Point Network."
                " ".format(self.selectCard.currentText()))

        # check connection with internet
        self.interfacesLink = Refactor.get_interfaces()

        # check if Wireless interface is being used
        if str(self.selectCard.currentText()) == self.interfacesLink['activated'][0]:
            iwconfig = Popen(['iwconfig'], stdout=PIPE,shell=False,stderr=PIPE)
            for line in iwconfig.stdout.readlines():
                if str(self.selectCard.currentText()) in line:
                    return QtGui.QMessageBox.warning(self,'Wireless interface is busy',
                    'Connection has been detected, this {} is joined the correct Wi-Fi network'
                    ' : Device or resource busy\n{}\nYou may need to another Wi-Fi USB Adapter'
                    ' for create AP or try use with local connetion(Ethernet).'.format(
                    str(self.selectCard.currentText()),line))

        # check if range ip class is same
        gateway_wp, gateway = self.PumpSettingsTAB.getPumpkinSettings()['router'],self.interfacesLink['gateway']
        if gateway != None:
            if gateway_wp[:len(gateway_wp)-len(gateway_wp.split('.').pop())] == \
                gateway[:len(gateway)-len(gateway.split('.').pop())]:
                return QtGui.QMessageBox.warning(self,'DHCP Server settings',
                    'The <b>DHCP server</b> check if range ip class is same.'
                    'it works, but not share internet connection in some case.<br>'
                    'for fix this, You need change on tab <b> (settings -> Class Ranges)</b>'
                    ' now you have choose the Class range different of your network.')
        del(gateway,gateway_wp)

        # Check the key
        if self.GroupApPassphrase.isChecked():
            if 1 <= self.WPAtype_spinbox.value() <= 2:
                if not (8 <= len(self.editPasswordAP.text()) <= 63 and is_ascii(str(self.editPasswordAP.text()))):
                    return self.check_key_security_invalid()
            if self.WPAtype_spinbox.value() == 0:
                if not (len(self.editPasswordAP.text()) == 5 or len(self.editPasswordAP.text()) == 13) and is_ascii(str(self.editPasswordAP.text()))\
                        and not ((len(self.editPasswordAP.text()) == 10 or len(self.editPasswordAP.text()) == 24) and is_hexadecimal(str(self.editPasswordAP.text()))):
                    return self.check_key_security_invalid()

        print('\n[*] Loading debugging mode')
        # create session ID to logging process
        self.currentSessionID = self.get_Session_ID()
        self.SessionsAP.update({self.currentSessionID : {'started': None,'stoped': None}})
        self.SessionsAP[self.currentSessionID]['started'] = asctime()
        print('[*] Current Session::ID [{}]'.format(self.currentSessionID))

        # clear before session
        if hasattr(self,'dockAreaList'):
            for dock in self.dockAreaList.keys():
                self.dockAreaList[dock].clear()
                self.dockAreaList[dock].stopProcess()
        self.PumpkinProxyTAB.tableLogging.clearContents()
        self.ImageCapTAB.TableImage.clear()
        self.ImageCapTAB.TableImage.setRowCount(0)

        # check if using ethernet or wireless connection
        print('[*] Configuring hostapd...')
        self.SettingsEnable['AP_iface'] = str(self.selectCard.currentText())
        set_monitor_mode(self.SettingsEnable['AP_iface']).setDisable()
        if self.interfacesLink['activated'][1] == 'ethernet' or self.interfacesLink['activated'][1] == 'ppp' \
                or self.interfacesLink['activated'][0] == None: #allow use without internet connection
            # change Wi-Fi state card
            Refactor.kill_procInterfaceBusy() # killing network process
            try:
                check_output(['nmcli','radio','wifi',"off"]) # old version
            except Exception:
                try:
                    check_output(['nmcli','nm','wifi',"off"]) # new version
                except Exception as error:
                    return QtGui.QMessageBox.warning(self,'Error nmcli',str(error))
            finally:
                call(['rfkill', 'unblock' ,'wifi'])

        #elif self.interfacesLink['activated'][1] == 'wireless':
        #    # exclude USB wireless adapter in file NetworkManager
        #    if not Refactor.settingsNetworkManager(self.SettingsEnable['AP_iface'],Remove=False):
        #        return QMessageBox.warning(self,'Network Manager',
        #        'Not found file NetworkManager.conf in folder /etc/NetworkManager/')

        # get Tab-Hostapd conf and configure hostapd
        self.configure_network_AP()
        self.check_Wireless_Security() # check if user set wireless password
        ignore = ('interface=','ssid=','channel=','essid=')
        with open(C.HOSTAPDCONF_PATH,'w') as apconf:
            for i in self.SettingsAP['hostapd']:apconf.write(i)
            for config in str(self.FSettings.ListHostapd.toPlainText()).split('\n'):
                if not config.startswith('#') and len(config) > 0:
                    if not config.startswith(ignore):
                        apconf.write(config+'\n')
            apconf.close()

        # create thread for hostapd and connect get_Hostapd_Response function
        self.Thread_hostapd = ProcessHostapd({self.hostapd_path:[C.HOSTAPDCONF_PATH]}, self.currentSessionID)
        self.Thread_hostapd.setObjectName('hostapd')
        self.Thread_hostapd.statusAP_connected.connect(self.get_Hostapd_Response)
        self.Thread_hostapd.statusAPError.connect(self.get_error_hostapdServices)
        self.Apthreads['RougeAP'].append(self.Thread_hostapd)

        # disable options when started AP
        self.btn_start_attack.setDisabled(True)
        self.GroupAP.setEnabled(False)
        self.GroupApPassphrase.setEnabled(False)
        self.GroupAdapter.setEnabled(False)
        self.PumpSettingsTAB.GroupDHCP.setEnabled(False)
        self.PopUpPlugins.tableplugins.setEnabled(False)
        self.PopUpPlugins.tableplugincheckbox.setEnabled(False)
        self.btn_cancelar.setEnabled(True)

        # start section time
        self.StatusAPTAB.update_labels()
        self.StatusAPTAB.start_timer()

        # create thread dhcpd and connect fuction get_DHCP_Requests_clients
        print('[*] Configuring dhcpd...')
        if  self.FSettings.Settings.get_setting('accesspoint','dhcpd_server',format=bool):
            # create dhcpd.leases and set permission for acesss DHCPD
            leases = C.DHCPLEASES_PATH
            if not path.exists(leases[:-12]):
                mkdir(leases[:-12])
            if not path.isfile(leases):
                with open(leases, 'wb') as leaconf:
                    leaconf.close()
            uid = getpwnam('root').pw_uid
            gid = getgrnam('root').gr_gid
            chown(leases, uid, gid)

            self.Thread_dhcp = ThRunDhcp(['dhcpd','-d','-f','-lf',C.DHCPLEASES_PATH,'-cf',
            '/etc/dhcp/dhcpd_wp.conf',self.SettingsEnable['AP_iface']],self.currentSessionID)
            self.Thread_dhcp.sendRequest.connect(self.get_DHCP_Requests_clients)
            self.Thread_dhcp.setObjectName('DHCP')
            self.Apthreads['RougeAP'].append(self.Thread_dhcp)
            self.PopUpPlugins.checkGeneralOptions() # check rules iptables

        elif self.FSettings.Settings.get_setting('accesspoint','pydhcp_server',format=bool):
            if self.FSettings.Settings.get_setting('accesspoint','pydns_server',format=bool):
                self.ThreadDNSServer = DNSServer(self.SettingsEnable['AP_iface'],self.DHCP['router'])
                self.ThreadDNSServer.setObjectName('DNSServer') # use DNS python implements

            elif self.FSettings.Settings.get_setting('accesspoint','dnsproxy_server',format=bool):
                self.ThreadDNSServer = ProcessThread({'python':['plugins/external/dns2proxy/dns2proxy.py','-i',
                str(self.selectCard.currentText()),'-k',self.currentSessionID]})
                self.ThreadDNSServer._ProcssOutput.connect(self.get_dns2proxy_output)
                self.ThreadDNSServer.setObjectName('DNSServer') # use dns2proxy as DNS server

            if not self.PopUpPlugins.check_dns2proy.isChecked():
                self.Apthreads['RougeAP'].append(self.ThreadDNSServer)
                #self.PopUpPlugins.set_Dns2proxyRule() # disabled :: redirect UDP port 53

            self.ThreadDHCPserver = DHCPServer(self.SettingsEnable['AP_iface'],self.DHCP)
            self.ThreadDHCPserver.sendConnetedClient.connect(self.get_DHCP_Discover_clients)
            self.ThreadDHCPserver.setObjectName('DHCPServer')
            self.Apthreads['RougeAP'].append(self.ThreadDHCPserver)

        self.set_status_label_AP(True)
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

        #create logging for somes threads
        setup_logger('pumpkinproxy', C.LOG_PUMPKINPROXY, self.currentSessionID)
        setup_logger('urls_capture', C.LOG_URLCAPTURE, self.currentSessionID)
        setup_logger('creds_capture', C.LOG_CREDSCAPTURE, self.currentSessionID)
        setup_logger('tcp_proxy', C.LOG_TCPPROXY, self.currentSessionID)
        setup_logger('responder', C.LOG_RESPONDER, self.currentSessionID)
        self.LogPumpkinproxy    = getLogger('pumpkinproxy')
        self.LogUrlMonitor      = getLogger('urls_capture')
        self.LogCredsMonitor    = getLogger('creds_capture')
        self.LogTcpproxy        = getLogger('tcp_proxy')
        self.responderlog       = getLogger('responder')


        if self.PopUpPlugins.check_responder.isChecked():
            # create thread for plugin responder
            self.Thread_responder = ProcessThread({
                'python':[C.RESPONDER_EXEC,'-I', str(self.selectCard.currentText()),'-wrFbv']})
            self.Thread_responder._ProcssOutput.connect(self.get_responder_output)
            self.Thread_responder.setObjectName('Responder')
            self.Apthreads['RougeAP'].append(self.Thread_responder)

        if self.PopUpPlugins.check_dns2proy.isChecked():
            # create thread for plugin DNS2proxy
            self.Thread_dns2proxy = ProcessThread(
            {'python':[C.DNS2PROXY_EXEC,'-i',str(self.selectCard.currentText()),'-k',self.currentSessionID]})
            self.Thread_dns2proxy._ProcssOutput.connect(self.get_dns2proxy_output)
            self.Thread_dns2proxy.setObjectName('Dns2Proxy')
            self.Apthreads['RougeAP'].append(self.Thread_dns2proxy)

            # create thread for plugin SSLstrip
            self.Threadsslstrip = Thread_sslstrip(self.SettingsEnable['PortRedirect'],
            self.plugins,self.ProxyPluginsTAB._PluginsToLoader,self.currentSessionID)
            self.Threadsslstrip.setObjectName("sslstrip2")
            self.Apthreads['RougeAP'].append(self.Threadsslstrip)

        elif self.PopUpPlugins.check_sergioProxy.isChecked():
            # create thread for plugin Sergio-proxy
            self.Threadsslstrip = Thread_sergioProxy(self.SettingsEnable['PortRedirect'],
            self.plugins,self.ProxyPluginsTAB._PluginsToLoader,self.currentSessionID)
            self.Threadsslstrip.setObjectName("sslstrip")
            self.Apthreads['RougeAP'].append(self.Threadsslstrip)

        elif self.PopUpPlugins.check_bdfproxy.isChecked():
            # create thread for plugin BDFproxy-ng
            self.Thread_bdfproxy = ProcessThread({'python':[C.BDFPROXY_EXEC,'-k',self.currentSessionID]})
            self.Thread_bdfproxy._ProcssOutput.connect(self.get_bdfproxy_output)
            self.Thread_bdfproxy.setObjectName('BDFProxy-ng')
            self.Apthreads['RougeAP'].append(self.Thread_bdfproxy)

        elif self.PopUpPlugins.check_pumpkinProxy.isChecked():
            # create thread for plugin Pumpkin-Proxy
            self.Thread_PumpkinProxy = ThreadPumpkinProxy(self.currentSessionID)
            self.Thread_PumpkinProxy.send.connect(self.get_PumpkinProxy_output)
            self.Thread_PumpkinProxy.setObjectName('Pumpkin-Proxy')
            self.Apthreads['RougeAP'].append(self.Thread_PumpkinProxy)

        # start thread TCPproxy Module
        if self.PopUpPlugins.check_tcpproxy.isChecked():
            self.Thread_TCPproxy = ThreadSniffingPackets(str(self.selectCard.currentText()),self.currentSessionID)
            self.Thread_TCPproxy.setObjectName('TCPProxy')
            self.Thread_TCPproxy.output_plugins.connect(self.get_TCPproxy_output)
            self.Apthreads['RougeAP'].append(self.Thread_TCPproxy)

        if self.InternetShareWiFi:
            print('[*] Sharing Internet Connections with NAT...')
        iptables = []
        # get all rules in settings->iptables
        for index in xrange(self.FSettings.ListRules.count()):
           iptables.append(str(self.FSettings.ListRules.item(index).text()))
        for rulesetfilter in iptables:
            if self.InternetShareWiFi: # disable share internet from network
                if '$inet' in rulesetfilter:
                    rulesetfilter = rulesetfilter.replace('$inet',str(self.interfacesLink['activated'][0]))
                if '$wlan' in rulesetfilter:
                    rulesetfilter = rulesetfilter.replace('$wlan',self.SettingsEnable['AP_iface'])
            if '$inet' in rulesetfilter or '$wlan' in rulesetfilter:
                continue
            popen(rulesetfilter)

        # start all Thread in sessions
        for thread in self.Apthreads['RougeAP']:
            self.progress.update_bar_simple(20)
            QtCore.QThread.sleep(1)
            thread.start()
        self.progress.setValue(100)
        self.progress.hideProcessbar()
        # check if Advanced mode is enable
        if self.FSettings.Settings.get_setting('dockarea','advanced',format=bool):
            self.PumpSettingsTAB.doCheckAdvanced()

        print('-------------------------------')
        print('AP::[{}] Running...'.format(self.EditApName.text()))
        print('AP::BSSID::[{}] CH {}'.format(Refactor.get_interface_mac(
        self.selectCard.currentText()),self.EditChannel.value()))
        self.FSettings.Settings.set_setting('accesspoint','ssid',str(self.EditApName.text()))
        self.FSettings.Settings.set_setting('accesspoint','channel',str(self.EditChannel.value()))

    def stop_access_point(self):
        ''' stop all thread :Access point attack and restore all settings  '''
        if self.Apthreads['RougeAP'] == []: return
        print('-------------------------------')
        self.ProxyPluginsTAB.GroupSettings.setEnabled(True)
        self.FSettings.Settings.set_setting('accesspoint','statusAP',False)
        self.FSettings.Settings.set_setting('accesspoint','bssid',str(self.EditBSSID.text()))
        self.SessionsAP[self.currentSessionID]['stoped'] = asctime()
        self.FSettings.Settings.set_setting('accesspoint','sessions',dumps(self.SessionsAP))
        # check if dockArea activated and stop dock Area
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
        for kill in self.SettingsAP['kill']: exec_bash(kill)
        # stop time count
        self.StatusAPTAB.stop_timer()
        #disabled options
        # check if persistent option in Settigs is enable
        #if not self.FSettings.Settings.get_setting('accesspoint','persistNetwokManager',format=bool):
        #    Refactor.settingsNetworkManager(self.SettingsEnable['AP_iface'],Remove=True)

        set_monitor_mode(self.SettingsEnable['AP_iface']).setDisable()
        self.set_status_label_AP(False)
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
        with open(C.DHCPLEASES_PATH,'w') as dhcpLease:
            dhcpLease.write(''),dhcpLease.close()
        self.btn_start_attack.setDisabled(False)
        # disable IP Forwarding in Linux
        Refactor.set_ip_forward(0)
        self.TabInfoAP.clearContents()
        self.window_phishing.killThread()

        self.GroupAP.setEnabled(True)
        self.GroupApPassphrase.setEnabled(True)
        self.GroupAdapter.setEnabled(True)
        self.PumpSettingsTAB.GroupDHCP.setEnabled(True)
        self.PopUpPlugins.tableplugins.setEnabled(True)
        self.PopUpPlugins.tableplugincheckbox.setEnabled(True)
        self.btn_cancelar.setEnabled(False)
        self.progress.showProcessBar()

    def about(self):
        ''' open about GUI interface '''
        self.Fabout = frmAbout(author,emails,
        version,update,license,desc)
        self.Fabout.show()
    def issue(self):
        ''' open issue in github page the project '''
        url = QtCore.QUrl('https://github.com/P0cL4bs/WiFi-Pumpkin/issues/new')
        if not QtGui.QDesktopServices.openUrl(url):
            QtGui.QMessageBox.warning(self, 'Open Url', 'Could not open url: {}'.format(url))
    def donate(self):
        ''' open page donation the project '''
        self.Fabout = frmAbout(author,emails,version,update,license,desc)
        self.Fabout.tabwid.setCurrentIndex(4)
        self.Fabout.show()

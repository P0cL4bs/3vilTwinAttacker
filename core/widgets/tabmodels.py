from proxy import *
from os import path
from PyQt4.QtGui import *
from PyQt4.QtCore import *
from datetime import datetime
from core.utils import Refactor
from core.utility.threads import ThreadPopen
from core.widgets.docks.dockmonitor import dockAreaAPI
"""
Description:
    This program is a core for wifi-pumpkin.py. file which includes functionality
    for pumpkin-proxy,pumokin-monitor,pumpkin-settings tab.

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

class PumpkinProxy(QVBoxLayout):
    ''' settings  Transparent Proxy '''
    sendError = pyqtSignal(str)
    _PluginsToLoader = {'plugins': None,'Content':''}
    def __init__(self,popup,main_method,FsettingsUI=None,parent = None):
        super(PumpkinProxy, self).__init__(parent)
        self.main_method = main_method
        self.popup      = popup
        self.urlinjected= []
        self.FSettings  = FsettingsUI
        self.mainLayout    = QVBoxLayout()

        #scroll area
        self.scrollwidget = QWidget()
        self.scrollwidget.setLayout(self.mainLayout)
        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setWidget(self.scrollwidget)

        # create widgets
        self.argsLabel  = QLabel('')
        self.hBox       = QHBoxLayout()
        self.hBoxargs   = QHBoxLayout()
        self.btnLoader  = QPushButton('Reload')
        self.btnEnable  = QPushButton('Enable')
        self.btncancel  = QPushButton('Cancel')
        self.btnbrownser= QPushButton('Browser')

        # size buttons
        self.btnLoader.setFixedWidth(100)
        self.btnEnable.setFixedWidth(100)
        self.btncancel.setFixedWidth(100)
        self.btnbrownser.setFixedWidth(100)

        self.comboxBox  = QComboBox()
        self.log_inject = QListWidget()
        self.docScripts = QTextEdit()
        self.argsScripts= QLineEdit()
        self.btncancel.setIcon(QIcon('icons/cancel.png'))
        self.btnLoader.setIcon(QIcon('icons/search.png'))
        self.btnEnable.setIcon(QIcon('icons/accept.png'))
        self.btnbrownser.setIcon(QIcon("icons/open.png"))
        self.argsScripts.setEnabled(False)
        self.btnbrownser.setEnabled(False)

        # group settings
        self.GroupSettings  = QGroupBox()
        self.GroupSettings.setTitle('settings:')
        self.SettingsLayout = QFormLayout()
        self.hBox.addWidget(self.comboxBox)
        self.hBox.addWidget(self.btnLoader)
        self.hBox.addWidget(self.btnEnable)
        self.hBox.addWidget(self.btncancel)
        self.hBoxargs.addWidget(self.argsLabel)
        self.hBoxargs.addWidget(self.argsScripts)
        self.hBoxargs.addWidget(self.btnbrownser)
        self.SettingsLayout.addRow(self.hBox)
        self.SettingsLayout.addRow(self.hBoxargs)
        self.GroupSettings.setLayout(self.SettingsLayout)
        #self.GroupSettings.setFixedWidth(450)
        #group logger
        self.GroupLogger  = QGroupBox()
        self.GroupLogger.setTitle('Logger Injection:')
        self.LoggerLayout = QVBoxLayout()
        self.LoggerLayout.addWidget(self.log_inject)
        self.GroupLogger.setLayout(self.LoggerLayout)
        #self.GroupLogger.setFixedWidth(450)

        #group descriptions
        self.GroupDoc  = QGroupBox()
        self.GroupDoc.setTitle('Description:')
        self.DocLayout = QFormLayout()
        self.DocLayout.addRow(self.docScripts)
        self.GroupDoc.setLayout(self.DocLayout)
        self.GroupDoc.setFixedHeight(100)

        #connections
        self.SearchProxyPlugins()
        self.readDocScripts('html_injector')
        self.btnLoader.clicked.connect(self.SearchProxyPlugins)
        self.connect(self.comboxBox,SIGNAL('currentIndexChanged(QString)'),self.readDocScripts)
        self.btnEnable.clicked.connect(self.setPluginsActivated)
        self.btncancel.clicked.connect(self.unsetPluginsConf)
        self.btnbrownser.clicked.connect(self.get_filenameToInjection)
        # add widgets
        self.mainLayout.addWidget(self.GroupSettings)
        self.mainLayout.addWidget(self.GroupDoc)
        self.mainLayout.addWidget(self.GroupLogger)
        self.layout = QHBoxLayout()
        self.layout.addWidget(self.scroll)
        self.addLayout(self.layout)

    def get_filenameToInjection(self):
        filename = QFileDialog.getOpenFileName(None,
        'load File','','HTML (*.html);;js (*.js);;css (*.css)')
        if len(filename) > 0:
            self.argsScripts.setText(filename)
            QMessageBox.information(None, 'Scripts Loaders', 'file has been loaded with success.')

    def setPluginsActivated(self):
        item = str(self.comboxBox.currentText())
        if self.popup.check_dns2proy.isChecked() or self.popup.check_sergioProxy.isChecked():
            if self.plugins[str(item)]._requiresArgs:
                if len(self.argsScripts.text()) != 0:
                    self._PluginsToLoader['plugins'] = item
                    self._PluginsToLoader['Content'] = str(self.argsScripts.text())
                else:
                    return self.sendError.emit('this module proxy requires {} args'.format(self.argsLabel.text()))
            else:
                self._PluginsToLoader['plugins'] = item
            self.btnEnable.setEnabled(False)
            self.ProcessReadLogger()
            return self.main_method.set_proxy_scripts(True)
        self.sendError.emit('plugins::Proxy is not enabled.'
        '\n\nthis module needs a proxy server(sslstrip) to work.'
        '\nPlease enable sslstrip in the Plugin Options.'.format(self.argsLabel.text()))

    def ProcessReadLogger(self):
        if path.exists('logs/AccessPoint/injectionPage.log'):
            with open('logs/AccessPoint/injectionPage.log','w') as bufferlog:
                bufferlog.write(''), bufferlog.close()
            self.injectionThread = ThreadPopen(['tail','-f','logs/AccessPoint/injectionPage.log'])
            self.connect(self.injectionThread,SIGNAL('Activated ( QString ) '), self.GetloggerInjection)
            self.injectionThread.setObjectName('Pump-Proxy::Capture')
            return self.injectionThread.start()
        QMessageBox.warning(self,'Proxy Logger','Pump-Proxy::capture is not found')

    def GetloggerInjection(self,data):
        if Refactor.getSize('logs/AccessPoint/injectionPage.log') > 255790:
            with open('logs/AccessPoint/injectionPage.log','w') as bufferlog:
                bufferlog.write(''), bufferlog.close()
        if data not in self.urlinjected:
            self.log_inject.addItem(data)
            self.urlinjected.append(data)
        self.log_inject.scrollToBottom()

    def readDocScripts(self,item):
        try:
            self.docScripts.setText(self.plugins[str(item)].__doc__)
            if self.plugins[str(item)]._requiresArgs:
                if 'FilePath' in self.plugins[str(item)]._argsname:
                    self.btnbrownser.setEnabled(True)
                else:
                    self.btnbrownser.setEnabled(False)
                self.argsScripts.setEnabled(True)
                self.argsLabel.setText(self.plugins[str(item)]._argsname)
            else:
                self.argsScripts.setEnabled(False)
                self.btnbrownser.setEnabled(False)
                self.argsLabel.setText('')
        except Exception:
            pass

    def unsetPluginsConf(self):
        if hasattr(self,'injectionThread'): self.injectionThread.stop()
        self._PluginsToLoader = {'plugins': None,'args':''}
        self.btnEnable.setEnabled(True)
        self.main_method.set_proxy_scripts(False)
        self.argsScripts.clear()
        self.log_inject.clear()
        self.urlinjected = []

    def SearchProxyPlugins(self):
        self.comboxBox.clear()
        self.plugin_classes = Plugin.PluginProxy.__subclasses__()
        self.plugins = {}
        for p in self.plugin_classes:
            self.plugins[p._name] = p()
        self.comboxBox.addItems(self.plugins.keys())


class PumpkinMonitor(QVBoxLayout):
    ''' Monitor Access Point cleints connections'''
    def __init__(self,FsettingsUI=None ,parent = None):
        super(PumpkinMonitor, self).__init__(parent)
        self.FSettings      = FsettingsUI
        self.Home   = QVBoxLayout()
        self.widget = QWidget()
        self.layout = QVBoxLayout(self.widget)

        self.GroupMonitor   = QGroupBox()
        self.MonitorTreeView= QTreeView()
        self.MonitorTreeView.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.model = QStandardItemModel()
        self.model.setHorizontalHeaderLabels(['Devices','Informations'])
        self.MonitorTreeView.setModel(self.model)
        self.MonitorTreeView.setUniformRowHeights(True)
        self.MonitorTreeView.setColumnWidth(0,130)

        self.GroupMonitor.setTitle('Station Monitor AP:')
        self.MonitorLayout = QVBoxLayout()
        self.MonitorLayout.addWidget(self.MonitorTreeView)
        self.GroupMonitor.setLayout(self.MonitorLayout)
        self.layout.addWidget(self.GroupMonitor)
        self.Home.addWidget(self.widget)
        self.addLayout(self.Home)

    def addRequests(self,macddress,user,status):
        if status:
            ParentMaster = QStandardItem('Connected:: {} at {}'.format(macddress,
            datetime.now().strftime("%H:%M")))
            ParentMaster.setIcon(QIcon('icons/connected.png'))
            ParentMaster.setSizeHint(QSize(30,30))
            info1 = QStandardItem('{}'.format(user['device']))
            info2 = QStandardItem('{}'.format(user['IP']))
            info3 = QStandardItem('{}'.format(datetime.now().strftime("%Y-%m-%d %H:%M")))
            ParentMaster.appendRow([QStandardItem('Device::'),info1])
            ParentMaster.appendRow([QStandardItem('IPAddr::'),info2])
            ParentMaster.appendRow([QStandardItem('Current date::'),info3])
            self.model.appendRow(ParentMaster)
            return self.MonitorTreeView.setFirstColumnSpanned(ParentMaster.row(),
            self.MonitorTreeView.rootIndex(), True)

        ParentMaster = QStandardItem('Disconnected:: {} at {}'.format(macddress,
        datetime.now().strftime("%H:%M")))
        ParentMaster.setIcon(QIcon('icons/disconnected.png'))
        ParentMaster.setSizeHint(QSize(30,30))
        info1 = QStandardItem('{}'.format(user['device']))
        info2 = QStandardItem('{}'.format(user['IP']))
        info3 = QStandardItem('{}'.format(datetime.now().strftime("%Y-%m-%d %H:%M")))
        ParentMaster.appendRow([QStandardItem('Device::'),info1])
        ParentMaster.appendRow([QStandardItem('IPAddr::'),info2])
        ParentMaster.appendRow([QStandardItem('Current date::'),info3])
        self.model.appendRow(ParentMaster)
        self.MonitorTreeView.setFirstColumnSpanned(ParentMaster.row(),
        self.MonitorTreeView.rootIndex(), True)


class PumpkinSettings(QVBoxLayout):
    ''' settings DHCP options'''
    sendMensage = pyqtSignal(str)
    checkDockArea = pyqtSignal(dict)
    def __init__(self, parent=None,settingsAP=None,dockinfo=None,InitialMehtod=None,FsettingsUI=None):
        super(PumpkinSettings, self).__init__(parent)
        self.SettingsAp      = settingsAP
        self.InitialMehtod   = InitialMehtod
        self.dockInfo      = dockinfo
        self.SettingsDHCP  = {}
        self.FSettings     = FsettingsUI
        self.mainLayout    = QFormLayout()

        #scroll area
        self.scrollwidget = QWidget()
        self.scrollwidget.setLayout(self.mainLayout)
        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setWidget(self.scrollwidget)

        self.GroupDHCP     = QGroupBox()
        self.GroupArea     = QGroupBox()
        self.layoutDHCP    = QFormLayout()
        self.layoutArea    = QFormLayout()
        self.layoutbuttons = QHBoxLayout()
        self.btnDefault    = QPushButton('Default')
        self.btnSave       = QPushButton('Save Settings')
        self.btnSave.setIcon(QIcon('icons/export.png'))
        self.btnDefault.setIcon(QIcon('icons/settings.png'))
        self.dhcpClassIP   = QComboBox()
        # dhcp class
        self.classtypes = ['Class-A-Address','Class-B-Address','Class-C-Address','Class-Custom-Address']
        for types in self.classtypes:
            if 'Class-{}-Address'.format(self.FSettings.Settings.get_setting('dhcp','classtype')) in types:
                self.classtypes.remove(types),self.classtypes.insert(0,types)
        self.dhcpClassIP.addItems(self.classtypes)

        self.leaseTime_def = QLineEdit(self.FSettings.Settings.get_setting('dhcp','leasetimeDef'))
        self.leaseTime_Max = QLineEdit(self.FSettings.Settings.get_setting('dhcp','leasetimeMax'))
        self.netmask       = QLineEdit(self.FSettings.Settings.get_setting('dhcp','netmask'))
        self.range_dhcp    = QLineEdit(self.FSettings.Settings.get_setting('dhcp','range'))
        self.route         = QLineEdit(self.FSettings.Settings.get_setting('dhcp','router'))
        self.subnet        = QLineEdit(self.FSettings.Settings.get_setting('dhcp','subnet'))
        self.broadcast     = QLineEdit(self.FSettings.Settings.get_setting('dhcp','broadcast'))
        self.dhcpClassIP.currentIndexChanged.connect(self.dhcpClassIPClicked)
        self.GroupDHCP.setTitle('DHCP Settings')
        self.GroupDHCP.setLayout(self.layoutDHCP)
        self.layoutDHCP.addRow('Class Ranges',self.dhcpClassIP)
        self.layoutDHCP.addRow('default-lease-time',self.leaseTime_def)
        self.layoutDHCP.addRow('max-lease-time',self.leaseTime_Max)
        self.layoutDHCP.addRow('subnet',self.subnet)
        self.layoutDHCP.addRow('router',self.route)
        self.layoutDHCP.addRow('netmask',self.netmask)
        self.layoutDHCP.addRow('broadcast-address',self.broadcast)
        self.layoutDHCP.addRow('range-dhcp',self.range_dhcp)
        self.GroupDHCP.setFixedWidth(350)
        # layout add
        self.layoutbuttons.addWidget(self.btnSave)
        self.layoutbuttons.addWidget(self.btnDefault)
        self.layoutDHCP.addRow(self.layoutbuttons)

        # Area Group
        self.gridArea = QGridLayout()
        self.CB_ActiveMode = QCheckBox('::Advanced Mode:: Monitor MITM Attack')
        self.CB_Cread    = QCheckBox('HTTP-Authentication')
        self.CB_monitorURL = QCheckBox('HTTP-Requests')
        self.CB_bdfproxy   = QCheckBox('BDFProxy-ng')
        self.CB_dns2proxy  = QCheckBox('Dns2Proxy')
        self.CB_responder  = QCheckBox('Responder')
        self.CB_ActiveMode.setChecked(self.FSettings.Settings.get_setting('dockarea','advanced',format=bool))
        self.CB_Cread.setChecked(self.FSettings.Settings.get_setting('dockarea','dock_credencials',format=bool))
        self.CB_monitorURL.setChecked(self.FSettings.Settings.get_setting('dockarea','dock_urlmonitor',format=bool))
        self.CB_bdfproxy.setChecked(self.FSettings.Settings.get_setting('dockarea','dock_bdfproxy',format=bool))
        self.CB_dns2proxy.setChecked(self.FSettings.Settings.get_setting('dockarea','dock_dns2proxy',format=bool))
        self.CB_responder.setChecked(self.FSettings.Settings.get_setting('dockarea','dock_responder',format=bool))

        #connect
        self.doCheckAdvanced()
        self.CB_ActiveMode.clicked.connect(self.doCheckAdvanced)
        self.CB_monitorURL.clicked.connect(self.doCheckAdvanced)
        self.CB_Cread.clicked.connect(self.doCheckAdvanced)
        self.CB_bdfproxy.clicked.connect(self.doCheckAdvanced)
        self.CB_dns2proxy.clicked.connect(self.doCheckAdvanced)
        self.CB_responder.clicked.connect(self.doCheckAdvanced)
        # group
        self.layoutArea.addRow(self.CB_ActiveMode)
        self.gridArea.addWidget(self.CB_monitorURL,0,0,)
        self.gridArea.addWidget(self.CB_Cread,0,1)
        self.gridArea.addWidget(self.CB_bdfproxy,1,0)
        self.gridArea.addWidget(self.CB_bdfproxy,1,0)
        self.gridArea.addWidget(self.CB_dns2proxy,1,1)
        self.gridArea.addWidget(self.CB_responder,1,2)
        self.layoutArea.addRow(self.gridArea)
        self.GroupArea.setTitle('Activity Monitor Settings')
        self.GroupArea.setLayout(self.layoutArea)

        # connects
        self.btnDefault.clicked.connect(self.setdefaultSettings)
        self.btnSave.clicked.connect(self.savesettingsDHCP)
        self.mainLayout.addRow(self.SettingsAp)
        self.mainLayout.addRow(self.GroupArea)
        self.mainLayout.addRow(self.GroupDHCP)
        self.layout = QHBoxLayout()
        self.layout.addWidget(self.scroll)
        self.addLayout(self.layout)


    def dhcpClassIPClicked(self,classIP):
        self.selected = str(self.dhcpClassIP.currentText())
        if 'class-Custom-Address' in self.selected: self.selected = 'dhcp'
        self.leaseTime_def.setText(self.FSettings.Settings.get_setting(self.selected,'leasetimeDef'))
        self.leaseTime_Max.setText(self.FSettings.Settings.get_setting(self.selected,'leasetimeMax'))
        self.netmask.setText(self.FSettings.Settings.get_setting(self.selected,'netmask'))
        self.range_dhcp.setText(self.FSettings.Settings.get_setting(self.selected,'range'))
        self.route.setText(self.FSettings.Settings.get_setting(self.selected,'router'))
        self.subnet.setText(self.FSettings.Settings.get_setting(self.selected,'subnet'))
        self.broadcast.setText(self.FSettings.Settings.get_setting(self.selected,'broadcast'))

    def AreaWidgetLoader(self,DockInfo):
        if hasattr(self,'dockList'):
            for dock in self.dockList: dock.close()
        self.AllDockArea = {}
        if self.FSettings.Settings.get_setting('dockarea','advanced',format=bool):
            self.dockList = []
            for key in DockInfo.keys():
                if DockInfo[key]['active']:
                    self.dock = QDockWidget(key)
                    self.AllDockArea[key] = dockAreaAPI(None,DockInfo[key])
                    self.dock.setWidget(self.AllDockArea[key])
                    self.dock.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
                    self.dock.setAllowedAreas(Qt.AllDockWidgetAreas)
                    self.dock.setFeatures(QDockWidget.DockWidgetMovable | QDockWidget.DockWidgetFloatable)
                    self.InitialMehtod.addDockWidget(Qt.LeftDockWidgetArea, self.dock)
                    self.dockList.insert(0,self.dock)
            if len(self.dockList) > 1:
                for index in range(1, len(self.dockList) - 1):
                    if self.dockList[index].objectName() != 'HTTP-Requests':
                        self.InitialMehtod.tabifyDockWidget(self.dockList[index],
                            self.dockList[index + 1])
            try:
                self.dockList[0].raise_()
            except IndexError:
                pass
            self.checkDockArea.emit(self.AllDockArea)


    def doCheckAdvanced(self):
        if self.CB_ActiveMode.isChecked():
            self.CB_monitorURL.setEnabled(True)
            self.CB_Cread.setEnabled(True)
            self.CB_bdfproxy.setEnabled(True)
            self.CB_dns2proxy.setEnabled(True)
            self.CB_responder.setEnabled(True)
        else:
            self.CB_monitorURL.setEnabled(False)
            self.CB_Cread.setEnabled(False)
            self.CB_bdfproxy.setEnabled(False)
            self.CB_dns2proxy.setEnabled(False)
            self.CB_responder.setEnabled(False)
        self.FSettings.Settings.set_setting('dockarea','dock_credencials',self.CB_Cread.isChecked())
        self.FSettings.Settings.set_setting('dockarea','dock_urlmonitor',self.CB_monitorURL.isChecked())
        self.FSettings.Settings.set_setting('dockarea','dock_bdfproxy',self.CB_bdfproxy.isChecked())
        self.FSettings.Settings.set_setting('dockarea','dock_dns2proxy',self.CB_dns2proxy.isChecked())
        self.FSettings.Settings.set_setting('dockarea','dock_responder',self.CB_responder.isChecked())
        self.FSettings.Settings.set_setting('dockarea','advanced',self.CB_ActiveMode.isChecked())
        self.dockInfo['HTTP-Requests']['active'] = self.CB_monitorURL.isChecked()
        self.dockInfo['HTTP-Authentication']['active'] = self.CB_Cread.isChecked()
        self.dockInfo['BDFProxy']['active'] = self.CB_bdfproxy.isChecked()
        self.dockInfo['Dns2Proxy']['active'] = self.CB_dns2proxy.isChecked()
        self.dockInfo['Responder']['active'] = self.CB_responder.isChecked()
        if self.CB_ActiveMode.isChecked():
            self.AreaWidgetLoader(self.dockInfo)
            self.checkDockArea.emit(self.AllDockArea)
            if hasattr(self.InitialMehtod,'form_widget'):
                if hasattr(self.InitialMehtod.form_widget,'Apthreads'):
                    if self.InitialMehtod.form_widget.Apthreads['RougeAP'] != []:
                        for dock in self.InitialMehtod.form_widget.dockAreaList.keys():
                            self.InitialMehtod.form_widget.dockAreaList[dock].RunThread()
        else:
            if hasattr(self,'dockList'):
                for dock in self.dockList: dock.close()


    def setdefaultSettings(self):
        self.dhcpClassIP.setCurrentIndex(self.classtypes.index('Class-A-Address'))
        self.leaseTime_def.setText(self.FSettings.Settings.get_setting('dhcpdefault','leasetimeDef'))
        self.leaseTime_Max.setText(self.FSettings.Settings.get_setting('dhcpdefault','leasetimeMax'))
        self.netmask.setText(self.FSettings.Settings.get_setting('dhcpdefault','netmask'))
        self.range_dhcp.setText(self.FSettings.Settings.get_setting('dhcpdefault','range'))
        self.route.setText(self.FSettings.Settings.get_setting('dhcpdefault','router'))
        self.subnet.setText(self.FSettings.Settings.get_setting('dhcpdefault','subnet'))
        self.broadcast.setText(self.FSettings.Settings.get_setting('dhcpdefault','broadcast'))

    def savesettingsDHCP(self):
        self.all_geteway_check = []
        for types in self.classtypes:
            if not 'Class-Custom-Address' in types:
                self.all_geteway_check.append(self.FSettings.Settings.get_by_index_key(5,types))
        self.FSettings.Settings.set_setting('dhcp','classtype',str(self.dhcpClassIP.currentText()).split('-')[1])
        self.FSettings.Settings.set_setting('dhcp','leasetimeDef',str(self.leaseTime_def.text()))
        self.FSettings.Settings.set_setting('dhcp','leasetimeMax',str(self.leaseTime_Max.text()))
        self.FSettings.Settings.set_setting('dhcp','netmask',str(self.netmask.text()))
        self.FSettings.Settings.set_setting('dhcp','range',str(self.range_dhcp.text()))
        self.FSettings.Settings.set_setting('dhcp','router',str(self.route.text()))
        self.FSettings.Settings.set_setting('dhcp','subnet',str(self.subnet.text()))
        self.FSettings.Settings.set_setting('dhcp','broadcast',str(self.broadcast.text()))
        if not str(self.route.text()) in self.all_geteway_check:
            self.FSettings.Settings.set_setting('dhcp','classtype','Custom')
        self.btnSave.setEnabled(False)
        self.sendMensage.emit('DHCP settings saved with success...')
        self.btnSave.setEnabled(True)

    def getPumpkinSettings(self):
        self.SettingsDHCP['leasetimeDef'] = str(self.leaseTime_def.text())
        self.SettingsDHCP['leasetimeMax'] = str(self.leaseTime_Max.text())
        self.SettingsDHCP['subnet'] = str(self.subnet.text())
        self.SettingsDHCP['router'] = str(self.route.text())
        self.SettingsDHCP['netmask'] = str(self.netmask.text())
        self.SettingsDHCP['broadcast'] = str(self.broadcast.text())
        self.SettingsDHCP['range'] = str(self.range_dhcp.text())
        return self.SettingsDHCP

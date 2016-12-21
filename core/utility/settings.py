from os import path,popen
from re import search
from PyQt4.QtCore import *
from PyQt4.QtGui import *
from core.utility.collection import SettingsINI

"""
Description:
    This program is a module for wifi-pumpkin.py.

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

class SettingsTabGeneral(QVBoxLayout):
    def __init__(self,Settings=None,parent= None):
        super(SettingsTabGeneral, self).__init__(parent)
        self.Settings      = Settings
        self.mainLayout    = QFormLayout()
        self.scrollwidget = QWidget()
        self.scrollwidget.setLayout(self.mainLayout)
        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setWidget(self.scrollwidget)

        self.GruPag0=QButtonGroup()
        self.GruPag1=QButtonGroup()
        self.GruPag2=QButtonGroup()
        self.GruPag3=QButtonGroup()
        self.GruPag4=QButtonGroup()

        # group options
        self.groupAP = QGroupBox()
        self.groupDhcp = QGroupBox()
        self.groupDeauth = QGroupBox()
        self.groupScan   = QGroupBox()
        self.groupThemes = QGroupBox()

        #form group
        self.formGroupAP = QFormLayout()
        self.formGroupDHCP = QFormLayout()
        self.formGroupDeauth = QFormLayout()
        self.formGroupScan = QFormLayout()
        self.formGroupThemes = QFormLayout()

        # set layout into groupbox
        self.groupAP.setLayout(self.formGroupAP)
        self.groupDhcp.setLayout(self.formGroupDHCP)
        self.groupDeauth.setLayout(self.formGroupDeauth)
        self.groupScan.setLayout(self.formGroupScan)
        self.groupThemes.setLayout(self.formGroupThemes)

        self.groupAP.setTitle('Access Point:')
        self.groupDhcp.setTitle('DHCP Server:')
        self.groupDeauth.setTitle('Deauth Attack:')
        self.groupScan.setTitle('Scan Network:')
        self.groupThemes.setTitle('Pumpkin Themes:')

        #page general
        self.Apname =  QLineEdit()
        self.Apname.setFixedWidth(80)
        self.channel = QSpinBox()
        self.network_manager = QCheckBox('Ignore USB Wi-Fi Adapter permanently')
        self.network_manager.setToolTip('We will use this file to tell Network Manager to stop controlling '
        'a particular interface.\nif you enable this options in next time you start AP the tool will not '
        'remove the key\nfor exclude card in file of configuration.')
        self.network_manager.setChecked(self.Settings.get_setting('accesspoint','persistNetwokManager',format=bool))

        #page 1 widgets
        self.AP_0 = QRadioButton('Hostapd')
        self.AP_1 = QRadioButton('Hostapd C. Binary (support hostapd-mana)')
        self.AP_0.setObjectName('hostapd_normal')
        self.AP_1.setObjectName('hostapd_edit')
        self.edit_hostapd_path = QLineEdit('')
        self.d_scapy = QRadioButton('Scapy Deauth')
        self.d_mdk = QRadioButton('mdk3 Deauth')
        self.scan_scapy = QRadioButton('Scan from scapy')
        self.scan_airodump = QRadioButton('Scan from airodump-ng')
        self.dhcpdserver = QRadioButton('Isc DHCP Server (dhcpd)')
        self.pydhcpserver = QRadioButton('python DHCPServer')
        self.theme1 = QRadioButton('theme Default')
        self.theme2 = QRadioButton('theme Blue Dark ')
        self.theme3 = QRadioButton('theme Orange Dark')
        self.theme1.setObjectName('themes/'+''.join(str(self.theme1.text()).split()))
        self.theme2.setObjectName('themes/'+''.join(str(self.theme2.text()).split()))
        self.theme3.setObjectName('themes/'+''.join(str(self.theme3.text()).split()))
        #grup page 1
        self.GruPag0.addButton(self.AP_0)
        self.GruPag0.addButton(self.AP_1)
        self.GruPag1.addButton(self.d_scapy)
        self.GruPag1.addButton(self.d_mdk)
        self.GruPag2.addButton(self.pydhcpserver)
        self.GruPag2.addButton(self.dhcpdserver)
        self.GruPag3.addButton(self.scan_scapy)
        self.GruPag3.addButton(self.scan_airodump)
        self.GruPag4.addButton(self.theme1)
        self.GruPag4.addButton(self.theme2)
        self.GruPag4.addButton(self.theme3)

        #page 1 config widgets
        self.GruPag0.buttonClicked.connect(self.get_options_hostapd)
        self.Apname.setText(self.Settings.get_setting('accesspoint','ssid'))
        self.channel.setValue(int(self.Settings.get_setting('accesspoint','channel')))
        self.d_scapy.setChecked(self.Settings.get_setting('settings','scapy_deauth',format=bool))
        self.d_mdk.setChecked(self.Settings.get_setting('settings','mdk3_deauth',format=bool))
        self.scan_scapy.setChecked(self.Settings.get_setting('settings','scan_scapy',format=bool))
        self.scan_airodump.setChecked(self.Settings.get_setting('settings','scan_airodump',format=bool))
        self.pydhcpserver.setChecked(self.Settings.get_setting('accesspoint', 'pydhcp_server',format=bool))
        self.dhcpdserver.setChecked(self.Settings.get_setting('accesspoint', 'dhcpd_server',format=bool))
        self.theme_selected = self.Settings.get_setting('settings','themes')

        check_path_hostapd = self.Settings.get_setting('accesspoint','hostapd_path')
        if len(check_path_hostapd) > 2: self.edit_hostapd_path.setText(check_path_hostapd)
        check_hostapd_custom = self.Settings.get_setting('accesspoint','hostapd_custom',format=bool)
        if check_hostapd_custom:
            self.AP_1.setChecked(True)
        else:
            self.edit_hostapd_path.setEnabled(False)
            self.AP_0.setChecked(True)

        # setting page 1
        if self.theme_selected in self.theme1.objectName():
            self.theme1.setChecked(True)
        elif self.theme_selected in self.theme2.objectName():
            self.theme2.setChecked(True)
        elif self.theme_selected in self.theme3.objectName():
            self.theme3.setChecked(True)
        self.formGroupAP.addRow('SSID:',self.Apname)
        self.formGroupAP.addRow('Channel:',self.channel)
        self.formGroupAP.addRow(self.AP_0)
        self.formGroupAP.addRow(self.AP_1)
        self.formGroupAP.addRow('Location:',self.edit_hostapd_path)
        self.formGroupAP.addRow(self.network_manager)
        self.formGroupDeauth.addRow(self.d_scapy)
        self.formGroupDeauth.addRow(self.d_mdk)
        self.formGroupScan.addRow(self.scan_scapy)
        self.formGroupScan.addRow(self.scan_airodump)
        self.formGroupDHCP.addRow(self.pydhcpserver)
        self.formGroupDHCP.addRow(self.dhcpdserver)
        self.formGroupThemes.addRow(self.theme1)
        self.formGroupThemes.addRow(self.theme2)
        self.formGroupThemes.addRow(self.theme3)

        self.mainLayout.addRow(self.groupAP)
        self.mainLayout.addRow(self.groupDhcp)
        self.mainLayout.addRow(self.groupScan)
        self.mainLayout.addRow(self.groupDeauth)
        self.mainLayout.addRow(self.groupThemes)

        self.layout = QHBoxLayout()
        self.layout.addWidget(self.scroll)
        self.addLayout(self.layout)

    def get_options_hostapd(self,option):
        '''check if Qradiobox is clicked '''
        if option.objectName() ==  'hostapd_edit':
            return self.edit_hostapd_path.setEnabled(True)
        if option.objectName() == 'hostapd_normal':
            hostapd = popen('which hostapd').read().split('\n')[0]
            if path.isfile(hostapd):
                self.edit_hostapd_path.setText(hostapd)
            self.edit_hostapd_path.setEnabled(False)


class frm_Settings(QDialog):
    def __init__(self, parent = None):
        super(frm_Settings, self).__init__(parent)
        self.setWindowTitle('settings WiFi-Pompkin')
        self.Settings = SettingsINI('core/config/app/config.ini')
        self.bdfproxyConf  = SettingsINI(self.Settings.get_setting('plugins','bdfproxy_config'))
        self.loadtheme(self.XmlThemeSelected())
        self.setGeometry(0, 0, 420, 440)
        self.center()
        self.Qui()

    def loadtheme(self,theme):
        ''' load theme widgets '''
        sshFile=("core/%s.qss"%(theme))
        with open(sshFile,"r") as fh:
            self.setStyleSheet(fh.read())

    def XmlThemeSelected(self):
        ''' get theme selected path'''
        return self.Settings.get_setting('settings','themes')

    def center(self):
        ''' set center widgets '''
        frameGm = self.frameGeometry()
        centerPoint = QDesktopWidget().availableGeometry().center()
        frameGm.moveCenter(centerPoint)
        self.move(frameGm.topLeft())

    def save_settings(self):
        self.Settings.set_setting('settings','scapy_deauth',self.pageTab1.d_scapy.isChecked())
        self.Settings.set_setting('settings','mdk3_deauth',self.pageTab1.d_mdk.isChecked())
        self.Settings.set_setting('settings','scan_scapy',self.pageTab1.scan_scapy.isChecked())
        self.Settings.set_setting('settings','scan_airodump',self.pageTab1.scan_airodump.isChecked())
        self.Settings.set_setting('accesspoint','dhcpd_server',self.pageTab1.dhcpdserver.isChecked())
        self.Settings.set_setting('accesspoint','pydhcp_server',self.pageTab1.pydhcpserver.isChecked())
        if self.pageTab1.theme1.isChecked():
            self.Settings.set_setting('settings','themes',str(self.pageTab1.theme1.objectName()))
        elif self.pageTab1.theme2.isChecked():
            self.Settings.set_setting('settings','themes',str(self.pageTab1.theme2.objectName()))
        elif self.pageTab1.theme3.isChecked():
            self.Settings.set_setting('settings','themes',str(self.pageTab1.theme3.objectName()))
        if self.pageTab1.AP_0.isChecked():
            self.Settings.set_setting('accesspoint','hostapd_custom',False)
        elif self.pageTab1.AP_1.isChecked():
            self.Settings.set_setting('accesspoint','hostapd_custom',True)

        self.Settings.set_setting('settings','mdk3',str(self.txt_arguments.text()))
        self.Settings.set_setting('settings','scanner_rangeIP',str(self.txt_ranger.text()))
        self.Settings.set_setting('accesspoint','ssid', str(self.pageTab1.Apname.text()))
        self.Settings.set_setting('accesspoint','channel', str(self.pageTab1.channel.value()))
        self.Settings.set_setting('accesspoint','persistNetwokManager',self.pageTab1.network_manager.isChecked())
        self.Settings.set_setting('accesspoint','check_support_ap_mode',self.check_interface_mode_AP.isChecked())
        self.Settings.set_setting('settings','redirect_port', str(self.redirectport.text()))
        if not path.isfile(self.pageTab1.edit_hostapd_path.text()):
            return QMessageBox.warning(self,'Path Hostapd Error','hostapd binary path is not found')
        self.Settings.set_setting('accesspoint','hostapd_path',self.pageTab1.edit_hostapd_path.text())
        with open('core/config/hostapd/hostapd+.conf','w') as apconf:
            apconf.write(self.ListHostapd.toPlainText())
        self.close()


    def listItemclicked(self,pos):
        ''' add,remove and edit rules iptables from WIFi-Pumpkin'''
        item = self.ListRules.selectedItems()
        self.listMenu= QMenu()
        menu = QMenu()
        additem = menu.addAction('Add')
        editem = menu.addAction('Edit')
        removeitem = menu.addAction('Remove ')
        clearitem = menu.addAction('clear')
        action = menu.exec_(self.ListRules.viewport().mapToGlobal(pos))
        if action == removeitem:
            if item != []:
                self.ListRules.takeItem(self.ListRules.currentRow())
        elif action == additem:
            text, resp = QInputDialog.getText(self, 'Add rules iptables',
            'Enter the rules iptables:')
            if resp:
                try:
                    itemsexits = []
                    for index in xrange(self.ListRules.count()):
                        itemsexits.append(str(self.ListRules.item(index).text()))
                    for i in itemsexits:
                        if search(str(text),i):
                            return QMessageBox.information(self,'Rules exist','this rules already exist!')
                    item = QListWidgetItem()
                    item.setText(text)
                    item.setSizeHint(QSize(30,30))
                    self.ListRules.addItem(item)
                except Exception as e:
                    return QMessageBox.information(self,'error',str(e))
        elif action == editem:
            text, resp = QInputDialog.getText(self, 'Add rules iptables',
            'Enter the rules iptables:',text=self.ListRules.item(self.ListRules.currentRow()).text())
            if resp:
                try:
                    itemsexits = []
                    for index in xrange(self.ListRules.count()):
                        itemsexits.append(str(self.ListRules.item(index).text()))
                    for i in itemsexits:
                        if search(str(text),i):
                            return QMessageBox.information(self,'Rules exist','this rules already exist!')
                    item = QListWidgetItem()
                    item.setText(text)
                    item.setSizeHint(QSize(30,30))
                    self.ListRules.insertItem(self.ListRules.currentRow(),item)
                except Exception as e:
                    return QMessageBox.information(self,'error',str(e))
        elif action == clearitem:
            self.ListRules.clear()

    def Qui(self):
        self.Main = QVBoxLayout()
        self.formGroupAd  = QFormLayout()
        self.form = QFormLayout()
        self.tabcontrol = QTabWidget()

        # tabs
        self.tab1 = QWidget()
        self.tab2 = QWidget()
        self.tab3 = QWidget()
        self.tab4 = QWidget()

        self.page_1 = QVBoxLayout(self.tab1)
        self.page_2 = QFormLayout(self.tab2)
        self.page_3 = QFormLayout(self.tab3)
        self.page_4 = QFormLayout(self.tab4)

        self.tabcontrol.addTab(self.tab1, 'General')
        self.tabcontrol.addTab(self.tab2, 'Advanced')
        self.tabcontrol.addTab(self.tab3,'Iptables')
        self.tabcontrol.addTab(self.tab4,'hostpad')

        self.pageTab1 = SettingsTabGeneral(self.Settings)
        self.page_1.addLayout(self.pageTab1)

        self.groupAdvanced = QGroupBox()
        self.groupAdvanced.setTitle('Advanced settings:')
        self.groupAdvanced.setLayout(self.formGroupAd)

        self.btn_save = QPushButton('Save')
        self.btn_save.clicked.connect(self.save_settings)
        self.btn_save.setFixedWidth(80)
        self.btn_save.setIcon(QIcon('icons/Save.png'))


        #page Adavanced
        self.bdfProxy_port = QSpinBox()
        self.bdfProxy_port.setMaximum(10000)
        self.txt_ranger = QLineEdit(self)
        self.txt_arguments = QLineEdit(self)
        self.scan1 = QRadioButton('Ping Scan:: Very fast scan IP')
        self.scan2 = QRadioButton('Python-Nmap:: Get hostname from IP')
        self.redirectport = QLineEdit(self)
        self.check_interface_mode_AP = QCheckBox('Check if interface has been support AP/Mode')
        self.check_interface_mode_AP.setChecked(self.Settings.get_setting('accesspoint','check_support_ap_mode',format=bool))
        self.check_interface_mode_AP.setToolTip('if you disable this options in next time, the interface is not should '
        'checked if has support AP mode.')

        # page Iptables
        self.ListRules = QListWidget(self)
        self.ListRules.setFixedHeight(300)
        self.ListRules.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOn)
        self.ListRules.setContextMenuPolicy(Qt.CustomContextMenu)
        self.ListRules.connect(self.ListRules,
        SIGNAL('customContextMenuRequested(QPoint)'),
        self.listItemclicked)
        for ech in self.Settings.get_all_childname('iptables'):
            item = QListWidgetItem()
            item.setText(str(self.Settings.get_setting('iptables',ech,format=str)))
            item.setSizeHint(QSize(30,30))
            self.ListRules.addItem(item)

        # page hostpad
        self.ListHostapd = QTextEdit(self)
        self.ListHostapd.setFixedHeight(300)
        with open('core/config/hostapd/hostapd+.conf','r') as apconf:
            self.ListHostapd.setText(apconf.read())

        # grup page 2
        self.gruButtonPag2 = QButtonGroup()
        self.gruButtonPag2.addButton(self.scan1)
        self.gruButtonPag2.addButton(self.scan2)

        self.txt_ranger.setText(self.Settings.get_setting('settings','scanner_rangeIP'))
        self.txt_arguments.setText(self.Settings.get_setting('settings','mdk3'))
        self.bdfProxy_port.setValue(int(self.bdfproxyConf.get_setting('Overall','proxyPort')))
        self.bdfProxy_port.setEnabled(False)
        self.scan2.setEnabled(False)
        self.scan1.setChecked(True)
        #settings tab Advanced
        self.redirectport.setText(self.Settings.get_setting('settings','redirect_port'))

        #add tab Advanced
        self.formGroupAd.addRow(QLabel('Thread Scan IP-Address:'))
        self.formGroupAd.addRow(self.scan1)
        self.formGroupAd.addRow(self.scan2)
        self.formGroupAd.addRow(self.check_interface_mode_AP)
        self.formGroupAd.addRow('Port BDFProxy-ng',self.bdfProxy_port)
        self.formGroupAd.addRow('Port sslstrip:',self.redirectport)
        self.formGroupAd.addRow(QLabel('mdk3 Args:'),self.txt_arguments)
        self.formGroupAd.addRow(QLabel('Range Scanner:'),self.txt_ranger)
        self.page_2.addRow(self.groupAdvanced)

        #add tab iptables
        self.page_3.addWidget(QLabel('Iptables:'))
        self.page_3.addRow(self.ListRules)

        #add tab hostpad
        self.page_4.addWidget(QLabel('settings hostapd:'))
        self.page_4.addRow(self.ListHostapd)

        self.form.addRow(self.tabcontrol)
        self.form.addRow(self.btn_save)
        self.Main.addLayout(self.form)
        self.setLayout(self.Main)

from os import getcwd,devnull
import threading
from multiprocessing import Process,Manager
from socket import gaierror
from re import search
from socket import gethostbyname
from scapy.all import get_if_hwaddr
from core.loaders.models.PackagesUI import *
from modules.spreads.UpdateFake import frm_update_attack
from core.packets.network import ThARP_posion,ThreadDNSspoofNF
threadloading = {'template':[],'dnsspoof':[],'arps':[]}

"""
Description:
    This program is a module for wifi-pumpkin.py file which includes functionality
    for Dns spoof Attack.

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

class frm_DnsSpoof(PumpkinModule):
    def __init__(self, PhishingManager,parent=None):
        super(frm_DnsSpoof, self).__init__(parent)
        self.setWindowTitle('DNS Spoofer')
        self.Main       = QVBoxLayout()
        self.owd        = getcwd()
        self.Ftemplates = PhishingManager
        self.loadtheme(self.configure.XmlThemeSelected())
        self.data       = {'IPaddress':[], 'Hostname':[], 'MacAddress':[]}
        self.ThreadDirc = {'dns_spoof':[]}
        global threadloading
        self.GUI()

    def closeEvent(self, event):
        reply = QMessageBox.question(self, 'DNS Spoofer',
            'Are you sure you want to close the DNS Spoofer?', QMessageBox.Yes |
            QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            event.accept()
            if len(self.ThreadDirc['dns_spoof']) != 0:
                for i in self.ThreadDirc['dns_spoof']:i.stop()
                for i in threadloading['template']:
                    i.stop(),i.join()
                    threadloading['template'] = []
                if not self.configure.Settings.get_setting('accesspoint','statusAP'):
                    Refactor.set_ip_forward(0)
            self.deleteLater()
            return
        event.ignore()


    def GUI(self):
        self.form           = QFormLayout()
        self.layoutform     = QFormLayout()
        self.layoutHost     = QFormLayout()
        self.layoutDNSReq   = QFormLayout()
        self.statusBar      = QStatusBar(self)
        self.tables = QTableWidget(5,3)
        self.tables.setRowCount(100)
        self.tables.setFixedHeight(245)
        self.tables.setFixedWidth(350)
        self.tables.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.tables.horizontalHeader().setStretchLastSection(True)
        self.tables.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.tables.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.tables.clicked.connect(self.list_clicked_scan)
        self.tables.resizeColumnsToContents()
        self.tables.resizeRowsToContents()
        self.tables.horizontalHeader().resizeSection(1,100)
        self.tables.horizontalHeader().resizeSection(0,100)
        self.tables.horizontalHeader().resizeSection(2,100)
        self.tables.verticalHeader().setVisible(False)
        self.tables.setSortingEnabled(True)
        Headers = []
        for key in reversed(self.data.keys()):
            Headers.append(key)
        self.tables.setHorizontalHeaderLabels(Headers)
        self.tables.verticalHeader().setDefaultSectionSize(23)

        self.ip_range = QLineEdit(self)
        self.txt_gateway = QLineEdit(self)
        self.txt_redirect = QLineEdit(self)
        self.txt_target = QLineEdit(self)
        self.ComboIface = QComboBox(self)
        self.connect(self.ComboIface, SIGNAL("currentIndexChanged(QString)"), self.discoveryIface)

        self.layoutform.addRow('Target:',self.txt_target)
        self.layoutform.addRow('Gateway:',self.txt_gateway)
        self.layoutform.addRow('Redirect IP:',self.txt_redirect)
        self.layoutform.addRow('IP Scan Range:',self.ip_range)
        self.layoutform.addRow('Interface:',self.ComboIface)

        self.GroupOptions = QGroupBox(self)
        self.GroupOptions.setTitle('Options')
        self.GroupOptions.setLayout(self.layoutform)

        self.myListDns = QListWidget(self)
        self.myDNsoutput = QListWidget(self)
        self.myListDns.setSizePolicy(QSizePolicy.Maximum, QSizePolicy.Maximum)
        self.myDNsoutput.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        self.GroupHosts  = QGroupBox(self)
        self.checkAllhost = QCheckBox('Redirect traffic from all domains ')
        self.checkAllhost.clicked.connect(self.set_redirect_all_domains)
        self.GroupHosts.setTitle('DNS::spoof')
        self.GroupHosts.setLayout(self.layoutHost)
        self.layoutHost.addRow(self.myListDns,self.myDNsoutput)
        self.layoutHost.addRow(self.checkAllhost)

        self.GroupOuput  = QGroupBox(self)
        self.GroupOuput.setTitle('DNS::Requests')
        self.GroupOuput.setLayout(self.layoutDNSReq)
        self.layoutDNSReq.addRow(self.myDNsoutput)

        self.SettingsGUI()


        self.myListDns.setContextMenuPolicy(Qt.CustomContextMenu)
        self.myListDns.connect(self.myListDns,
        SIGNAL('customContextMenuRequested(QPoint)' ),
        self.listItemclicked)

        self.txt_status_scan = QLabel('')
        self.txt_statusarp = QLabel('')
        self.txt_status_phishing = QLabel('')

        self.StatusMonitor(False,'stas_scan')
        self.StatusMonitor(False,'dns_spoof')
        self.StatusMonitor(False,'stas_phishing')
        scan_range = self.configure.Settings.get_setting('settings','scanner_rangeIP')
        self.ip_range.setText(scan_range)

        # button conf
        self.btn_start_scanner = QPushButton('Start Scan  ')
        self.btn_stop_scanner = QPushButton('Stop Scan   ')
        self.btn_Attack_Posion = QPushButton('Start Attack')
        self.btn_Stop_Posion = QPushButton('Stop Attack')
        self.btn_server = QPushButton('Phishing M.')
        self.btn_windows_update = QPushButton('Fake Update')
        self.btn_server.setIcon(QIcon('icons/page.png'))

        self.layoutform.addRow(self.btn_start_scanner,self.btn_stop_scanner)
        self.layoutform.addRow(self.btn_server,self.btn_windows_update)


        # connet buttons
        self.btn_start_scanner.clicked.connect(self.Start_scan)
        self.btn_stop_scanner.clicked.connect(self.Stop_scan)
        self.btn_Attack_Posion.clicked.connect(self.Start_Attack)
        self.btn_Stop_Posion.clicked.connect(self.kill_attack)
        self.btn_server.clicked.connect(self.show_template_dialog)
        self.btn_windows_update.clicked.connect(self.show_frm_fake)

        #icons
        self.btn_start_scanner.setIcon(QIcon('icons/network.png'))
        self.btn_Attack_Posion.setIcon(QIcon('icons/start.png'))
        self.btn_Stop_Posion.setIcon(QIcon('icons/Stop.png'))
        self.btn_stop_scanner.setIcon(QIcon('icons/network_off.png'))
        self.btn_windows_update.setIcon(QIcon('icons/winUp.png'))

        self.btn_stop_scanner.setEnabled(False)
        self.btn_Stop_Posion.setEnabled(False)

        self.statusBar.addWidget(QLabel('DnsSpoof:'))
        self.statusBar.addWidget(self.txt_statusarp,10)
        self.statusBar.addWidget(QLabel('Phishing:'))
        self.statusBar.addWidget(self.txt_status_phishing,10)
        self.statusBar.addWidget(QLabel('Scan:'))
        self.statusBar.addWidget(self.txt_status_scan,10)

        #btn start and stop
        self.grid2 = QGridLayout()
        self.grid2.addWidget(self.btn_Attack_Posion,1,0)
        self.grid2.addWidget(self.btn_Stop_Posion,1,5)

        self.form0  = QHBoxLayout()
        self.form0.addWidget(self.tables)
        self.form0.addWidget(self.GroupOptions)

        self.layout = QHBoxLayout()
        self.layout.addWidget(self.GroupHosts)
        self.layout.addWidget(self.GroupOuput)
        self.form.addRow(self.grid2)

        self.Main.addLayout(self.form0)
        self.Main.addLayout(self.layout)
        self.Main.addLayout(self.form)
        self.Main.addWidget(self.statusBar)
        self.setLayout(self.Main)

    def set_redirect_all_domains(self):
        if self.checkAllhost.isChecked():
            self.myListDns.setEnabled(False)
            return self.myListDns.clear()
        self.myListDns.setEnabled(True)

    def SettingsGUI(self):
        ifaces = self.interfaces
        for i,j in enumerate(ifaces['all']):
            if ifaces['all'][i] != '':
                self.ComboIface.addItem(ifaces['all'][i])
        if ifaces['gateway'] != None:
            self.txt_gateway.setText(ifaces['gateway'])
            self.txt_redirect.setText(ifaces['IPaddress'])
        item = QListWidgetItem()
        item.setIcon(QIcon('icons/dnsspoof.png'))
        item.setText('example.com')
        item.setSizeHint(QSize(30,30))
        self.myListDns.addItem(item)
        if self.configure.Settings.get_setting('accesspoint','statusAP',format=bool):
            self.ComboIface.setCurrentIndex(ifaces['all'].index(self.configure.Settings.get_setting('accesspoint',
            'interfaceAP')))
        else:
            self.myDNsoutput.setEnabled(False)

    def listItemclicked(self,pos):
        item = self.myListDns.selectedItems()
        self.listMenu= QMenu()
        menu = QMenu()
        additem = menu.addAction('Add Host')
        removeitem = menu.addAction('Remove Host')
        clearitem = menu.addAction('Clear all')
        action = menu.exec_(self.myListDns.viewport().mapToGlobal(pos))
        if action == removeitem:
            if item != []:
                self.myListDns.takeItem(self.myListDns.currentRow())
        elif action == additem:
            text, resp = QInputDialog.getText(self, 'Add Host',
            'Enter the Host to spoof: (ex.: example2.com)')
            if resp:
                try:
                    itemsexits = []
                    for index in xrange(self.myListDns.count()):
                        itemsexits.append(str(self.myListDns.item(index).text()))
                    for i in itemsexits:
                        if search(str(text),i):
                            QMessageBox.information(self,'DNS Resolver','This Host already exists on the List')
                            return
                    item = QListWidgetItem()
                    item.setIcon(QIcon('icons/dnsspoof.png'))
                    item.setText(text)
                    item.setSizeHint(QSize(30,30))
                    self.myListDns.addItem(item)
                except gaierror,e:
                    QMessageBox.information(self,'error',str(e))
                    return
        elif action == clearitem:
            self.myListDns.clear()

    @pyqtSlot(QModelIndex)
    def discoveryIface(self,iface):
        if self.configure.Settings.get_setting('accesspoint','interfaceAP') == str(iface):
            if self.configure.Settings.get_setting('accesspoint','statusAP',format=bool):
                self.txt_gateway.setText(self.configure.Settings.get_setting('dhcp','router'))
                self.txt_target.setEnabled(False)
        self.txt_redirect.setText(Refactor.get_Ipaddr(str(iface)))


    def thread_scan_reveice(self,info_ip):
        self.StatusMonitor(False,'stas_scan')
        self.tables.setVisible(True)
        data = info_ip.split('|')
        Headers = []
        self.data['IPaddress'].append(data[0])
        self.data['MacAddress'].append(data[1])
        self.data['Hostname'].append(data[2])
        for n, key in enumerate(reversed(self.data.keys())):
            Headers.append(key)
            for m, item in enumerate(self.data[key]):
                item = QTableWidgetItem(item)
                item.setTextAlignment(Qt.AlignVCenter | Qt.AlignCenter)
                self.tables.setItem(m, n, item)
        Headers = []
        for key in reversed(self.data.keys()):
            Headers.append(key)
        self.tables.setHorizontalHeaderLabels(Headers)


    def show_frm_fake(self):
        self.n = frm_update_attack()
        self.n.setGeometry(QRect(100, 100, 300, 300))
        self.n.show()

    def emit_template(self,log):
        if log == 'started':
            self.StatusMonitor(True,'stas_phishing')

    def show_template_dialog(self):
        self.connect(self.Ftemplates,SIGNAL('Activated ( QString ) '), self.emit_template)
        self.Ftemplates.txt_redirect.setText(self.txt_redirect.text())
        self.Ftemplates.show()

    def kill_attack(self):
        if hasattr(self, 'Ftemplates'):
            self.Ftemplates.killThread()
        if hasattr(self,'ThreadScanner'):
            self.ThreadScanner.terminate()
        for i in self.ThreadDirc['dns_spoof']:i.stop()
        for i in threadloading['arps']:i.stop()
        threadloading['template'] = []
        threadloading['arps'] = []
        self.ThreadDirc['dns_spoof'] = []
        self.StatusMonitor(False,'dns_spoof')
        self.StatusMonitor(False,'stas_phishing')
        self.btn_Attack_Posion.setEnabled(True)
        self.btn_Stop_Posion.setEnabled(False)
        self.myDNsoutput.clear()

    @pyqtSlot(QModelIndex)
    def check_options(self,index):
        if self.check_face.isChecked():
            self.check_route.setChecked(False)
            self.check_gmail.setChecked(False)

        elif self.check_gmail.isChecked():
            self.check_face.setChecked(False)
            self.check_route.setChecked(False)
        else:
            self.check_face.setChecked(False)
            self.check_gmail.setChecked(False)

    def StopArpAttack(self,data):
        if data == 'finished':
            self.StatusMonitor(False,'dns_spoof')

    def Start_Attack(self):
        self.targets,self.domains = {},[]
        if self.myListDns.count() != 0:
            for index in xrange(self.myListDns.count()):
                self.domains.append(str(self.myListDns.item(index).text()))
            for i in self.domains: self.targets[i] = ''
        self.myDNsoutput.clear()
        if not self.configure.Settings.get_setting('accesspoint','statusAP',format=bool):
            if (len(self.txt_target.text()) and  len(self.txt_gateway.text())) == 0:
                return QMessageBox.warning(self, 'DNS Spoofer', 'You need to set the input correctly')
            if (len(self.txt_target.text()) and len(self.txt_gateway.text())) and len(self.txt_redirect.text()) != 0:
                Refactor.set_ip_forward(1)

                arp_gateway = ThARP_posion(str(self.txt_target.text()),str(self.txt_gateway.text()),
                get_if_hwaddr(str(self.ComboIface.currentText())))
                arp_gateway.setObjectName('Arp Posion:: [gateway]')
                threadloading['arps'].append(arp_gateway)
                arp_gateway.start()

                arp_target = ThARP_posion(str(self.txt_gateway.text()),str(self.txt_target.text()),
                get_if_hwaddr(str(self.ComboIface.currentText())))
                arp_target.setObjectName('Arp Posion:: [target]')
                threadloading['arps'].append(arp_target)
                arp_target.start()

                self.thr = ThSpoofAttack(self.targets,str(self.ComboIface.currentText()),
                'udp port 53',True,str(self.txt_redirect.text()))
        else:
            self.thr = ThreadDNSspoofNF(self.targets,str(self.ComboIface.currentText()),
            str(self.txt_redirect.text()),APmode=True)
            self.thr.DnsReq.connect(self.get_outputDNSspoof)
        self.connect(self.thr,SIGNAL('Activated ( QString ) '), self.StopArpAttack)
        self.thr.setObjectName('Dns Spoof')
        self.ThreadDirc['dns_spoof'].append(self.thr)
        self.StatusMonitor(True,'dns_spoof')
        self.btn_Attack_Posion.setEnabled(False)
        self.btn_Stop_Posion.setEnabled(True)
        self.thr.start()

    def Start_scan(self):
        Headers = []
        self.tables.clear()
        self.data = {'IPaddress':[], 'Hostname':[], 'MacAddress':[]}
        if self.txt_gateway.text() != '':
            self.btn_start_scanner.setEnabled(False)
            self.btn_stop_scanner.setEnabled(True)
            self.thread_ScanIP = ThreadFastScanIP(str(self.txt_gateway.text()),self.ip_range.text())
            self.thread_ScanIP.sendDictResultscan.connect(self.get_result_scanner_ip)
            self.StatusMonitor(True,'stas_scan')
            self.thread_ScanIP.start()
            for key in reversed(self.data.keys()):
                Headers.append(key)
            return self.tables.setHorizontalHeaderLabels(Headers)
        return QMessageBox.information(self,'Gateway','Gateway not found.')

    def get_outputDNSspoof(self,data):
        self.myDNsoutput.addItem(data)
        self.myDNsoutput.scrollToBottom()

    def get_result_scanner_ip(self,data):
        Headers = []
        for items in data.values():
            dataIP = items.split('|')
            self.data['IPaddress'].append(dataIP[0])
            self.data['MacAddress'].append(dataIP[1])
            self.data['Hostname'].append('<unknown>')
            for n, key in enumerate(reversed(self.data.keys())):
                Headers.append(key)
                for m, item in enumerate(self.data[key]):
                    item = QTableWidgetItem(item)
                    item.setTextAlignment(Qt.AlignVCenter | Qt.AlignCenter)
                    self.tables.setItem(m, n, item)
        Headers = []
        for key in reversed(self.data.keys()):
            Headers.append(key)
        self.tables.setHorizontalHeaderLabels(Headers)
        self.StatusMonitor(False,'stas_scan')
        self.Stop_scan()
        self.thread_ScanIP.manager.shutdown()
        self.btn_start_scanner.setEnabled(True)
        self.btn_stop_scanner.setEnabled(False)

    def Stop_scan(self):
        self.thread_ScanIP.stop()
        self.StatusMonitor(False,'stas_scan')
        Headers = []
        for key in reversed(self.data.keys()):
            Headers.append(key)
        self.tables.setHorizontalHeaderLabels(Headers)
        self.tables.setVisible(True)

    def StatusMonitor(self,bool,wid):
        if bool and wid == 'stas_scan':
            self.txt_status_scan.setText('[ ON ]')
            self.txt_status_scan.setStyleSheet('QLabel {  color : green; }')
        elif not bool and wid == 'stas_scan':
            self.txt_status_scan.setText('[ OFF ]')
            self.txt_status_scan.setStyleSheet('QLabel {  color : red; }')
        elif bool and wid == 'dns_spoof':
            self.txt_statusarp.setText('[ ON ]')
            self.txt_statusarp.setStyleSheet('QLabel {  color : green; }')
        elif not bool and wid == 'dns_spoof':
            self.txt_statusarp.setText('[ OFF ]')
            self.txt_statusarp.setStyleSheet('QLabel {  color : red; }')
        elif bool and wid == 'stas_phishing':
            self.txt_status_phishing.setText('[ ON ]')
            self.txt_status_phishing.setStyleSheet('QLabel {  color : green; }')
        elif not bool and wid == 'stas_phishing':
            self.txt_status_phishing.setText('[ OFF ]')
            self.txt_status_phishing.setStyleSheet('QLabel {  color : red; }')

    @pyqtSlot(QModelIndex)
    def list_clicked_scan(self, index):
        item = self.tables.selectedItems()
        if item != []:
            self.txt_target.setText(item[0].text())
        else:
            self.txt_target.clear()

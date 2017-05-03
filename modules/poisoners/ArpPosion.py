import threading
from os import chdir,getcwd, devnull
from multiprocessing import Process,Manager
from modules.spreads.UpdateFake import frm_update_attack
from core.packets.network import ThARP_posion,ThSpoofAttack
from core.loaders.models.PackagesUI import *
from scapy.all import get_if_hwaddr
threadloading = {'template':[],'posion':[]}

"""
Description:
    This program is a module for wifi-pumpkin.py file which includes functionality
    for GUI Arp Posion attack.

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

class frm_Arp_Poison(PumpkinModule):

    def __init__(self,PhishingManager ,parent=None):
        super(frm_Arp_Poison, self).__init__(parent)
        self.setWindowTitle('ARP Poison Attack')
        self.Main           = QVBoxLayout()
        self.owd            = getcwd()
        self.Ftemplates     = PhishingManager
        self.loadtheme(self.configure.XmlThemeSelected())
        self.data = {'IPaddress':[], 'Hostname':[], 'MacAddress':[]}
        self.ThreadDirc = {'Arp_posion':[]}
        global threadloading
        self.GUI()

    def closeEvent(self, event):
        reply = QMessageBox.question(self, 'About Exit',
        'Are you sure that you want to close ARP Posion?', QMessageBox.Yes |
            QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            event.accept()
            if (len(self.ThreadDirc['Arp_posion']) != 0):
                try:
                    for i in self.ThreadDirc['Arp_posion']:
                        i.stop(),i.join()
                except:pass
                if not self.configure.Settings.get_setting('accesspoint','statusAP'):
                    Refactor.set_ip_forward(0)
            self.deleteLater()
            return
        event.ignore()

    def GUI(self):
        self.form =QFormLayout()
        self.tables = QTableWidget(5,3)
        self.tables.setRowCount(100)
        self.tables.setFixedHeight(200)
        self.tables.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.tables.horizontalHeader().setStretchLastSection(True)
        self.tables.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.tables.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.tables.clicked.connect(self.list_clicked_scan)
        self.tables.resizeColumnsToContents()
        self.tables.resizeRowsToContents()
        self.tables.horizontalHeader().resizeSection(1,120)
        self.tables.horizontalHeader().resizeSection(0,135)
        self.tables.horizontalHeader().resizeSection(2,150)
        self.tables.verticalHeader().setVisible(False)
        self.tables.setSortingEnabled(True)
        Headers = []
        for key in reversed(self.data.keys()):
            Headers.append(key)
        self.tables.setHorizontalHeaderLabels(Headers)
        self.tables.verticalHeader().setDefaultSectionSize(23)

        self.txt_target = QLineEdit(self)
        self.txt_gateway = QLineEdit(self)
        self.txt_redirect = QLineEdit(self)
        self.txt_mac = QLineEdit(self)
        self.ip_range = QLineEdit(self)
        self.txt_status_scan = QLabel('')
        self.txt_statusarp = QLabel('')
        self.txt_status_phishing = QLabel('')

        self.btn_start_scanner = QPushButton('Scan')
        self.btn_stop_scanner = QPushButton('Stop')
        self.btn_Attack_Posion = QPushButton('Start Attack')
        self.btn_Stop_Posion = QPushButton('Stop Attack')
        self.btn_server = QPushButton('Phishing M.')
        self.btn_windows_update = QPushButton('Fake Update')
        self.btn_server.setFixedHeight(22)
        self.btn_stop_scanner.setFixedWidth(100)
        self.btn_start_scanner.setFixedWidth(100)
        self.btn_start_scanner.setFixedHeight(22)
        self.btn_stop_scanner.setFixedHeight(22)
        self.btn_windows_update.setFixedHeight(22)
        self.btn_stop_scanner.setEnabled(False)

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
        self.btn_server.setIcon(QIcon('icons/page.png'))
        self.btn_windows_update.setIcon(QIcon('icons/winUp.png'))

        self.grid0 = QGridLayout()
        self.grid0.minimumSize()
        self.grid0.addWidget(QLabel('ArpPosion:'),0,2)
        self.grid0.addWidget(QLabel('Phishing:'),0,4)
        self.grid0.addWidget(QLabel('Scanner:'),0,0)
        self.grid0.addWidget(self.txt_status_scan,0,1)
        self.grid0.addWidget(self.txt_statusarp,0,3)
        self.grid0.addWidget(self.txt_status_phishing,0,5)


        # grid options
        self.grid1 = QGridLayout()
        self.grid1.addWidget(self.btn_start_scanner,0,0)
        self.grid1.addWidget(self.btn_stop_scanner,0,1)
        self.grid1.addWidget(self.btn_server,0,2)
        self.grid1.addWidget(self.btn_windows_update, 0,3)

        #btn
        self.grid2 = QGridLayout()
        self.grid2.addWidget(self.btn_Attack_Posion,1,0)
        self.grid2.addWidget(self.btn_Stop_Posion,1,5)

        self.ComboIface = QComboBox(self)
        self.ConfigureEdits()

        self.form0  = QGridLayout()
        self.form0.addWidget(self.tables,0,0)

        self.form.addRow(self.form0)
        self.form.addRow(self.grid1)
        self.form.addRow('Target:', self.txt_target)
        self.form.addRow('Gateway:', self.txt_gateway)
        self.form.addRow('MAC address:', self.txt_mac)
        self.form.addRow('Redirect IP:', self.txt_redirect)
        self.form.addRow('IP Scan Range:',self.ip_range)
        self.form.addRow('Network Adapter:',self.ComboIface)
        self.form.addRow(self.grid0)
        self.form.addRow(self.grid2)

        self.Main.addLayout(self.form)
        self.setLayout(self.Main)

    def ConfigureEdits(self):
        x  = self.interfaces
        self.StatusMonitor(False,'stas_scan')
        self.StatusMonitor(False,'stas_arp')
        self.StatusMonitor(False,'stas_phishing')
        scan_range = self.configure.Settings.get_setting('settings','scanner_rangeIP')
        self.ip_range.setText(scan_range)
        if x['gateway'] != None:
            self.txt_gateway.setText(x['gateway'])
            self.txt_redirect.setText(x['IPaddress'])
            self.txt_mac.setText(Refactor.getHwAddr(x['activated'][0]))
        self.connect(self.ComboIface, SIGNAL("currentIndexChanged(QString)"), self.discoveryIface)
        n = self.interfaces['all']
        for i,j in enumerate(n):
            if n[i] != '':
                self.ComboIface.addItem(n[i])
        if self.configure.Settings.get_setting('accesspoint','statusAP',format=bool):
            self.ComboIface.setCurrentIndex(x['all'].index(self.configure.Settings.get_setting('accesspoint',
            'interfaceAP')))

    def thread_scan_reveice(self,info_ip):
        self.StatusMonitor(False,'stas_scan')
        self.movie_screen.setDisabled(False)
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

    @pyqtSlot(QModelIndex)
    def discoveryIface(self,iface):
        if self.configure.Settings.get_setting('accesspoint','interfaceAP') == str(iface):
            if self.configure.Settings.get_setting('accesspoint','statusAP',format=bool):
                self.txt_gateway.setText(self.configure.Settings.get_setting('dhcp','router'))
        self.txt_mac.setText(Refactor.getHwAddr(str(iface)))
        self.txt_redirect.setText(Refactor.get_Ipaddr(str(iface)))

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
        for i in self.ThreadDirc['Arp_posion']:i.stop()
        threadloading['template'] = []
        threadloading['arps'] = []
        self.ThreadDirc['Arp_posion'] = []
        self.StatusMonitor(False,'stas_arp')
        self.StatusMonitor(False,'stas_phishing')
        chdir(self.owd)

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
        self.StatusMonitor(False,'stas_arp')
    def Start_Attack(self):
        if  (len(self.txt_target.text()) and len(self.txt_mac.text()) and len(self.txt_gateway.text())) == 0:
            QMessageBox.information(self, 'ARP Poisoner', 'You need set the input correctly')
        else:
            chdir(self.owd)
            if (len(self.txt_target.text()) and len(self.txt_gateway.text())) and len(self.txt_mac.text()) != 0:
                if len(self.txt_redirect.text()) != 0:
                    self.StatusMonitor(True,'stas_arp')
                    Refactor.set_ip_forward(1)
                    arp_gateway = ThARP_posion(str(self.txt_gateway.text()),str(self.txt_target.text()),
                    get_if_hwaddr(str(self.ComboIface.currentText())))
                    arp_gateway.setObjectName('Arp Poison:: [gateway]')
                    self.ThreadDirc['Arp_posion'].append(arp_gateway)
                    arp_gateway.start()

                    arp_target = ThARP_posion(str(self.txt_target.text()),str(self.txt_gateway.text()),
                    str(self.txt_mac.text()))
                    self.connect(arp_target,SIGNAL('Activated ( QString ) '), self.StopArpAttack)
                    arp_target.setObjectName('Arp::Poison => [target]')
                    self.ThreadDirc['Arp_posion'].append(arp_target)
                    arp_target.start()

                    redirectPackets = ThSpoofAttack('',
                    str(self.ComboIface.currentText()),'udp port 53',True,str(self.txt_redirect.text()))
                    self.connect(redirectPackets,SIGNAL('Activated ( QString ) '), self.StopArpAttack)
                    redirectPackets.setObjectName('Packets Spoof')
                    self.ThreadDirc['Arp_posion'].append(redirectPackets)
                    redirectPackets.start()
                    return
                QMessageBox.information(self,'Redirect IP','Redirect IP not found')

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
        elif bool and wid == 'stas_arp':
            self.txt_statusarp.setText('[ ON ]')
            self.txt_statusarp.setStyleSheet('QLabel {  color : green; }')
        elif not bool and wid == 'stas_arp':
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

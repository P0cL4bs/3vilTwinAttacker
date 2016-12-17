from core.loaders.models.PackagesUI import *
from os import geteuid
import subprocess
import random


"""
Description:
    This program is a module for wifi-pumpkin.py file which includes functionality
    for change mac system.

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

class frm_mac_generator(PumpkinModule):
    def __init__(self, parent=None):
        super(frm_mac_generator, self).__init__(parent)
        self.setWindowIcon(QIcon('icons/icon.ico'))
        self.setWindowTitle("MAC Address Generator")
        self.Main = QVBoxLayout()
        self.prefix = [ 0x00, 0xCB, 0x01,0x03 ,\
                        0x84,0x78,0xAC, 0x88,0xD3,\
                        0x7B, 0x8C,0x7C,0xB5, 0x90,0x99,0x16, \
                        0x9C, 0x6A ,0xBE , 0x55, 0x12, 0x6C , 0xD2,\
                        0x8b, 0xDA, 0xF1, 0x9c , 0x20 , 0x3A, 0x4A,\
                        0x2F, 0x31, 0x32, 0x1D, 0x5F, 0x70, 0x5A,\
                        0x5B, 0x5C, 0x63, 0x4F, 0x3F, 0x5F, 0x9E]

        self.loadtheme(self.configure.XmlThemeSelected())
        self.MacGUI()

    @pyqtSlot(QModelIndex)
    def combo_clicked(self, device):
        if device == '' or device == 'lo':
            self.i_mac.setText('Not Found')
            return
        self.i_mac.setText(Refactor.get_interface_mac(device))

    def action_btn_random(self):
        mac = Refactor.randomMacAddress([random.choice(self.prefix) ,
        random.choice(self.prefix) , random.choice(self.prefix)])
        self.i_mac.setText(mac)

    def setMAC(self,device,mac):
        subprocess.check_call(["ifconfig",device, "down"])
        subprocess.call(["ifconfig",device, "hw", "ether",mac])
        subprocess.check_call(["ifconfig",device, "up"])

    def change_macaddress(self):
        if not geteuid() == 0:
            QMessageBox.information(self, "Permission Denied",
            'Tool must be run as root try again.')
        else:
            self.setMAC(str(self.combo_card.currentText()), str(self.i_mac.text()))
            self.deleteLater()

    def MacGUI(self):
        self.form_mac = QFormLayout()
        self.i_mac = QLineEdit(self)
        self.combo_card = QComboBox(self)
        self.btn_random = QPushButton("Random MAC")
        self.btn_random.setIcon(QIcon("icons/refresh.png"))
        self.btn_save = QPushButton("Save")
        self.btn_save.setIcon(QIcon("icons/Save.png"))
        self.btn_save.clicked.connect(self.change_macaddress)
        self.btn_random.clicked.connect(self.action_btn_random)
        self.cards = Refactor.get_interfaces()['all']
        self.combo_card.addItems(self.cards)
        self.connect(self.combo_card, SIGNAL('activated(QString)'), self.combo_clicked)
        self.form_mac.addRow(self.combo_card,self.i_mac)
        self.form_mac.addRow("MAC Random: ", self.btn_random)
        self.form_mac.addRow(self.btn_save)
        self.Main.addLayout(self.form_mac)
        self.setLayout(self.Main)


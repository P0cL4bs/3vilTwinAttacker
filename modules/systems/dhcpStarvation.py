from core.packets.network import ThreadAttackStar
from core.loaders.models.PackagesUI import *
"""
Description:
    This program is a module for wifi-pumpkin.py file which includes functionality
    for dhcp starvation attack.

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

class frm_dhcp_Attack(PumpkinModule):
    def __init__(self, parent=None):
        super(frm_dhcp_Attack, self).__init__(parent)
        self.loadtheme(self.configure.XmlThemeSelected())
        self.setWindowTitle("Dhcp Starvation Attack")
        self.Main       = QVBoxLayout()
        self.control    = None
        self.GUI()

    def GUI(self):
        self.form       = QFormLayout()
        self.list_log   = QListWidget()
        self.check      = QLabel("")
        self.btn_Start_attack   = QPushButton("Start Attack",self)
        self.btn_Stop_attack    = QPushButton("Stop Attack",self)
        self.check.setText("[ OFF ]")
        self.check.setStyleSheet("QLabel {  color : red; }")

        self.btn_Start_attack.clicked.connect(self.D_attack)
        self.btn_Stop_attack.clicked.connect(self.kill_thread)

        self.btn_Start_attack.setIcon(QIcon("icons/start.png"))
        self.btn_Stop_attack.setIcon(QIcon("icons/Stop.png"))

        self.form.addRow(self.list_log)
        self.form.addRow("Status Attack:",self.check)
        self.form.addRow(self.btn_Start_attack, self.btn_Stop_attack)
        self.Main.addLayout(self.form)
        self.setLayout(self.Main)


    def getloggerAttack(self,log):
        self.list_log.addItem(log)

    def D_attack(self):
        interface = Refactor.get_interfaces()['activated']
        if interface != None:
            self.check.setText("[ ON ]")
            self.check.setStyleSheet("QLabel {  color : green; }")
            self.threadstar = ThreadAttackStar(interface)
            self.connect(self.threadstar,SIGNAL("Activated ( QString )"),self.getloggerAttack)
            self.threadstar.setObjectName("DHCP Starvation")
            self.threadstar.start()
            return
        QMessageBox.information(self, 'Interface Not found', 'None detected network interface try again.')

    def attack_OFF(self):
        self.check.setStyleSheet("QLabel {  color : red; }")

    def kill_thread(self):
        self.threadstar.stop()
        self.attack_OFF()
        self.list_log.clear()
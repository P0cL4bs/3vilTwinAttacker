from os import getcwd,path
from core.loaders.models.PackagesUI import *


class frm_NetCredsLogger(PumpkinModule):
    def __init__(self, parent = None):
        super(frm_NetCredsLogger, self).__init__(parent)
        self.setGeometry(0, 0, 550, 400)
        self.Main       = QVBoxLayout()
        self.owd        = getcwd()
        self.thread     = []
        self.loadtheme(self.configure.XmlThemeSelected())
        self.center()
        self.Qui()

    def closeEvent(self, event):
        self.exit_function()

    def Start_Get_creds(self):
        self.listURL.clear()
        self.list_creds.clear()
        self.btn_getdata.setEnabled(False)
        self.btn_exit.setEnabled(True)
        # Thread Capture logs
        creds = ThreadPopen(['tail','-f','logs/AccessPoint/credentials.log'])
        self.connect(creds,SIGNAL('Activated ( QString ) '), self.loggercreds)
        creds.setObjectName('Netcreds::Credentials')
        urls = ThreadPopen(['tail','-f','logs/AccessPoint/urls.log'])
        self.connect(urls,SIGNAL('Activated ( QString ) '), self.loggerurls)
        urls.setObjectName('Netcreds::Urls')
        if path.exists('logs/AccessPoint/credentials.log'):
            self.thread.append(creds)
            creds.start()
        if path.exists('logs/AccessPoint/urls.log'):
            self.thread.append(urls)
            urls.start()
        if not urls.isRunning():
            QMessageBox.warning(self,'NetCreds Logger','netcreds no logger found.')

    def loggercreds(self,data):
        self.list_creds.addItem(data)
        self.list_creds.scrollToBottom()
    def loggerurls(self,data):
        self.listURL.addItem(data)
        self.listURL.scrollToBottom()

    def exit_function(self):
        for i in self.thread:i.stop()
        self.deleteLater()
    def Qui(self):
        self.frm0 = QFormLayout()
        self.widget = QWidget()
        self.layout = QVBoxLayout(self.widget)

        self.listURL = QListWidget(self)
        self.list_creds = QListWidget(self)

        self.GroupBoxURL = QGroupBox()
        self.layoutGroupURL = QVBoxLayout()
        self.GroupBoxURL.setLayout(self.layoutGroupURL)
        self.GroupBoxURL.setTitle('Monitor::URLCapture')
        self.layoutGroupURL.addWidget(self.listURL)

        self.listURL.setAutoScroll(True)
        self.listURL.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        self.list_creds.setAutoScroll(True)
        self.list_creds.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)


        self.GroupBoxCreds = QGroupBox()
        self.layoutGroupCreds = QVBoxLayout()
        self.GroupBoxCreds.setLayout(self.layoutGroupCreds)
        self.GroupBoxCreds.setTitle('Monitor::Credentials')
        self.layoutGroupCreds.addWidget(self.list_creds)

        self.btn_getdata = QPushButton('Capture logs')
        self.btn_getdata.setIcon(QIcon('icons/start.png'))
        self.btn_getdata.clicked.connect(self.Start_Get_creds)
        self.btn_exit = QPushButton('Kill')
        self.btn_exit.setEnabled(False)
        self.btn_exit.setIcon(QIcon('icons/cancel.png'))
        self.btn_exit.clicked.connect(self.exit_function)

        self.layout.addWidget(self.GroupBoxURL)
        self.layout.addWidget(self.GroupBoxCreds)
        self.layout.addLayout(self.frm0)

        self.frm0.addRow(self.btn_getdata,self.btn_exit)
        self.Main.addWidget(self.widget)
        self.setLayout(self.Main)

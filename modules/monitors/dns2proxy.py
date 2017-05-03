from os import getcwd,path
from core.loaders.models.PackagesUI import *


class frm_dns2proxy(PumpkinModule):
    def __init__(self, parent = None):
        super(frm_dns2proxy, self).__init__(parent)
        self.setGeometry(0, 0, 400, 400)
        self.Main       = QVBoxLayout()
        self.owd        = getcwd()
        self.thread     = []
        self.loadtheme(self.configure.XmlThemeSelected())
        self.center()
        self.Qui()

    def closeEvent(self, event):
        self.exit_function()

    def Start_Get_creds(self):
        self.listDns.clear()
        self.btn_getdata.setEnabled(False)
        self.btn_exit.setEnabled(True)
        # Thread Capture logs
        if path.exists('logs/AccessPoint/dns2proxy.log'):
            dns = ThreadPopen(['tail','-f','logs/AccessPoint/dns2proxy.log'])
            self.connect(dns,SIGNAL('Activated ( QString ) '), self.loggerdns)
            dns.setObjectName('Dns2proxy::Capture')
            self.thread.append(dns)
            dns.start()
            return
        QMessageBox.warning(self,'Dns2proxy Logger','dns2proxy::capture no logger found')


    def loggerdns(self,data):
        self.listDns.addItem(data)
        self.listDns.scrollToBottom()

    def exit_function(self):
        for i in self.thread:i.stop()
        self.deleteLater()
    def Qui(self):
        self.frm0 = QFormLayout()
        self.widget = QWidget()
        self.layout = QVBoxLayout(self.widget)
        self.listDns = QListWidget(self)
        self.listDns.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.listDns.setAutoScroll(True)

        self.btn_getdata = QPushButton('Capture logs')
        self.btn_getdata.setIcon(QIcon('icons/start.png'))
        self.btn_getdata.clicked.connect(self.Start_Get_creds)
        self.btn_exit = QPushButton('Kill')
        self.btn_exit.setEnabled(False)
        self.btn_exit.setIcon(QIcon('icons/cancel.png'))
        self.btn_exit.clicked.connect(self.exit_function)

        self.layout.addWidget(self.listDns)
        self.layout.addLayout(self.frm0)

        self.frm0.addRow(self.btn_getdata,self.btn_exit)
        self.Main.addWidget(self.widget)
        self.setLayout(self.Main)

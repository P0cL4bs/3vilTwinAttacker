from configobj import ConfigObj,Section
from collections import OrderedDict
from core.loaders.models.PackagesUI import *

class BDFProxySettings(PumpkinModule):
    def __init__(self,parent=None):
        super(BDFProxySettings, self).__init__(parent)
        self.setWindowTitle('DBFProxy-ng Plugin Settings')
        self.setGeometry(0,0,480, 500)
        self.main       = QVBoxLayout()
        self.THeaders   = {'Config':[],'Value':[] }
        self.userConfig = ConfigObj(str(self.configure.Settings.get_setting('plugins','bdfproxy_config')))
        self.userConfig.interpolation = False
        self.loadtheme(self.configure.XmlThemeSelected())
        self.center()
        self.GUI()

    def addRowTableWidget(self, _key, _value):
        ''' add items into TableWidget '''
        Headers = []
        self.THeaders['Config'].append(_key)
        self.THeaders['Value'].append(_value)
        for n, key in enumerate(self.THeaders.keys()):
            Headers.append(key)
            for m, item in enumerate(self.THeaders[key]):
                item = QTableWidgetItem(item)
                item.setFlags(item.flags() | Qt.ItemIsEditable)
                self.TabSettings.setItem(m, n, item)
        self.TabSettings.resizeColumnToContents(0)

    def getAllRowTablesWidget(self):
        ''' dump all settings from table '''
        model = self.TabSettings.model()
        data,datafilter,self.key = [],OrderedDict(),None
        for row in range(model.rowCount()):
            data.append([])
            for column in range(model.columnCount()):
                index = model.index(row, column)
                data[row].append(str(model.data(index).toString()))
        datafilter['ESP'] = {}
        datafilter['LinuxIntelx86'] = {}
        datafilter['LinuxIntelx64'] = {}
        datafilter['WindowsIntelx86'] = {}
        datafilter['WindowsIntelx64'] = {}
        datafilter['MachoIntelx86'] = {}
        datafilter['MachoIntelx64'] = {}
        for count,item in enumerate(data):
            if count < 5:
                if item[0] != '' or item[1] != '':
                    datafilter['ESP'][item[0]] = item[1]
            else:
                if item[0] != '' or item[1] != '':
                    if item[1] in datafilter.keys():
                        self.key = item[1]
                    else:
                        datafilter[self.key][item[0]] = item[1]
        return datafilter

    def saveConfigObject(self):
        self.checkConfigKeysBDFProxy(saveObjct=True)
        QMessageBox.information(self,'BDFProxy-ng settings','All settings in {} have been saved '
        'with success.'.format(str(self.configure.Settings.get_setting('plugins','bdfproxy_config'))))
        self.close()

    def checkConfigKeysBDFProxy(self,saveObjct=False):
        ''' save all change into file.conf '''
        if saveObjct: changedData = self.getAllRowTablesWidget()
        for target in self.userConfig['targets'].keys():
            if target == 'ALL':
                for item in self.userConfig['targets']['ALL']:
                    if type(self.userConfig['targets']['ALL'][item]) == str:
                        if saveObjct:
                            self.userConfig['targets']['ALL'][item] = changedData['ESP'][item]
                        else:
                            self.addRowTableWidget(item,self.userConfig['targets']['ALL'][item])
                    elif type(self.userConfig['targets']['ALL'][item]) == Section:
                        if saveObjct:
                            self.userConfig['targets']['ALL'][item] = changedData[item]
                        else:
                            self.addRowTableWidget('-'*35+'>',item)
                            for key in self.userConfig['targets']['ALL'][item]:
                                self.addRowTableWidget(key,self.userConfig['targets']['ALL'][item][key])
        if saveObjct: self.userConfig.write()

    def GUI(self):
        self.TabSettings = QTableWidget(50,2)
        self.btnSave     = QPushButton('Save Settings')
        self.GroupBox    = QGroupBox(self)
        self.widget      = QWidget()
        self.layoutGroup = QVBoxLayout(self.widget)
        self.GroupBox.setLayout(self.layoutGroup)
        self.GroupBox.setTitle('Options')
        self.checkConfigKeysBDFProxy()
        self.btnSave.clicked.connect(self.saveConfigObject)
        self.TabSettings.resizeRowsToContents()
        self.TabSettings.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Preferred)
        self.TabSettings.horizontalHeader().setStretchLastSection(True)
        self.TabSettings.setSelectionBehavior(QAbstractItemView.SelectRows)
        #self.TabSettings.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.TabSettings.verticalHeader().setVisible(False)
        self.TabSettings.setHorizontalHeaderLabels(self.THeaders.keys())
        self.TabSettings.verticalHeader().setDefaultSectionSize(23)

        self.layout = QVBoxLayout(self.widget)
        self.layoutGroup.addWidget(self.TabSettings)
        self.layout.addWidget(self.GroupBox)
        self.layout.addWidget(self.btnSave)
        self.main.addWidget(self.widget)
        self.setLayout(self.main)


class ResponderSettings(PumpkinModule):
    def __init__(self,parent=None):
        super(ResponderSettings, self).__init__(parent)
        self.setWindowTitle('Responder Plugin Settings')
        self.setGeometry(0,0,480, 500)
        self.main       = QVBoxLayout()
        self.THeaders   = {'Config':[],'Value':[] }
        self.userConfig = ConfigObj(str(self.configure.Settings.get_setting('plugins','responder_config')))
        self.userConfig.interpolation = False
        self.loadtheme(self.configure.XmlThemeSelected())
        self.center()
        self.GUI()

    def addRowTableWidget(self, _key, _value):
        ''' add items into TableWidget '''
        Headers = []
        self.THeaders['Config'].append(_key)
        self.THeaders['Value'].append(_value)
        for n, key in enumerate(self.THeaders.keys()):
            Headers.append(key)
            for m, item in enumerate(self.THeaders[key]):
                item = QTableWidgetItem(item)
                item.setFlags(item.flags() | Qt.ItemIsEditable)
                self.TabSettings.setItem(m, n, item)
        self.TabSettings.resizeColumnToContents(0)

    def getAllRowTablesWidget(self):
        ''' dump all setting into table for list'''
        model = self.TabSettings.model()
        data,datafilter = [],[]
        for row in range(model.rowCount()):
            data.append([])
            for column in range(model.columnCount()):
                index = model.index(row, column)
                data[row].append(str(model.data(index).toString()))
        for key,item in data:
            datafilter.append(key)
            datafilter.append(item)
        return datafilter

    def addAllconfigKeys(self):
        ''' get all settings and add into table'''
        for key in self.userConfig.keys():
            for items in self.userConfig[key].items():
                self.addRowTableWidget(items[0],items[1])

    def checkConfigKeysResponder(self,saveObjct=False,count=False):
        ''' check number row and save settings '''
        if count:
            lenconfig = 0
            for key in self.userConfig.keys():
                for items in self.userConfig[key].items(): lenconfig += 1
            return lenconfig
        if saveObjct:
            settings = self.getAllRowTablesWidget()
            for key in self.userConfig.keys():
                for items in self.userConfig[key].items():
                    self.userConfig[key][items[0]] = settings[settings.index(items[0])+1]
            self.userConfig.write()

    def saveConfigObject(self):
        self.checkConfigKeysResponder(saveObjct=True)
        QMessageBox.information(self,'Responder Settings','All settings in {} have been saved '
        'with success.'.format(str(self.configure.Settings.get_setting('plugins','responder_config'))))
        self.close()

    def GUI(self):
        self.TabSettings = QTableWidget(self.checkConfigKeysResponder(count=True),2)
        self.btnSave     = QPushButton('Save settings')
        self.GroupBox    = QGroupBox(self)
        self.widget      = QWidget()
        self.layoutGroup = QVBoxLayout(self.widget)
        self.GroupBox.setLayout(self.layoutGroup)
        self.GroupBox.setTitle('Options')
        self.addAllconfigKeys()
        self.btnSave.clicked.connect(self.saveConfigObject)
        self.TabSettings.resizeRowsToContents()
        self.TabSettings.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Preferred)
        self.TabSettings.horizontalHeader().setStretchLastSection(True)
        self.TabSettings.setSelectionBehavior(QAbstractItemView.SelectRows)
        #self.TabSettings.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.TabSettings.verticalHeader().setVisible(False)
        self.TabSettings.setHorizontalHeaderLabels(self.THeaders.keys())
        self.TabSettings.verticalHeader().setDefaultSectionSize(23)

        self.layout = QVBoxLayout(self.widget)
        self.layoutGroup.addWidget(self.TabSettings)
        self.layout.addWidget(self.GroupBox)
        self.layout.addWidget(self.btnSave)
        self.main.addWidget(self.widget)
        self.setLayout(self.main)

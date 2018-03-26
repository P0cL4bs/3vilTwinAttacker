load_plugins = True
try:
    from plugins.extension import *
except ImportError:
    load_plugins = False
from collections import OrderedDict
from PyQt4.QtGui import (
    QListWidget,QTableWidget,QSizePolicy,
    QAbstractItemView,QTableWidgetItem,QIcon,QListWidgetItem,
    QTreeView,QStandardItemModel,QStandardItem
)
from PyQt4.QtCore import (
    SIGNAL,QProcess,pyqtSlot,QObject,SLOT,Qt,QSize
)

"""
Description:
    This program is a core for wifi-pumpkin.py. file which includes functionality
    for Activity-Monitor tab.

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

class ThreadLogger(QObject):
    def __init__(self,logger_path=str):
        QObject.__init__(self)
        self.logger_path = logger_path

    @pyqtSlot()
    def readProcessOutput(self):
        try:
            self.emit(SIGNAL('Activated( QString )'),
            str(self.procLogger.readAllStandardOutput()).rstrip().split(' : ')[1])
        except Exception: pass

    def start(self):
        self.procLogger = QProcess(self)
        self.procLogger.setProcessChannelMode(QProcess.MergedChannels)
        QObject.connect(self.procLogger, SIGNAL('readyReadStandardOutput()'), self, SLOT('readProcessOutput()'))
        self.procLogger.start('tail',['-f',self.logger_path])

    def stop(self):
        if hasattr(self,'procLogger'):
            self.procLogger.terminate()
            self.procLogger.waitForFinished()
            self.procLogger.kill()

class dockAreaAPI(QListWidget):
    ''' general dock widgets for show logging of plugins '''
    def __init__(self, parent=None,info={}):
        super(dockAreaAPI, self).__init__(parent)
        self.logger = info
        self.startThread  = False
        self.processThread = None

    def RunThread(self):
        self.startThread = True

    def writeModeData(self,data):
        item = QListWidgetItem()
        item.setText(data)
        item.setSizeHint(QSize(27,27))
        item.setFlags(Qt.ItemIsEnabled | Qt.ItemIsEditable | Qt.ItemIsSelectable)
        self.insertItem(self.count()+1,item)
        self.scrollToBottom()

    def stopProcess(self):
        if self.processThread != None:
            self.processThread.stop()

class dockCredsMonitor(QTableWidget):
    ''' dock widget for get all credentials logger netcreds'''
    def __init__(self, parent=None,info={}):
        super(dockCredsMonitor, self).__init__(parent)
        self.logger = info
        self.startThread  = False
        self.processThread = None
        self.setColumnCount(4)
        self.resizeRowsToContents()
        self.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Preferred)
        self.horizontalHeader().setStretchLastSection(True)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.verticalHeader().setVisible(False)
        self.verticalHeader().setDefaultSectionSize(27)
        self.setSortingEnabled(True)
        self.THeaders  = OrderedDict([ ('Username',[]),('Password',[]),('Url',[]),('Source/Destination',[])])
        self.setHorizontalHeaderLabels(self.THeaders.keys())
        self.horizontalHeader().resizeSection(0,120)
        self.horizontalHeader().resizeSection(1,120)
        self.horizontalHeader().resizeSection(2,180)

    def writeModeData(self,data):
        ''' get data output and add on QtableWidgets '''
        self.THeaders['Username'].append(data['POSTCreds']['User'])
        self.THeaders['Password'].append(data['POSTCreds']['Pass'])
        self.THeaders['Url'].append(data['POSTCreds']['Url'])
        self.THeaders['Source/Destination'].append(data['POSTCreds']['Destination'])
        Headers = []
        self.setRowCount(len(self.THeaders['Username']))
        for n, key in enumerate(self.THeaders.keys()):
            Headers.append(key)
            for m, item in enumerate(self.THeaders[key]):
                item = QTableWidgetItem(item)
                item.setTextAlignment(Qt.AlignVCenter | Qt.AlignCenter)
                self.setItem(m, n, item)
        self.setHorizontalHeaderLabels(self.THeaders.keys())
        self.verticalHeader().setDefaultSectionSize(27)
        self.scrollToBottom()

    def stopProcess(self):
        self.setRowCount(0)
        self.clearContents()
        self.setHorizontalHeaderLabels(self.THeaders.keys())

class dockUrlMonitor(QTreeView):
    ''' dock widget for get all credentials logger netcreds'''
    def __init__(self, parent=None,info={}):
        super(dockUrlMonitor, self).__init__(parent)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.model = QStandardItemModel()
        self.model.setHorizontalHeaderLabels(['URL','HTTP-Headers'])
        self.setModel(self.model)
        self.setUniformRowHeights(True)
        self.setColumnWidth(0,130)

    def writeModeData(self,data):
        ''' get data output and add on QtableWidgets '''
        ParentMaster = QStandardItem('[ {0[src]} > {0[dst]} ] {1[Method]} {1[Host]}{1[Path]}'.format(
        data['urlsCap']['IP'], data['urlsCap']['Headers']))
        ParentMaster.setIcon(QIcon('icons/accept.png'))
        ParentMaster.setSizeHint(QSize(30,30))
        for item in data['urlsCap']['Headers']:
            ParentMaster.appendRow([QStandardItem('{}'.format(item)),
            QStandardItem(data['urlsCap']['Headers'][item])])
        self.model.appendRow(ParentMaster)
        self.setFirstColumnSpanned(ParentMaster.row(),
        self.rootIndex(), True)
        self.scrollToBottom()

    def clear(self):
        self.model.clear()

    def stopProcess(self):
        self.clearSelection()


class dockTCPproxy(QTableWidget):
    ''' dock widget for get all credentials logger netcreds'''
    def __init__(self, parent=None):
        super(dockTCPproxy, self).__init__(parent)
        self.setColumnCount(2)
        self.resizeRowsToContents()
        self.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Preferred)
        self.horizontalHeader().setStretchLastSection(True)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.verticalHeader().setVisible(False)
        self.verticalHeader().setDefaultSectionSize(27)
        self.setSortingEnabled(True)
        self.THeaders  = OrderedDict([ ('Plugin',[]),('Logging',[])])
        self.setHorizontalHeaderLabels(self.THeaders.keys())
        self.horizontalHeader().resizeSection(0,150)
        self.horizontalHeader().resizeSection(1,150)

    def writeModeData(self,data):
        ''' get data output and add on QtableWidgets '''
        self.THeaders['Plugin'].append(data.keys()[0])
        self.THeaders['Logging'].append(data[data.keys()[0]])
        Headers = []
        self.setRowCount(len(self.THeaders['Plugin']))
        for n, key in enumerate(self.THeaders.keys()):
            Headers.append(key)
            for m, item in enumerate(self.THeaders[key]):
                item = QTableWidgetItem(item)
                if key != 'Logging':
                    item.setTextAlignment(Qt.AlignVCenter | Qt.AlignCenter)
                self.setItem(m, n, item)
        self.setHorizontalHeaderLabels(self.THeaders.keys())
        self.verticalHeader().setDefaultSectionSize(27)
        self.scrollToBottom()

    def stopProcess(self):
        self.setRowCount(0)
        self.clearContents()
        self.setHorizontalHeaderLabels(self.THeaders.keys())


class dockPumpkinProxy(QTableWidget):
    ''' get all output and filter data from Pumpkin-Proxy plugin'''
    def __init__(self, parent=None,info={}):
        super(dockPumpkinProxy, self).__init__(parent)
        self.logger = info
        self.processThread = None
        self.pluginsName = []
        self.setColumnCount(2)
        self.resizeRowsToContents()
        self.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Preferred)
        self.horizontalHeader().setStretchLastSection(True)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.verticalHeader().setVisible(False)
        self.verticalHeader().setDefaultSectionSize(27)
        self.setSortingEnabled(True)
        self.THeaders  = OrderedDict([ ('Plugin',[]),('Output',[])])
        self.setHorizontalHeaderLabels(self.THeaders.keys())
        self.horizontalHeader().resizeSection(0,150)
        self.get_AllPluginName()

    def get_AllPluginName(self):
        ''' get all name plugins PumpkinProxy'''
        if load_plugins:
            plugin_classes = plugin.PluginTemplate.__subclasses__()
            for p in plugin_classes:
                self.pluginsName.append(p().Name)

    def writeModeData(self,data):
        ''' get data output and add on QtableWidgets'''
        for name in self.pluginsName:
            if name in data:
                self.THeaders['Output'].append(data[len('[{}]'.format(name)):])
                self.THeaders['Plugin'].append('[{}]'.format(name))

        Headers = []
        self.setRowCount(len(self.THeaders['Plugin']))
        for n, key in enumerate(self.THeaders.keys()):
            Headers.append(key)
            for m, item in enumerate(self.THeaders[key]):
                item = QTableWidgetItem(item)
                if key == 'Plugin':
                    item.setTextAlignment(Qt.AlignVCenter | Qt.AlignCenter)
                self.setItem(m, n, item)
        self.setHorizontalHeaderLabels(self.THeaders.keys())
        self.verticalHeader().setDefaultSectionSize(27)
        self.scrollToBottom()

    def stopProcess(self):
        self.setRowCount(0)
        self.clearContents()
        self.setHorizontalHeaderLabels(self.THeaders.keys())
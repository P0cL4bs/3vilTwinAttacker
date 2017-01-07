from plugins.extension import *
from collections import OrderedDict
from PyQt4.QtGui import (
    QListWidget,QTableWidget,QSizePolicy,
    QAbstractItemView,QTableWidgetItem,QIcon,QListWidgetItem
)
from PyQt4.QtCore import (
    SIGNAL,QProcess,pyqtSlot,QObject,SLOT,Qt,QSize
)

"""
Description:
    This program is a core for wifi-pumpkin.py. file which includes functionality
    for Activity-Monitor tab.

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

class dockUrlMonitor(QTableWidget):
    ''' dock widget for get all url monitor '''
    def __init__(self, parent=None,info={}):
        super(dockUrlMonitor, self).__init__(parent)
        self.setMinimumWidth(580)
        self.logger = info
        self.startThread  = False
        self.processThread = None
        self.setColumnCount(3)
        self.resizeRowsToContents()
        self.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Preferred)
        self.horizontalHeader().setStretchLastSection(True)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.verticalHeader().setVisible(False)
        self.verticalHeader().setDefaultSectionSize(27)
        self.setSortingEnabled(True)
        self.THeaders  = OrderedDict([ ('IP Address',[]),('Method',[]),('Path',[])])
        self.setHorizontalHeaderLabels(self.THeaders.keys())
        self.horizontalHeader().resizeSection(0,100)
        self.horizontalHeader().resizeSection(1,60)

    def writeModeData(self,data):
        '''get data output and add on QtableWidgets '''
        Headers = []
        data = data.split()
        self.THeaders['IP Address'].append(data[0])
        self.THeaders['Method'].append(data[1])
        self.THeaders['Path'].append(data[2])
        self.setRowCount(len(self.THeaders['Path']))
        for n, key in enumerate(self.THeaders.keys()):
            Headers.append(key)
            for m, item in enumerate(self.THeaders[key]):
                item = QTableWidgetItem(item)
                if key == 'Path':
                    item.setIcon(QIcon('icons/accept.png'))
                else:
                    item.setTextAlignment(Qt.AlignVCenter | Qt.AlignCenter)
                self.setItem(m, n, item)
        self.setHorizontalHeaderLabels(self.THeaders.keys())
        self.scrollToBottom()

    def stopProcess(self):
        self.clearContents()
        self.setRowCount(0)
        self.setHorizontalHeaderLabels(self.THeaders.keys())
        self.verticalHeader().setDefaultSectionSize(27)


class dockCredsMonitor(QTableWidget):
    ''' dock widget for get all credentials logger netcreds'''
    def __init__(self, parent=None,info={}):
        super(dockCredsMonitor, self).__init__(parent)
        self.logger = info
        self.startThread  = False
        self.processThread = None
        self.setColumnCount(3)
        self.resizeRowsToContents()
        self.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Preferred)
        self.horizontalHeader().setStretchLastSection(True)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.verticalHeader().setVisible(False)
        self.verticalHeader().setDefaultSectionSize(27)
        self.setSortingEnabled(True)
        self.THeaders  = OrderedDict([ ('Username',[]),('Password',[]),('Source/Destination',[])])
        self.setHorizontalHeaderLabels(self.THeaders.keys())
        self.horizontalHeader().resizeSection(0,170)
        self.horizontalHeader().resizeSection(1,150)

    def writeModeData(self,data):
        ''' get data output and add on QtableWidgets '''
        packetsIp = data.split(':[creds]')[1].split('HTTP username:')[0]
        for count,value in enumerate(data.split()):
            if 'username:' in value:
                username = data.split()[count+1]
                self.THeaders['Username'].append(username.split('=')[1])
            if 'password:' in value:
                password = data.split()[count+1]
                self.THeaders['Password'].append(password.split('=')[1])

        Headers = []
        if packetsIp not in self.THeaders['Source/Destination'] and not 'SessionID' in packetsIp:
            self.THeaders['Source/Destination'].append(packetsIp)
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
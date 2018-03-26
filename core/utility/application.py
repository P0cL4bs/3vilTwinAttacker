from PyQt4 import QtCore, QtGui
import core.utility.constants as C
from core.main import version

"""
Description:
    This program is a module for wifi-pumpkin.py manages the GUI
     application's control flow and main settings.

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

class ApplicationLoop(QtGui.QApplication):

    def __init__(self, argv):
        QtGui.QApplication.__init__(self, argv)
        self._memory    = QtCore.QSharedMemory(self)
        self.key        = 'WiFi-Pumpkin'
        self._memory.setKey(self.key)
        self.setApplicationName(self.key)
        self.setApplicationVersion(version)
        self.setOrganizationName('P0cL4bs Team')
        self.setWindowIcon(QtGui.QIcon('icons/icon.ico'))
        self.setAppQTDesigner(self.style().objectName())
        if self._memory.attach():
            self._running = True
        else:
            self._running = False
            if not self._memory.create(1):
                raise RuntimeError(self._memory.errorString())

    def setAppQTDesigner(self,style):
        if 'gtk+' in str(style).lower():
            self.setStyle(QtGui.QStyleFactory.create(C.GTKTHEME))

    def isRunning(self):
        return self._running
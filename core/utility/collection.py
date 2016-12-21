from os import path
from PyQt4.QtCore import QSettings

"""
Description:
    This program is a module for wifi-pumpkin.py.

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

class SettingsINI(object):
	""" settings INI file implemented for Wifi-Pumpkin"""
	def __init__(self,filename):
		if path.isfile(filename):
			self.psettings = QSettings(filename,QSettings.IniFormat)

	def get_setting(self,name_group,key,format=str):
		""" Get the value for setting key """
		self.psettings.beginGroup(name_group)
		value = self.psettings.value(key,type=format)
		self.closeGroup()
		return value

	def set_setting(self,name_group,key, value):
		""" Sets the value of setting key to value """
		self.psettings.beginGroup(name_group)
		self.psettings.setValue(key, value)
		self.closeGroup()

	def get_by_index_key(self,index,key=str):
		""" get specific key value by index type(list) """
		return str(self.get_setting(key,self.get_all_childname(key)[index]))

	def get_all_childname(self,key):
		""" get list all childskeys on file config.ini """
		return [x.split('/')[1] for x in self.get_all_keys() if x.split('/')[0] == key]

	def get_all_keys(self):
		""" get all keys on settings"""
		return str(self.psettings.allKeys().join("<join>")).split("<join>")

	def closeGroup(self):
		""" close group settings"""
		self.psettings.endGroup()
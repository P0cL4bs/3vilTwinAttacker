from config import Config
import urllib2
from subprocess import call,Popen,PIPE,STDOUT
import threading
from os import path
from PyQt4.QtCore import QThread,SIGNAL,pyqtSignal
from PyQt4.QtGui import QMessageBox

"""
Description:
    This program is a module for wifi-pumpkin.py file which includes functionality
    for downloading commits from github.

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

class TimerThread(threading._Timer):
    def run(self):
        while True:
            self.finished.wait(self.interval)
            if self.finished.is_set():
                return
            else:
                self.function(*self.args, **self.kwargs)

class UrllibDownload(QThread):
    '''Qthread Urllib download Git ChangeLog'''
    data_downloaded = pyqtSignal(object)
    def __init__(self, url):
        QThread.__init__(self)
        self.url = url
        self.response = None
    def run(self):
        try:
            self.response = urllib2.urlopen(self.url).read()
        except urllib2.URLError:
            try:
                self.response = urllib2.urlopen(self.url.replace('Core','core')).read()
            except urllib2.URLError:
                return self.data_downloaded.emit('URLError')
        return self.data_downloaded.emit(self.response)

class GithubUpdate(QThread):
    ''' thread github update from file .cfg'''
    def __init__(self,Version,Rlogger,localC,remoteC):
        QThread.__init__(self)
        self.Version    = Version
        self.localC     = localC
        self.remoteC    = remoteC
        self.Rchangelog = Rlogger

    def run(self):
        with open(self.remoteC,'w') as resp:
            resp.write(self.Rchangelog),resp.close()
        local,remote = file(self.localC),file(self.remoteC)
        self.commit_local,self.commit_update = self.getchangelog(local),self.getchangelog(remote)
        self.checkUpdate(self.Version)

    def UpdateRepository(self):
        if hasattr(self,'commit_update'):
            if self.commit_update['Updates'] != []:
                if not path.isdir('.git/'):self.gitZipRepo()
                call(['git','reset','--hard','origin/master'])
                self.ProcessCall_(['git','pull','origin','master'])

    def NewVersionUpdate(self):
        if not path.isdir('.git/'):self.gitZipRepo()
        call(['git','reset','--hard','origin/master'])
        self.ProcessCall_(['git','pull','origin','master'])

    def checkUpdate(self,Version):
        if self.commit_update['Version'] != Version:
            return self.emit(SIGNAL('Activated ( QString )'),'New Version available: WiFi-Pumpkin v'
            +self.commit_update['Version'])
        if self.commit_update['size'] > self.commit_local['size']:
            for commit in self.commit_update['lines'][self.commit_local['size']:]:
                self.emit(SIGNAL('Activated ( QString )'),'commit: '+commit)
                self.commit_update['Updates'].append(commit)
        elif self.commit_update['size'] == self.commit_local['size']:
            return self.emit(SIGNAL('Activated ( QString )'),'no changes in the repository.')
        else:
            self.emit(SIGNAL('Activated ( QString )'),'')

    def getchangelog(self,f):
        cfg = Config(f)
        commits = {'size': None,'lines': [],'Version': None,'Updates':[]}
        for m in cfg.master:
            if hasattr(m,'changelog'):
                commits['lines'].append(m['changelog'])
            if hasattr(m,'Version'):
                commits['Version'] = m['Version']
        commits['size'] = len(commits['lines'])
        return commits

    def gitZipRepo(self):
        call(['git','init'])
        call(['git','remote', 'add', 'origin', 'https://github.com/P0cL4bs/WiFi-Pumpkin.git'])
        call(['git', 'fetch','--all'])
        call(['git','reset','--hard','origin/master'])

    def status(self):
        self.emit(SIGNAL('Activated ( QString )'),'alive::')
        if hasattr(self,'proc'):
            for line in iter(self.proc.stdout.readline, b''):
                self.emit(SIGNAL('Activated ( QString )'),line)

    def ProcessCall_(self,command=[]):
        self.running = TimerThread(0.5, self.status)
        self.running.daemon = True
        self.running.start()
        self.proc = Popen(command,stdout=PIPE,
            stderr=STDOUT)
        self.proc.wait()
        self.running.cancel()
        self.emit(SIGNAL('Activated ( QString )'),'::updated')


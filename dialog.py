#!/usr/bin/env python
# -*- coding=utf-8 -*-
# dialog.py
# This file is showing UI
# autor: Hang Liu, Dongao Li, Paerhati Remutula
# 10/2/17

import sys
import os
import socket
import struct
import threading,getopt,string
import re
import time
import math
import base64

from PyQt5 import QtWidgets
from PyQt5 import QtGui
from PyQt5 import uic
from PyQt5 import QtCore
from PyQt5.QtCore import pyqtSlot
from PyQt5.QtCore import QObject, pyqtSignal
from PyQt5.QtWidgets import QFileDialog

from Crypto.Hash import SHA

from enum import Enum

from entity import EntityListenThread, EntitySession
from protocol import Protocol_Type

ENTITY_NAME = ''
ENTITY_ADDR = ''

SYSTEM_PREFIX = 'System>>'
ERROR_PREFIX = 'Error>>'
LOCAL_PREFIX = 'Local>>'
REMOTE_PREFIX = 'Remote>>'

MODE_TYPE = 1 # This is debug mode. This feature is invaild, when add session feature

HOST = "127.0.0.1"
PORT = 8000
# enum divide messages to 4 kinds.
class Message_Type(Enum):
    SYSTEM = 1
    ERROR = 2
    LOCAL = 3
    REMOTE = 4

class Form(QtWidgets.QDialog):
    host = remote = HOST
    port = rePort = PORT
    host_name = ''
    host_addr = ''

    session = None
    thread = None

    secretSignal = pyqtSignal(bool)

    def __init__(self, parent=None):
        QtWidgets.QDialog.__init__(self, parent)
        self.ui = uic.loadUi("dialog.ui", self)
        self.ui.show()
        self.initUI()

    # Initialize when the UI is created.
    def initUI(self):
        ENTITY_NAME, ENTITY_ADDR = self.getEntityNameAndIP()
        if MODE_TYPE:
            self.host = ENTITY_ADDR
        self.ui.entityName.setText(ENTITY_NAME)

    # Get Entity's name and ip
    def getEntityNameAndIP(self):
        # entityName = socket.getfqdn(socket.gethostname())
        if MODE_TYPE:
            self.host_name = socket.gethostname()
            self.host_addr = socket.gethostbyname(self.host_name)
        else:
            self.host_name = "localhost"
            self.host_addr = HOST
        return (self.host_name, self.host_addr)

    # Format message style via message type
    def dialogMessage(self, text, type):
        switcher = {
            Message_Type.SYSTEM: "<font color=green>%s %s</font>" % (SYSTEM_PREFIX, text),
            Message_Type.ERROR: "<font color=red>%s %s</font>" % (ERROR_PREFIX, text),
            Message_Type.LOCAL: "<I>%s %s</I>" % (LOCAL_PREFIX, text),
            Message_Type.REMOTE: "<U>%s %s</U>" % (REMOTE_PREFIX, text)
        }
        return switcher.get(type)

    # Set the message to textBrowser and display it
    def setDialogMessage(self, text, type):
        self.ui.textBrowser.append(self.dialogMessage(text, type))
        if self.session:
            if self.session.using_secret and (type == Message_Type.LOCAL or type == Message_Type.REMOTE):
                self.ui.textBrowser.append(self.dialogMessage('Above message is encrypted during transmission', Message_Type.SYSTEM))

    # Check the widget. If it is empty, give a tip to user
    def checkText(self, text, widgetName):
        if text == '':
            self.setDialogMessage(widgetName + ' Can not be null.', Message_Type.ERROR)
            return False
        else:
            return True

    # Call os file browser, and return the path of selected file
    def openFileNameDialog(self):
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog
        fileName, _ = QFileDialog.getOpenFileName(self,"QFileDialog.getOpenFileName()", "","All Files (*);;Python Files (*.py)", options=options)
        return fileName

    # Create a connection with socket and return the socket
    def socketConnect(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if not MODE_TYPE:
            self.remote = HOST
            self.rePort = PORT
        try:
            s.connect((self.remote, self.rePort))
        except socket.error as errmsg:
            print(errmsg)
            sys.exit(1)
        return s

    # Sent message for one entity to the other with socket
    def sendMessage(self, socket, msg):
        if socket is None:
            print('Could not open socket')
            sys.exit(1)
        with socket:
            # This is message type(see protocol.py)
            mhead = struct.pack('!I', Protocol_Type.TEXT.value)
            msg_size = len(msg)
            # Using secure to send a message
            if self.session:
                if self.session.using_secret:
                    msg_size = msg_size+40
            # This header is the size of message
            shead = struct.pack('l', msg_size)
            socket.sendall(mhead+shead+msg)
        socket.close()

    # This is the entry of communication of creating session.
    def sendIdentification(self, socket, header):
        if socket is None:
            sys.exit(1)
        with socket:
            mhead = struct.pack('!I', Protocol_Type.PROTOCOL.value)
            socket.sendall(mhead+header)
        socket.close()

    # This is the entry of communication of command.
    # Now there is only one command that is close session when an entity is closed
    def sendCommand(self, socket, command):
        if socket is None:
            sys.exit(1)
        with socket:
            mhead = struct.pack('!I', Protocol_Type.COMMAND.value)
            cmd_size = len(command)

            if self.session:
                if self.session.using_secret:
                    cmd_size = cmd_size+40
            shead = struct.pack('l', cmd_size)
            socket.sendall(mhead+shead+command)
        socket.close()

    # Encrypt file with file path
    # 1.This function is reading raw img and encrypt it with file block size(2048)
    # 2.Save the encrypted data to a tmp file(raw_tmp)
    # 3.Calculate the shasum with 2048size, return it
    def encrypt_file(self, filepath):
        f = open(filepath, 'rb')
        tmp = open('raw_tmp', 'wb')
        h = SHA.new()
        while True:
            data = f.read(EntitySession.file_block_size)
            if not data:
                break
            encrypted = EntitySession.aesEncrypt(data, self.session.session_key)
            h.update(data)
            tmp.write(encrypted)
        tmp.close()
        f.close()
        # os.remove('raw_tmp')
        print('sent shasum: ', h.hexdigest())
        return h.hexdigest()

    # This function is called in secure mode after encrypt_file
    def sendEncryptedFile(self, socket, raw_filepath, filepath, shasum):
        while True:
            if os.path.isfile(raw_filepath):
                # Set the message type is file(see protocol.py)
                mhead = struct.pack('!I', Protocol_Type.FILE.value)

                fileinfo_size = struct.calcsize('128sl')
                file_size = os.stat(raw_filepath).st_size
                # Set file name and file size into sec. header
                fhead = struct.pack('128sl', str.encode(os.path.basename(filepath), encoding = "utf8"), file_size)
                socket.send(mhead + fhead)
                print ('Client file path: %s'%format(filepath))
                fp = open('raw_tmp', 'rb')
                while True:
                    data = fp.read(EntitySession.file_block_size)
                    if not data:
                        print ('%s file send over...'%format(filepath))
                        break

                    socket.sendall(data)
                socket.send(str.encode(shasum, encoding='utf8'))
                fp.close()
            socket.close()
            break

    # This function is called common file communication
    def sendFile(self, socket, filepath):
        while True:
            if os.path.isfile(filepath):
                hash_text = self.session.ihash
                # 1st header is recording file type(see protocol.py)
                mhead = struct.pack('!I', Protocol_Type.FILE.value)
                fileinfo_size = struct.calcsize('128sl')
                file_size = os.stat(filepath).st_size
                # 2nd header is recording file name and file size
                fhead = struct.pack('128sl', str.encode(os.path.basename(filepath), encoding = "utf8"), file_size)
                socket.send(mhead + fhead)
                print ('Client file path: %s'%format(filepath))
                fp = open(filepath, 'rb')
                while True:
                    data = fp.read(EntitySession.file_block_size)
                    if not data:
                        print ('%s file send over...'%format(filepath))
                        break
                    socket.sendall(data)
                fp.close()
            socket.close()
            break

    # Create a session when user click the connect button.
    # Before call this function, the user needs to make sure all info have be filled.
    # info: listening port, host addr and host port (server entity and client entity)
    def createSessionConnect(self):
        self.session = EntitySession(self.host_addr)
        self.session.sendPhaseSignal.connect(self.sendPhase)

    @pyqtSlot()
    def closeEvent(self, event):
        if self.session:
            if self.session.using_secret:
                s = self.socketConnect()
                cmd = b'disconnect'
                cmd = data = EntitySession.aesEncrypt(EntitySession.hashTextByte(cmd), self.session.session_key)
                self.sendCommand(s, cmd)
                self.session = None
    # connect event
    @pyqtSlot()
    def connect(self):
        if self.checkText(self.ui.Host.text(), 'Host') and self.checkText(self.ui.Port_2.text(), 'Remote Port'):
            if MODE_TYPE:
                self.remote = self.ui.Host.text()
                self.rePort = int(self.ui.Port_2.text())
            self.createSessionConnect()
            if not self.session.is_client:
                self.session.is_client = True
                self.setDialogMessage('This is client', Message_Type.SYSTEM)
            self.session.createSession()
            self.ui.Connect.setEnabled(False)

    # send event
    @pyqtSlot()
    def send(self):
        if not self.session:
            self.setDialogMessage('You must connect to an Entity first.', Message_Type.ERROR)
            return

        if self.checkText(self.ui.lineEdit.text(), 'Message'):
            s = self.socketConnect()
            self.setDialogMessage(self.ui.lineEdit.text(), Message_Type.LOCAL)
            msg_str = self.ui.lineEdit.text()
            msg = str.encode(msg_str, encoding = "utf8")
            if self.session:
                if self.session.using_secret:
                    msg = EntitySession.aesEncrypt(EntitySession.hashText(msg_str), self.session.glost_public_key_name)

            self.sendMessage(s, msg)
            # self.setDialogMessage(repr(data), Message_Type.REMOTE)
            self.ui.lineEdit.clear()

    # secret event
    @pyqtSlot()
    def secret(self):
        if self.session:
            self.session.using_secret = not self.session.using_secret
            self.thread.secret_mode = self.session.using_secret
            if self.session.using_secret:
                self.thread.session_key = self.session.session_key
            else:
                self.thread.session_key = None
            self.setDialogMessage('Security Enabled: %s' % str(self.session.using_secret), Message_Type.SYSTEM)
        else:
            self.setDialogMessage('You must connect to an Entity first.', Message_Type.ERROR)
    # listen event
    @pyqtSlot()
    def listen(self):
        if self.checkText(self.ui.Port.text(), 'Port'):
            if MODE_TYPE:
                self.port = int(self.ui.Port.text())
                self.ui.Listen.setEnabled(False)
                self.setDialogMessage('Listening %s' %self.ui.Port.text(), Message_Type.SYSTEM)
            pass
        else:
            return
        try:
            self.thread = EntityListenThread(self)
            self.thread.hostInfo = (self.host, self.port)
            self.thread.setRemoteHostSignal.connect(self.setRemoteHost)
            self.thread.receiveDataSignal.connect(self.receiveData)
            self.thread.p_phase1_signal.connect(self.phase1_resolve)
            self.thread.p_phase2_signal.connect(self.phase2_resolve)
            self.thread.p_phase3_signal.connect(self.phase3_resolve)
            self.thread.p_phase4_signal.connect(self.phase4_resolve)
            self.thread.disconnect_signal.connect(self.disconnect)
            self.thread.start()
            # self.thread.close()
        except:
            pass

    @pyqtSlot()
    def loadFile(self):
        if not self.session:
            self.setDialogMessage('You must connect to an Entity first.', Message_Type.ERROR)
            return
        path = self.openFileNameDialog()
        if path.strip() != '':
            imgTag = '<img width="400" src="%s" />' % path
            s = self.socketConnect()
            if self.session:
                if self.session.using_secret:
                    shasum = self.encrypt_file(path)
                    self.sendEncryptedFile(s, 'raw_tmp', path, shasum)
                else:
                    self.sendFile(s, path)
            self.setDialogMessage(imgTag, Message_Type.LOCAL)

    @pyqtSlot(str, name='setRemoteHostSignal')
    def setRemoteHost(self, s):
        self.remote = s
        if not self.session:
            if MODE_TYPE:
                self.remote = self.ui.Host.text()
                self.rePort = int(self.ui.Port_2.text())
            self.createSessionConnect()
            if not self.session.is_server:
                self.session.is_server = True
                self.setDialogMessage('This is server', Message_Type.SYSTEM)
            self.session.createSession()
            self.ui.Connect.setEnabled(False)

    @pyqtSlot(bytes, int, name='receiveDataSignal')
    def receiveData(self, s, i):
        if i == 0:
            msg = s
            if self.session:
                if self.session.using_secret:
                    msg = EntitySession.aesDecrypt(s, self.session.glost_public_key_name)
                    origin_msg, flag = EntitySession.integrity(msg)
                    if flag: # pass the verify of Integrity
                        msg = origin_msg
                    else: # not pass the verify of Integrity
                        msg = origin_msg
                        self.setDialogMessage('Below message has some problems in the process of transmission', Message_Type.ERROR)
                        pass

            self.setDialogMessage(bytes.decode(msg, encoding='utf8'), Message_Type.REMOTE)
        else:
            imgTag = '<img width="400" src="%s" />' % bytes.decode(s, encoding='utf8')
            self.setDialogMessage(imgTag, Message_Type.REMOTE)

    # ==========Begin creating session event with protocol ==========
    @pyqtSlot(bytes, bytes, name='p_phase1_signal')
    def phase1_resolve(self, ds, pk):
        self.is_server = True
        self.session.protocol_phase1_resolver(self.remote, ds, pk)

    @pyqtSlot(bytes, bytes, bytes, name='p_phase2_signal')
    def phase2_resolve(self, pk, confid, ds):
        self.session.protocol_phase2_resolver(pk, confid, ds)

    @pyqtSlot(bytes, bytes, bytes, name='p_phase3_signal')
    def phase3_resolve(self, p_confid, ds, s_confid):
        self.session.protocol_phase3_resolver(p_confid, ds, s_confid)

    @pyqtSlot(bytes, name='p_phase4_signal')
    def phase4_resolve(self, s_confid):
        self.session.protocol_phase4_resolver(s_confid)

    @pyqtSlot(bytes, name='sendPhaseSignal')
    def sendPhase(self, b):
        s = self.socketConnect()
        self.sendIdentification(s, b)
    # ========== End creating session event with protocol ==========

    # del session when an entity is closed
    @pyqtSlot(name='disconnect_signal')
    def disconnect(self):
        if self.session:
            self.setDialogMessage('Session Closed', Message_Type.SYSTEM)
            self.ui.Connect.setEnabled(True)
            self.session.using_secret = False
            self.thread.secret_mode = False
            self.session = None
# App entry            
if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    w = Form()
    sys.exit(app.exec())

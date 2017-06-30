#!/usr/bin/env python
# -*- coding=utf-8 -*-
# entity.py
# This file includes Thread and Session
# autor: Hang Liu, Dongao Li, Paerhati Remutula
# 10/2/17
#
import sys
import os
import socket
import struct
import random
import math
import codecs
from PyQt5.QtCore import (QCoreApplication, QObject, QRunnable, QThread,
                          QThreadPool, pyqtSignal)

from Crypto import Random
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5
from Crypto.Cipher import AES
import base64
import uuid

from protocol import Protocol_Type

class EntityListenThread(QThread):
    hostInfo = ('', 0)
    secret_mode = False
    session_key = None

    # Signals
    setRemoteHostSignal = pyqtSignal('QString')
    receiveDataSignal = pyqtSignal(bytes, int)
    p_phase1_signal = pyqtSignal(bytes, bytes)
    p_phase2_signal = pyqtSignal(bytes, bytes, bytes)
    p_phase3_signal = pyqtSignal(bytes, bytes, bytes)
    p_phase4_signal = pyqtSignal(bytes)
    disconnect_signal = pyqtSignal()

    # decrypt file
    # This is converse function of encrypt file. It is similar to encrypt file in dialog.py
    # Using a tmp file to store received encrypted data.
    # shasum is received shasum from the other entity.
    def decrypt_file(self, filepath, shasum):
        f = open(filepath, 'wb')
        tmp = open('tmp', 'rb')
        h = SHA.new()
        while True:
            data = tmp.read(EntitySession.file_block_size)
            if not data:
                break
            decrypted = EntitySession.aesDecrypt(data, self.session_key)
            h.update(decrypted)
            f.write(decrypted)
        tmp.close()
        f.close()
        os.remove('tmp')
        print('received shasum: ', h.hexdigest())
        print('shasum: ', shasum)
        # Check received shasum and decrypted shasum. Are they equal or not
        if str.encode(h.hexdigest(), encoding='utf8') == shasum:
            # Shasums are equal
            return True
        else:
            # Shasums are not equal
            return False

    # This is thread entry. When user click the listening button, the function will be called
    def run(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(self.hostInfo)
            print(self.hostInfo)
            s.listen(5)
            protocol_type = Protocol_Type.TEXT
            while True:
                conn, addr = s.accept()
                self.setRemoteHostSignal.emit(addr[0])
                content_header_size = struct.calcsize('!I')
                buf = conn.recv(content_header_size)
                if buf:
                    filename = ''
                    filesize = 0
                    header = buf[0:content_header_size]
                    # Received message type, the value is number
                    temp, = struct.unpack('!I', header)
                    # Map the number of type to protocol enum
                    protocol_type = Protocol_Type(int(temp))
                    if protocol_type == Protocol_Type.FILE:
                        fileinfo_size = struct.calcsize('128sl')
                        content = conn.recv(fileinfo_size)
                        filename, filesize = struct.unpack('128sl', content)
                        fn = filename.strip(b'\00')
                        new_filename = os.path.join('./', 'new_' + bytes.decode(fn, encoding = "utf8"))
                        print ('file new name is %s, file size is %s'%(format(new_filename), filesize))
                        recvd_size = 0
                        fp = open('tmp', 'wb')
                        print ('start receiving...')

                        while not recvd_size == filesize:
                            data = ''
                            # Receive the data with 2048size
                            if filesize - recvd_size > EntitySession.file_block_size:
                                data = conn.recv(EntitySession.file_block_size)
                                recvd_size += len(data)
                            else:
                                # When the length of left data less than 2048, just receive left size data
                                data = conn.recv(filesize - recvd_size)
                                recvd_size = filesize

                            fp.write(data)
                        fp.close()
                        print ('end receive...')
                        if self.secret_mode:
                            data = conn.recv(40)
                            # using secure mode, need decrypt file first.
                            if self.decrypt_file(new_filename, data):
                                self.receiveDataSignal.emit(str.encode(new_filename, encoding='utf8'), 1)
                            else:
                                print('Some problems has been occured.')
                                pass
                        else:
                            # Rename tmp file to img file
                            os.rename('tmp', new_filename)
                            self.receiveDataSignal.emit(str.encode(new_filename, encoding='utf8'), 1)
                    # The process of message received
                    elif protocol_type == Protocol_Type.TEXT:
                        shead_size = struct.calcsize('l')
                        shead = conn.recv(shead_size)
                        content_size, = struct.unpack('l', shead)
                        if self.secret_mode:
                            content_size = content_size+40
                        content = conn.recv(content_size)
                        self.receiveDataSignal.emit(content, 0)
                    # The process of session creating
                    elif protocol_type == Protocol_Type.PROTOCOL:
                        # get header of wraper 1
                        p_header_size = struct.calcsize('!I64sl')
                        p_header = conn.recv(p_header_size)
                        # phase number, phase pattern, phase pattern size
                        p_phase, p_pattern, p_pattern_size = struct.unpack('!I64sl', p_header)

                        p_content = conn.recv(p_pattern_size)
                        p_pattern = p_pattern.strip(b'\00')

                        if int(p_phase) == 1:
                            # get header  of wraper 2
                            ds, pk = struct.unpack(p_pattern, p_content)
                            self.p_phase1_signal.emit(ds, pk)
                        elif int(p_phase) == 2:
                            # get header  of wraper 2
                            pk, confid, ds = struct.unpack(p_pattern, p_content)
                            self.p_phase2_signal.emit(pk, confid, ds)
                        elif int(p_phase) == 3:
                            # get header  of wraper 2
                            p_confid, ds, s_confid = struct.unpack(p_pattern, p_content)
                            self.p_phase3_signal.emit(p_confid, ds, s_confid)
                        elif int(p_phase) == 4:
                            # get header  of wraper 2
                            s_confid, = struct.unpack(p_pattern, p_content)
                            self.p_phase4_signal.emit(s_confid)
                    elif protocol_type == Protocol_Type.COMMAND:
                        shead_size = struct.calcsize('l')
                        shead = conn.recv(shead_size)
                        content_size, = struct.unpack('l', shead)
                        if self.secret_mode:
                            content_size = content_size+40
                        content = conn.recv(content_size)
                        if self.secret_mode:
                            content = EntitySession.aesDecrypt(content, self.session_key)
                            origin_content, flag = EntitySession.integrity(content)
                            if flag: # pass the verify of Integrity
                                content = origin_content
                            else: # not pass the verify of Integrity

                                pass
                        if content == b'disconnect':
                            self.disconnect_signal.emit()

                    conn.close()
            s.close()


class EntitySession(QObject):
    is_client = False
    is_server = False
    is_session_created = False
    using_secret = False
    session_id = ''
    nonce = 0
    remote_nonce = 0
    session_key = None
    random_generator = 0
    iv = b'1111111111111111'
    entity_uuid = ''
    private_key_name = 'entity-private.pem'
    public_key_name = 'entity-public.pem'
    glost_public_key_name = 'glost-public.pem'
    rsa_decrypt_err = 'Decrypt Error'
    local = ''
    remote = ''
    sendPhaseSignal = pyqtSignal(bytes)
    # record a size of data to process
    file_block_size = 2048
    def __init__(self, hostaddr, parent=None):
        QObject.__init__(self, parent)
        # get a id of A that will be stored database
        self.local = hostaddr
        self.entity_uuid = uuid.uuid5(uuid.NAMESPACE_DNS, hostaddr)

    # generate public and private key using rsa
    def generateRSAKeys(self):
        # generate psudo random number
        self.random_generator = Random.new().read
        # generate rsa
        rsa = RSA.generate(1024)

        # private key generating and writing as a file
        private_pem = rsa.exportKey()
        with open(self.private_key_name, 'w') as f:
            f.write(bytes.decode(private_pem, encoding='utf8'))
            f.close()
        # public key generating and writing as a file
        public_pem = rsa.publickey().exportKey()
        with open(self.public_key_name, 'w') as f:
            f.write(bytes.decode(public_pem, encoding='utf8'))
            f.close()

    # encrypt plaintext by public or private key
    def rsaEncrypt(self, plaintext, keyPath):
        key = ''
        with open(keyPath) as f:
            key = f.read()
            f.close()
        rsakey = RSA.importKey(key)
        cipher = Cipher_pkcs1_v1_5.new(rsakey)
        cipher_text = base64.b64encode(cipher.encrypt(str.encode(plaintext, encoding='utf8')))
        return cipher_text # This is a byte object

    # descrypt ciphertext by public or private key
    def rsaDecrypt(self, ciphertext, keyPath):
        key = ''
        with open(keyPath) as f:
            key = f.read()
            f.close()
        rsakey = RSA.importKey(key)
        cipher = Cipher_pkcs1_v1_5.new(rsakey)
        text = cipher.decrypt(base64.b64decode(ciphertext), self.rsa_decrypt_err)
        return text # This is a byte object

    # Important: pycrypto can not allowed using private key to encrypt message
    # explain as blow link
    # http://stackoverflow.com/questions/20057764/python-pycrypto-rsa-encrypt-method-gives-same-results-using-private-or-public-ke
    def rsaSign(self, plaintext, key, flag=False): #if flag=False, read key from file, else use it directly
        k = None
        if not flag:
            k = RSA.importKey(open(key).read())
        else:
            k = RSA.importKey(key)
        h = SHA.new(plaintext)
        signer = PKCS1_v1_5.new(k)
        return signer.sign(h)

    # Verify the signature of RSA
    def rsaVerifySign(self, plaintext, signature, key, flag=False):#if flag=False, read key from file, else use it directly
        k = None
        if not flag:
            k = RSA.importKey(open(key).read())
        else:
            k = RSA.importKey(key)
        h = SHA.new(plaintext)
        verifier = PKCS1_v1_5.new(k)
        if verifier.verify(h, signature):
            # print ("The signature is authenticated.")
            return True
        else:
            # print ("The signature is not authenticated.")
            return False

    # AES encrypt text
    @staticmethod
    def aesEncrypt(plaintext, key):
        cipher = AES.new(key, AES.MODE_CFB, EntitySession.iv)
        result = cipher.encrypt(plaintext)
        return result

    # AES decrypt text
    @staticmethod
    def aesDecrypt(ciphertext, key):
        cipher = AES.new(key, AES.MODE_CFB, EntitySession.iv)
        result = cipher.decrypt(ciphertext)
        return result

    # using sha to hash text
    @staticmethod
    def sha(text):
        h = SHA.new()
        h.update(str.encode(text, encoding='utf8'))
        return h.hexdigest()

    @staticmethod
    def sha_byte(text):
        h = SHA.new()
        h.update(text)
        return h.hexdigest()

    @staticmethod
    def hashText(text):
        hash_text = EntitySession.sha(text)
        print('Sent hash text:',hash_text)
        return hash_text + text

    @staticmethod
    def hashTextByte(text):
        hash_text = EntitySession.sha_byte(text)
        print('Sent hash text:',hash_text)
        return str.encode(hash_text, encoding='utf8') + text

    # Verify the integrity of message and command process
    @staticmethod
    def integrity(hash_text):
        hash_size = 40 # record the digitals of sha result
        hash_text_len = len(hash_text)
        text_len = hash_text_len - hash_size
        origin = hash_text[hash_size:]
        hashed = hash_text[0:hash_size]
        print('Received hash text:', hashed)
        if str.encode(EntitySession.sha_byte(origin), encoding='utf8') == hashed:
            return (origin, True)
        else:
            return (origin, False)

    def generateNonce(self, b):
        result = random.randint(1*pow(10, b-1), 10*pow(10, b-1)-1)
        return result

    def createSession(self):
        # generate asymmetric keys using RSA
        self.generateRSAKeys()
        if self.is_client and not self.is_server:
            self.protocol_phase1_generator()

    # A->B: {A}Ka-1, Ka+
    def protocol_phase1_generator(self):
        # A: uuid by address of A
        entity_identification = str.encode(str(self.entity_uuid), encoding='utf8')
        # {A}Ka-1
        digital_signature = self.rsaSign(entity_identification, self.private_key_name)
        # get Ka+ string
        public_key = ''
        with open(self.public_key_name) as f:
            public_key = f.read()
            f.close()
        # 1 means this is the phase 1
        pattern = '%ss%ss' % (len(digital_signature), len(str.encode(public_key, encoding='utf8')))
        p1_header = struct.pack('!I64sl', 1, str.encode(pattern, encoding='utf8'), struct.calcsize(pattern))
        msg = struct.pack(pattern, digital_signature, str.encode(public_key, encoding='utf8'))

        self.sendPhaseSignal.emit(p1_header+msg)
        print('===================1.The client has sent=================== \n Kc+, {H(C)}Kc-1')

    # B->A: Kb+, {sid, Nb}Ka+, {H(Nb)}Kb-1
    def protocol_phase2_generator(self):
        # Kb+
        public_key = ''
        with open(self.public_key_name) as f:
            public_key = f.read()
            f.close()
        # Nb
        self.nonce = self.generateNonce(10)
        # {sid, Nb}Ka+
        confiden_str = '||'.join([self.session_id, str(self.nonce)])
        confiden_result = self.rsaEncrypt(confiden_str, self.glost_public_key_name)

        # H(Nb) Dont need to hash nonce. When give a sign to nonce, sign function has hashed
        hash_nonce = EntitySession.sha(str(self.nonce))
        # {H(Nb)}Kb-1
        ds = self.rsaSign(str.encode(str(self.nonce), encoding='utf8'), self.private_key_name)

        # 2 means this is the phase 2
        pattern = '%ss%ss%ss' % (len(str.encode(public_key, encoding='utf8')), len(confiden_result), len(ds))
        p2_header = struct.pack('!I64sl', 2, str.encode(pattern, encoding='utf8'), struct.calcsize(pattern))
        msg = struct.pack(pattern, str.encode(public_key, encoding='utf8'), confiden_result, ds)
        self.sendPhaseSignal.emit(p2_header+msg)
        print('===================2.The server has sent=================== \n Ks+, {sid, Ns}Kc+, {H(Ns)}Kc-1 \n Ns = %s' % str(self.nonce))

    # A->B {Na}Kb+, {H(Na)}Ka-1, {Nb}Kab
    def protocol_phase3_generator(self):
        # Na
        self.nonce = self.generateNonce(10)
        # {Na}Kb+
        p_confid = self.rsaEncrypt(str(self.nonce), self.glost_public_key_name)
        # {H(Na)}Ka-1
        ds = self.rsaSign(str(self.nonce).encode('utf8'), self.private_key_name)

        # Generate Kab
        session_key = self.sha(str(self.nonce)+str(self.remote_nonce))
        # session key can has more 32 digits
        self.session_key = session_key[0:32]

        # {Nb}Kab
        s_confid = EntitySession.aesEncrypt(str.encode(str(self.remote_nonce), encoding='utf8'),
            str.encode(self.session_key, encoding='utf8'))

        # 3 means this is the phase 3
        pattern = '%ss%ss%ss' % (len(p_confid), len(ds), len(s_confid))
        p3_header = struct.pack('!I64sl', 3, str.encode(pattern, encoding='utf8'), struct.calcsize(pattern))
        msg = struct.pack(pattern, p_confid, ds, s_confid)
        self.sendPhaseSignal.emit(p3_header+msg)
        print('===================3.The client has sent=================== \n {Nc}Ks+, {H(Nc)}Kc-1, {Ns}Kcs \n Nc = %s' % str(self.nonce))

    # B->A: {Na}Kab
    def protocol_phase4_generator(self):
        s_confid = EntitySession.aesEncrypt(str(self.remote_nonce).encode('utf8'), self.session_key)
        # 4 means this is the phase 4
        pattern = '%ss' % (len(s_confid))
        p4_header = struct.pack('!I64sl', 4, str.encode(pattern, encoding='utf8'), struct.calcsize(pattern))
        msg = struct.pack(pattern, s_confid)
        self.sendPhaseSignal.emit(p4_header+msg)
        print('===================4.The server has sent=================== \n {Nc}Kcs}')

    # executed in B
    def protocol_phase1_resolver(self, hostaddr, ds, pk):
        glost_uuid = uuid.uuid5(uuid.NAMESPACE_DNS, hostaddr)
        self.saveGlostPublicKey(pk)
        if self.rsaVerifySign(str.encode(str(glost_uuid), encoding='utf8'), ds, pk, True):
            glost_uuid = uuid.uuid5(uuid.NAMESPACE_DNS, hostaddr)
        else:
            # re-connect
            pass

        # glost_uuid = self.rsaDecrypt(ds, self.glost_public_key_name)
        self.generateSessionID(glost_uuid)
        print('===================1.The server has received=================== \n Kc+, {H(C)}Kc-1')
        self.protocol_phase2_generator()


        # print(socket.gethostbyaddr(hostaddr))
    # executed in A
    def protocol_phase2_resolver(self, pk, confid, ds):
        info = bytes.decode(self.rsaDecrypt(confid, self.private_key_name), encoding='utf8')
        if info == self.rsa_decrypt_err:
            # do something or exit(1)
            pass
        else:
            self.session_id = info.split('||')[0]
            self.remote_nonce = int(info.split('||')[1])
            challenage = str(self.remote_nonce).encode('utf8')
            if self.rsaVerifySign(challenage, ds, pk, True):
                self.saveGlostPublicKey(pk)
            else:
                # re-send or re-resovle
                pass
            print('===================2.The client has received=================== \n Ks+, {sid, Ns}Kc+, {H(Ns)}Kc-1 \n Ns = %s' % self.remote_nonce)
            self.protocol_phase3_generator()


    # executed in B
    def protocol_phase3_resolver(self, p_confid, ds, s_confid):
        # Na
        remote_nonce = bytes.decode(self.rsaDecrypt(p_confid, self.private_key_name), encoding='utf8')
        if self.rsaVerifySign(remote_nonce.encode('utf8'), ds, self.glost_public_key_name):
            self.remote_nonce = int(remote_nonce)
        else:
            # re-send
            pass

        # Generate Kab
        session_key = self.sha(str(self.remote_nonce)+str(self.nonce))
        # session key can has more 32 digits
        i_session_key = session_key[0:32]

        # Nb
        nonce_return = bytes.decode(EntitySession.aesDecrypt(s_confid, i_session_key), encoding='utf8')
        if self.nonce == int(nonce_return):
            self.session_key = i_session_key
            is_session_created = True
            print('===================3.The server has received=================== \n {Nc}Ks+, {H(Nc)}Kc-1, {Ns}Kcs \n Nc = %s' % remote_nonce)
            self.protocol_phase4_generator()
        else:
            # re-send
            pass

    # executed in A
    def protocol_phase4_resolver(self, s_confid):
        nonce_return = bytes.decode(EntitySession.aesDecrypt(s_confid, self.session_key), encoding='utf8')
        if int(nonce_return) == self.nonce:
            is_session_created = True
        print('===================4.The client has received=================== \n {Nc}Kcs}')

    # save remote entity public key to a file
    def saveGlostPublicKey(self, key):
        with open(self.glost_public_key_name, 'w') as f:
            f.write(bytes.decode(key, encoding='utf8'))
            f.close()

    def generateSessionID(self, entity_uuid):
        self.session_id = str(entity_uuid)

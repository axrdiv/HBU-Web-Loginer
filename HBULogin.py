#!/usr/bin/python
# coding=utf-8
import requests
import time 
import json
import math
import random
import re
from urllib import quote
from hashlib import md5, sha1
import binascii
import ctypes
import string
import array
import collections


username = '12345678'
password = 'abcdefgh'

class ConnectError(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return self.value

class HBULoginer():
    def __init__(self, username, password, url='http://202.206.1.231'):
        self.username = username
        self.password = password
        self.url = url
        self.id = str(random.randint(112401023580207000000, 112401023580207100000))
        try:
            self.ip = self.__get_ip()
            self.token = self.__get_challenge()
        except ConnectError as e:
            print(e)


    def __timestamp(self):
        return str(int(time.time() * 1e3))

    def __get_ip(self):
        infurl = self.url + "/cgi-bin/rad_user_info?callback=jQuery"
        infurl += self.id + "_"
        infurl += self.__timestamp() + "&_=" + self.__timestamp()
        try:
            r = requests.get(infurl, timeout=4)
            content = json.loads(re.findall(r'\{.*\}', r.text)[0])
            return content['online_ip']
        except:
            raise ConnectError("Can Not Acquire IP Address.")

    def __get_challenge(self):
        chalurl = self.url + "/cgi-bin/get_challenge?callback=jQuery"
        chalurl += self.id + "_" + self.__timestamp()
        chalurl += "&username=" + self.username
        chalurl += "&ip=" + self.ip
        chalurl += "&_=" + self.__timestamp()
        try:
            r = requests.get(chalurl, timeout=4)
            content = json.loads(re.findall(r'\{.*\}', r.text)[0])
            return content['challenge']
        except:
            raise ConnectError("Can Not Acquire Challenge Token.")

    def login(self):
        srun_url = self.url + "/cgi-bin/srun_portal?callback=jQuery"+ self.id
        srun_url += "_" + self.__timestamp()
        srun_url += "&username=" + self.username
        srun_url += "&ip="+ self.ip + "&chksum=" + self.__chksum() + "&password=%7BMD5%7D"+ self.__pwd()
        srun_url += "&double_stack=0&info="+ quote(self.__info()) + "&name=Linux&type=1&n=200&action=login&os=Linux&ac_id=1&_="
        srun_url += self.__timestamp()
        try:
            r = requests.get(srun_url, timeout=4)
            content = json.loads(re.findall(r'\{.*\}', r.text)[0])
            assert(content['error'] == 'ok')
        except:
            raise ConnectError("Can Not Login.")

    def logout(self):
        logout_url = self.url + "/cgi-bin/srun_portal?callback=jQuery" + self.id + "_" + self.__timestamp() + "&action=logout&ac_id=1&ip="
        logout_url += self.ip + "&_=" + self.__timestamp()
        try:
            r = requests.get(logout_url, timeout=4)
            content = json.loads(re.findall(r'\{.*\}', r.text)[0])
            assert(content['error'] == 'ok')
        except:
            raise ConnectError("Can Not Logout.")

    def __pwd(self):
        m = md5(self.password)
        return m.hexdigest()

    def __s(self, a, b):
        c = len(a)
        v = []
        a += chr(0) * 4
        for i in range(0, c, 4):
            p = ord(a[i]) | ord(a[i+1]) << 8 | ord(a[i+2]) << 16 | ord(a[i+3]) << 24
            v.append(p)
        if b:
            v.append(c)
        return v

    def __int_overflow(self, val):
        maxint = 2147483647
        if not -maxint - 1 <= val <= maxint:
            val = (val + (maxint + 1)) % (2 * (maxint + 1)) - maxint - 1
        return val

    def __urs_op(self, n, i):
        """unsiged_right_shift
            to implement >>> operator in js"""
        if n < 0:
            n = ctypes.c_uint32(n).value
        if i < 0:
            return -self.__int_overflow(n << abs(i))
        return self.__int_overflow(n >> i)


    def __l(self, a, b):
        d = len(a)
        c = (d-1) << 2
        v = []
        if b:
            m = a[d-1]
            if m < c - 3 or m > c:
                return None
            c = m
        for i in range(d):
            for j in range(4):
                v.append(self.__urs_op(a[i], 8*j) & 0xff)

        alter_base64chars =  "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"
        std_base64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

        s = array.array('B', v).tostring()
        return binascii.b2a_base64(s).translate(string.maketrans(std_base64chars, alter_base64chars))


    def __xEncode(self, str, key):
        if str == "":
            return ""
        v = self.__s(str, True)
        k = self.__s(key, False)
        if len(k) < 4:
            for i in range(4):
                k.append(0)
            k = k[:4]
        n = len(v)-1
        z = v[n]
        y = v[0]
        pp = 0
        c = ctypes.c_int32(0x86014019).value | ctypes.c_int32(0x183639A0).value
        q = int(math.floor(6 + 52 / (n+1)))
        d = 0
        while(q > 0):
            q = q-1
            d = ctypes.c_int32(ctypes.c_int32(d).value + ctypes.c_int32(c).value & (ctypes.c_int32(0x8CE0D9BF).value | ctypes.c_int32(0x731F2640).value)).value
            e = self.__urs_op(d, 2) & 3
            for p in range(n):
                pp = p
                y = v[p+1]
                m = self.__urs_op(z, 5) ^ ((y << 2) & 0xffffffff)
                m += (self.__urs_op(y, 3) ^ ((z << 4) & 0xffffffff)) ^ (d ^ y)
                m += k[(p & 3) ^ e] ^ z
                v[p] = v[p] + m & (0xEFB8D130 | 0x10472ECF)
                z = v[p]
            y = v[0]
            m = self.__urs_op(z, 5) ^ ((y << 2) & 0xffffffff)
            m += (self.__urs_op(y, 3) ^ ((z << 4) & 0xffffffff)) ^ (d ^ y)
            m += k[(pp+1) & 3 ^ e] ^ z
            z = v[n] = v[n] + m & (0xBB390742 | 0x44C6F8BD)

        return self.__l(v, False)


    def __info(self):
        params = collections.OrderedDict()
        params['username'] = self.username
        params['password'] = self.password
        params['ip'] = self.ip
        params['acid'] = "1"
        params['enc_ver'] = 'srun_bx1'
        s = ''.join(json.dumps(params).split(' '))
        return "{SRBX1}" + self.__xEncode(s, self.token)[:-1]



    def __chksum(self):
        hmd5 = self.__pwd()
        ac_id = "1"
        n = "200"
        i = self.__info()
        chkstr = self.token + self.username
        chkstr += self.token + hmd5
        chkstr += self.token + ac_id
        chkstr += self.token + self.ip
        chkstr += self.token + n
        chkstr += self.token + "1"                  # type = 1; token + type;
        chkstr += self.token + i
        return sha1(chkstr).hexdigest()



if __name__ == '__main__':
    loginer = HBULoginer(username, password)
    loginer.login()
    # loginer.logout()

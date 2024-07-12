#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import json
import random
import time
import requests
import string
import sys
from base64 import b64encode
from uuid import uuid4


from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import RSA

# from pocsuite3.lib.core.data import conf, logger
# from pocsuite3.lib.request import requests
# from pocsuite3.lib.utils import random_str

def random_str():
    '''随机子域名前缀'''
    len = random.randint(7, 9)
    lis = ['h','t','t','p','s','g','i','t','h','u','b','c','o','m','s','m','a','l','l','f','o','x','2','3','3']
    return ''.join(random.sample(lis, len))

class Interactsh:
    def __init__(self, server='', token=''):
        rsa = RSA.generate(2048)
        self.public_key = rsa.publickey().exportKey()
        self.private_key = rsa.exportKey()

        self.server = server.lstrip('.')
        # if 'oob_server' in conf: 配置
        #     self.server = self.server or conf.oob_server
        self.server = self.server or 'oast.me'

        self.token = token
        # if 'oob_token' in conf:
        #     self.token = self.token or conf.oob_token

        self.headers = {
            "Content-Type": "application/json",
        }
        if self.token:
            self.headers['Authorization'] = self.token
        self.secret = str(uuid4())
        self.encoded = b64encode(self.public_key).decode("utf8")
        guid = uuid4().hex.ljust(33, 'a')
        guid = ''.join(i if i.isdigit() else chr(ord(i) + random.randint(0, 20)) for i in guid)
        self.domain = f'{guid}.{self.server}'
        self.correlation_id = self.domain[:20]

        self.session = requests.session()
        self.session.headers = self.headers
        self.register_flag = False
        self.register()



    def register(self):
        data = {
            "public-key": self.encoded,
            "secret-key": self.secret,
            "correlation-id": self.correlation_id
        }
        msg = f"无法获取 {self.server} 授权信息 "
        try:
            res = self.session.post(
                f"http://{self.server}/register", headers=self.headers, json=data, verify=False)
            # print(res)
            if res.status_code == 401:
                print("[!] DNSLog授权失败")
            elif 'success' not in res.text:
                print(msg)
            self.register_flag = True
        except requests.RequestException:
            print("[!] "+msg)

    def poll(self):
        '''
        :return: [{'protocol',xxxxx},
                {'protocol': '协议类型', 'unique-id': 'dnslog地址子域名', 'full-id': '触发的子域名（没有点隔开）',
                'raw-request': '请求', 'raw-response': '回包', 'remote-address': 'IP地址', 'timestamp': '时间'}
                ]
        '''
        count = 3
        result = []
        while count:

            try:
                url = f"http://{self.server}/poll?id={self.correlation_id}&secret={self.secret}"
                res = self.session.get(url, headers=self.headers, verify=False).json()
                aes_key, data_list = res['aes_key'], res['data']
                for i in data_list:
                    decrypt_data = self.decrypt_data(aes_key, i)
                    result.append(decrypt_data)
                return result
            except Exception:
                count -= 1
                time.sleep(1)
                continue
        return []

    def decrypt_data(self, aes_key, data):
        private_key = RSA.importKey(self.private_key)
        cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
        aes_plain_key = cipher.decrypt(base64.b64decode(aes_key))
        decode = base64.b64decode(data)
        bs = AES.block_size
        iv = decode[:bs]
        cryptor = AES.new(key=aes_plain_key, mode=AES.MODE_CFB, IV=iv, segment_size=128)
        plain_text = cryptor.decrypt(decode)
        return json.loads(plain_text[16:])

    def build_request(self, length=10, method='http'):
        """
        Generate the url and flag for verification

        :param length: The flag length
        :param method: Request type (dns|https|http), the default is https
        :return: dict { url: Return the request url, flag: Return a random flag }
        Example:
          {
            'url': 'http://hqlbbwmo8u.7735s13s04hp4eu19s4q8n963n73jw6hr.interactsh.com'
          }

        """

        url = f'{self.domain}'
        # if method.startswith('http'):
        #     url = f'{method}://{url}'
        return url,self.register_flag

    def verify(self, flag, get_result=False):
        """
        Check the flag

        :param flag: The flag to verify
        :param get_result: Whether to return detailed results
        :return: Boolean
        """
        result = self.poll() # [{'protocol',xxxxx},{'protocol': '协议类型', 'unique-id': 'dnslog地址子域名', 'full-id': '触发的子域名（没有点隔开）', 'raw-request': '请求', 'raw-response': '回包', 'remote-address': 'IP地址', 'timestamp': '时间'}]
        print(result)
        for item in result: #在结果集中遍历获取信息
            if flag.lower() in item['full-id'].lower():
                return (True, result) if get_result else True
        return (False, result) if get_result else False


if __name__ == "__main__":
    ISH = Interactsh(token="", server="")
    url, flag = ISH.build_request()
    print(ISH.poll())
    x = random_str()
    requests.get("http://"+x+"."+url, timeout=5, verify=False)
    print(x)
    print(ISH.poll())
    print(ISH.verify(flag, get_result=True))

    data = [{'protocol': 'dns', 'unique-id': '25tof78eu7864e01990g09x1n1ws742tb',
             'full-id': '25tof78eu7864e01990g09x1n1ws742tb', 'q-type': 'A',
             'raw-request': ';; opcode: QUERY, status: NOERROR, id: 58899\n;; flags: cd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version 0; flags: do; udp: 1232\n; SUBNET: 46.3.240.0/24/0\n\n;; QUESTION SECTION:\n;25tof78eu7864e01990g09x1n1ws742tb.oast.me.\tIN\t A\n',
             'raw-response': ';; opcode: QUERY, status: NOERROR, id: 58899\n;; flags: qr aa cd; QUERY: 1, ANSWER: 1, AUTHORITY: 2, ADDITIONAL: 2\n\n;; QUESTION SECTION:\n;25tof78eu7864e01990g09x1n1ws742tb.oast.me.\tIN\t A\n\n;; ANSWER SECTION:\n25tof78eu7864e01990g09x1n1ws742tb.oast.me.\t3600\tIN\tA\t178.128.209.14\n\n;; AUTHORITY SECTION:\n25tof78eu7864e01990g09x1n1ws742tb.oast.me.\t3600\tIN\tNS\tns1.oast.me.\n25tof78eu7864e01990g09x1n1ws742tb.oast.me.\t3600\tIN\tNS\tns2.oast.me.\n\n;; ADDITIONAL SECTION:\nns1.oast.me.\t3600\tIN\tA\t178.128.209.14\nns2.oast.me.\t3600\tIN\tA\t178.128.209.14\n',
             'remote-address': '45.11.104.186',
             'timestamp': '2023-08-18T07:09:06.602449322Z'},
            {'protocol': 'http', 'unique-id': '25tof78eu7864e01990g09x1n1ws742tb',
             'full-id': '25tof78eu7864e01990g09x1n1ws742tb', 'raw-request': 'GET / HTTP/1.1\r\nHost: 25tof78eu7864e01990g09x1n1ws742tb.oast.me\r\nAccept: */*\r\nAccept-Encoding: gzip, deflate\r\nUser-Agent: python-requests/2.31.0\r\n\r\n', 'raw-response': 'HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html; charset=utf-8\r\nServer: oast.me\r\nX-Interactsh-Version: 1.1.5\r\n\r\n<html><head></head><body>bt247sw1n1x90g09910e4687ue87fot52</body></html>', 'remote-address': '46.232.120.227',
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 'timestamp': '2023-08-18T07:09:06.677781548Z'}]

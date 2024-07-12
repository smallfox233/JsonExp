# 作者：小狐狸FM
# 版本：2024.07.12
import time
import requests
import os
import random
import lib.fread as Fread
import lib.format as Format
import lib.get as Get
from lib.interactsh import *


def random_str():
    len = random.randint(7, 9)
    lis = ['h', 't', 't', 'p', 's', 'g', 'i', 't', 'h', 'u', 'b', 'c', 'o', 'm', 's', 'm', 'a', 'l', 'l', 'f', 'o', 'x',
           '2', '3', '3']
    return ''.join(random.sample(lis, len))



class Check:
    def __init__(self, dic_origin):
        '''
        :param dic_origin: {'header': {'User-Agent': 'xxx'}, 'path': 'x', 'host': 'xx', 'body': ''
                            , 'port': '', 'dnslog': True|False, 'timeout': x, 'ldap_rmi': '', 'payload': '',
                            'type': 'post|get', 'file': 'xxx.txt', 'protocol': 'http', 'proxy': {'http': '',
                            'https': ''}, 'url': 'xxx'}
        '''
        self.dic_origin = dic_origin

    def _msg(self):
        '''
        打印提示
        '''
        # 消息提示
        if self.dic_origin['proxy']['http'] != '' and "http" in self.dic_origin['proxy']['http']:  # 存在http代理地址时
            # time.sleep(1)
            print("[+] 代理开启：" + self.dic_origin['proxy']['http'])
        if self.dic_origin['proxy']['https'] != '' and "https" in self.dic_origin['proxy']['https']:  # 存在https代理地址时
            # time.sleep(1)
            print("[+] 代理开启：" + self.dic_origin['proxy']['https'])
        print("[+] 测试URL：" + self.dic_origin['url'])
        print("[+] 请求类型：" + self.dic_origin['type'].upper())
        print("[+] 提示：若程序在某个payload中断一段时间，该payload可能触发了漏洞, 可复制payload至本地修改子域名检测")
        print("[+] 测试的payload如下：")
        print()

    def _check(self):
        '''
        检测漏洞
        '''
        dic = dict()
        dic = self.dic_origin
        # 定义
        dnslog_html_flag = False #是否输出了dnslog文件
        req = ""
        res = ""
        result_dnslog = ""
        oob = Interactsh()  # 实例化
        data_lis = Fread.fread_payload(dic['file'])  # 读取payload
        # print(data_lis)

        ldap_rmi = ""  # ldap/rmi请求地址
        response = ""  # 返回包
        result_data = ""  # report.html末尾的json数据
        # 请求地址检测
        if "http://" not in str(dic['url']) and "https://" not in str(dic['url']):
            print("[!] 请在该URL中添加http://或https://协议头信息")
            return
        # 时间戳设置，共13位
        dic['create_time'] = str(time.time())  # 获取当前时间至1970年1月1日的秒数
        dic['create_time'] = dic['create_time'].replace(".", "")[:13:]  # 保留整数部分,及小数的3位，共13位
        if 'Content-Type' not in dic['header']:  # mime类型设置
            dic['header']['Content-Type'] = 'application/json'
        # print(header)
        print()
        # DNSLog资源申请
        try:
            if self.dic_origin['dnslog']:  # 需要申请地址时
                dic['ldap'], flag = oob.build_request()  # 申请地址
                if flag == False:  # 无法获取申请的资源时
                    return
        except:
            return
        # 测试
        # requests.get("http://"+"123"+dic['ldap'])
        # requests.get("http://" + "233" + dic['ldap'])
        # print(oob.verify("23"))
        # return

        self._msg() #发送提示

        for i in range(len(data_lis)):  # 逐个发送报文
            # print(self.dic_origin['body'])
            # break
            # 赋值还原
            result_dnslog = ""
            dnslog_flag = False
            dic['url'] = self.dic_origin['url']
            dic['body'] = self.dic_origin['body']
            dic['path'] = self.dic_origin['path']
            dic['payload'] = data_lis[i]
            now_random = random_str()  # 随机7-9位数字+字母
            if dic['port'] == "":  # 端口空值检测
                dic['port'] = Get.get_port(dic['url'])
            # print(dic)
            # payload格式替换
            now_payload,header,body,url = Format.format_payload(dic, now_random)
            # print(dic['url'])
            # break
            # 消息提示
            print("[+] 序号：" + str(i + 1))

            # print(body)
            # break
            # print(dic['protocol']+ "://"+dic['host']+dic['path'])
            # 发包
            try:  # 异常检测
                # 提交表单
                if str(self.dic_origin['type']).lower() == "get":  # 请求类型get
                    requests.packages.urllib3.disable_warnings() # 取消request报错回显信息
                    response = requests.get(url , headers=header, timeout=self.dic_origin['timeout'],
                                            proxies=self.dic_origin['proxy'],verify=False)  # 发送请求
                elif self.dic_origin['type'] == 'post':  # 请求类型post
                    requests.packages.urllib3.disable_warnings()  # 取消request报错回显信息
                    response= requests.post(url, data=body, headers=header,
                                             timeout=self.dic_origin['timeout'], proxies=self.dic_origin['proxy'],verify=False)  # 发送请求
                # print(response.json())
                print("[+] 响应时长：",response.elapsed.total_seconds(),"秒")
                print(now_payload)

                # 请求包数据处理
                req = Format.format_req(dic)
                # 返回包数据处理
                res = Format.format_res(response)
                # print()
                # print(req)
                # print()
                # 结果保存
                result_data = Format.format_result(create_time=dic['create_time'], url=dic['url'],
                                                   http_type=dic['type'],
                                                   ldap_rmi=now_random + "." + dic['ldap_rmi'], payload=now_payload,
                                                   req=req, res=res)
                Format.output(filename=Get.get_host(dic['url']), result_data=result_data)

                # Dnslog模式数据存储
                if dic['dnslog']:
                    result_dnslog = Get.get_dnslog(oob.poll())  # 获取结果集
                    if result_dnslog != []:  # 存在结果时
                        result_dnslog = Format.format_result_dnslog(result_dnslog)  # 对结果集进行格式化处理
                        Format.output_dnslog("template/dnslog.html", Get.get_host(dic['url']) + "_dnslog.html",
                                             result_dnslog)
                        dnslog_html_flag = True #标记输出了dnslog文件


            except requests.exceptions.ConnectionError as e:  # 连接失败
                print("\n[!] 连接" + dic['url'] + "失败\n")

            except requests.exceptions.ReadTimeout as e:  # 请求超时
                # print("\n[!] 请求超时，请检测DNSlog/LDAP是否已成功检测")
                # print("[!] 当前超时时长设置为"+ str(dic['timeout']) +"，可使用-to参数设置请求超时时长\n")
                # 请求包数据处理
                req = Format.format_req(dic)
                # 返回包数据处理
                res = '请求超时,当前请求超时时长设置为' + str(dic['timeout'] )+ "秒"
                print("[!] " + str(res))
                print(now_payload)
                # 结果保存
                result_data = Format.format_result(create_time=dic['create_time'], url=dic['url'],
                                                   http_type=dic['type'],
                                                   ldap_rmi=now_random + "." + dic['ldap_rmi'], payload=now_payload,
                                                   req=req, res=res)
                Format.output(filename=Get.get_host(dic['url']), result_data=result_data)
                continue
            # break

        print("[+] 检测结束")
        print("[+] 检测结果已保存至result/" + Get.get_host(dic['url']) + ".html文件中")
        if dnslog_html_flag:
            print("[+] DNSLog回显结果已保存至result/" + Get.get_host(dic['url']) + "_dnslog.html文件中")

    def _check_request(self):
        '''
        根据请求包进行检测
        '''
        # 检测文件是否已存在
        if os.path.exists(self.dic_origin['request']) == False:
            print("[!]: 文件" + self.dic_origin['request'] + "不存在")
            return
        # 读取请求信息
        self.dic_origin = Fread.fread_request(self.dic_origin)
        # print(dic_origin)
        self._check()

    def _check_multiple(self, target):
        '''
        检测多个目标URL
        :param target: list()
        :return:
        '''
        # print(target)

        for url in target:
            if url != "":  # 不为空值时
                # url设置
                self.dic_origin['url'] = url
                self._check()

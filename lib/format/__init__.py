# 作者：小狐狸FM
# 版本：2024.07.12

import json, re, sys, random
from lib.check import *
import lib.get as Get


def is_ip(txt):
    '''
    检测字符串是否含有ip地址
    :param txt:
    :return: bool
    '''
    # 数据处理
    txt = txt.split(":")[0]  # 截取ip地址，删除端口信息
    # 正则匹配
    pattern = "^((2(5[0-5]|[0-4]\d))|[0-1]?\d{1,2})(\.((2(5[0-5]|[0-4]\d))|[0-1]?\d{1,2})){3}$"
    if re.match(pattern=pattern, string=txt) == None:
        return False
    return True


def format_path(path):
    '''
    处理路径信息
    :param path:
    :return: str
    '''
    if "//" in path:
        path = path.replace("//", "/")
        path = path.replace(" ", "")
    return path


def format_req(dic):
    '''
    将请求包信息格式化输出
    :param dic: 基础数据 dict
    :return: str
    '''
    # 定义
    result = ""
    payload = ""
    path = ""
    url = ""
    # 初始化
    result = dic['type'].upper()
    path = dic['path'].replace("$payload$", dic['payload'])
    url = dic['url']
    if dic['type'].lower() == "get":  # GET类型
        payload = dic['payload']
        result += " " + path + r"?" + payload + r" HTTP/1.1\r\n"  # 请求路径
    elif dic['type'].lower() == "post":  # POST类型
        payload = dic['body']
        result += " " + path + r" HTTP/1.1\r\n"  # 请求路径
    # Host值
    if Get.get_port(dic['url']) != "":  # Host中存在端口时
        result += "Host: " + Get.get_host(dic['url']) + ":" + Get.get_port(dic['url']) + r"\r\n"
    else:
        result += "Host: " + Get.get_host(dic['url']) + r"\r\n"
    # 请求头信息
    for key, value in dic['header'].items():
        result += key + ": "
        result += value + r"\r\n"
    # print(result)
    # print(dic)
    # 请求payload
    if dic['type'].lower() == "post":
        result += r"\r\n"
        result += dic['payload']

    return result


def format_res(response):
    '''
    将返回包结果格式化输出
    :param response:
    :return: str
    '''
    # 头部信息
    result = "HTTP/1.1 " + str(response.status_code) + r"\r\n"
    # 返回报头信息
    for key, value in response.headers.items():
        result += key + ": "
        result += value + r"\r\n"
    # 返回报文内容body
    result += r"\r\n"
    try:
        result += str(json.loads(response.text))  # 针对返回内容为json数据进行修改
    except:  # 若json转换出错时，即返回内容不为json数据
        text = response.text
        text = text.replace("'", "\'")
        text = text.replace('"', '\"')
        result += text
    # 特殊情况处理
    if '<div class=\"title\"><h1>Burp Suite Professional</h1></div>' in result:  # 存在抓包代理返回报错时
        result = "Burp Suite抓包报错，无法访问目标站点"
    return result


def format_payload(dic, now):
    '''
    1. 替换payload中的$type$、$ip$信息
    2. 将payload写入请求内容中
    :param dic:
    :param now: 当前的编号
    :return: body,header,body,url
    '''
    header = dic['header']  # 请求头
    body = ""  # post请求体
    url = ""  # 目标url
    ldap_rmi = ""  # ldap或rmi地址
    # print(dic)
    # 数据处理
    url = dic['url'].replace(" ", "")
    if 'rmi' in ldap_rmi:
        ldap_rmi = dic['rmi']
    elif dic['ldap_rmi'] != "":
        ldap_rmi = dic['ldap_rmi']
    else:
        ldap_rmi = dic["ldap"]
    # 替换$payload$
    url = url.replace("$payload$", dic['payload'])
    body = dic['body'].replace("$payload$", dic['payload'])
    # 替换$ip$
    url = url.replace("$ip$", now + ldap_rmi)
    body = body.replace("$ip$", now + ldap_rmi)
    # 替换$type$
    if "rmi" in dic:
        url = url.replace("$type$", "rmi")
        body = body.replace("$type$", "rmi")
    else:
        url = url.replace("$type$", "ldap")
        body = body.replace("$type$", "ldap")
    return body, header, body, url


def format_result(create_time, url, payload, req, http_type, ldap_rmi, res):
    '''
    :param create_time: 发包时间,int
    :param url: 目标URL,str
    :param payload: 攻击载荷,str
    :param req: 请求报文,str
    :param res: 返回包,str
    :param http_type: 请求类型,str
    :param ldap_rmi: LDAP或RMI地址
    :return: str
    '''
    result = ""
    # 格式化
    url = url.replace('"', r'\"')
    payload = payload.replace('"', r'\"')
    req = req.replace('"', r'\"')
    res = res.replace('"', r'\"')
    # 发包时间
    result = r'''<script class='web-vulns'>webVulns.push({"create_time":''' + str(create_time)
    # 目标url
    result += r''',"detail":{"addr":"''' + url
    # fastjson/jackson payload
    result += r'''","payload":"''' + payload
    # 请求包
    result += r'''","snapshot":[["''' + req
    # 返回包
    result += r'''","''' + res
    # 请求类型
    result += r'''"]],"extra":{"param":{"key":"''' + str(http_type).upper()
    # ldap地址
    result += r'''","ldap":"''' + ldap_rmi
    result += r'''","value":""}}},"ldap":"''' + ldap_rmi
    # 目标url
    result += r'''","target":{"url":"''' + url
    # ldap地址
    result += r'''","params":[{"ldap":"''' + ldap_rmi
    # 请求类型
    result += r'''","path":["''' + str(http_type).upper() + r'''"]}]}})</script>'''
    return result


def format_result_dnslog(data):
    '''
    :data: [{"dnslog":"xxx","ip":"xxx","time":"xxx"},xxx]
    :return: <tr><td>233.2357o713p27f4mxjk0k07js744929818d.oaste.me</td><td>46.232.120.227</td><td>2020-12-01 11:21:57.33</td></tr>
    '''
    # 定义
    result = ""
    # 读取信息
    for sub_dnslog in data:
        # 域名
        result += "<tr><td>" + sub_dnslog['dnslog'] + "</td>"
        # IP
        result += "<td>" + sub_dnslog['ip'] + "</td>"
        # 发包时间
        result += "<td>" + sub_dnslog['time'] + "</td>"
    return result


def output_dnslog(in_path="template/dnslog.html", filename="", result_data=""):
    '''
        输出检测结果,保存至result文件夹
        :param in_path: 模板路径 str
        :param filename: 结果文件名 str
        :param result_data: 结果 str
        :return: bool
        '''
    tmp = ""
    # 检测文件名是否包含.html后缀
    if ".html" not in filename:  # 不含.html时
        filename += ".html"  # 追加后缀
    # 检测文件夹是否存在
    if os.path.exists("result") == False:  # 不存在时
        os.mkdir("result")  # 创建文件夹
    # 检测模板是否存在
    if os.path.exists(in_path) == False:  # 不存在时
        print("[!] 模板" + in_path + "识别失败")  # 报错消息
        sys.exit()
    else:  # 已存在时
        with open(in_path, "r", encoding="utf-8") as fp:  # 读取模板数据
            tmp = fp.read()
    # 检测结果是否已存在
    if os.path.exists("result/" + filename) == True:  # 已存在时
        data = result_data  # 新增数据
        # 读取原有数据
        with open("result/" + filename, "r", encoding="utf-8") as fp:  # 读取
            tmp = fp.read()
        # 写入新数据
        data = tmp.replace("<!--Data-->", result_data + "<!--Data-->")  # 模板数据 + 新增数据
        with open("result/" + filename, "w", encoding="utf-8") as fp:  # 追加
            fp.write(data)
    else:  # 不存在时
        data = tmp.replace("<!--Data-->", result_data + "<!--Data-->")  # 模板数据 + 新增数据
        with open("result/" + filename, "w", encoding="utf-8") as fp:  # 新建
            fp.write(data)


def output(in_path="template/report.html", filename="", result_data=""):
    '''
    输出检测结果,保存至result文件夹
    :param in_path: 模板路径 str
    :param filename: 结果文件名 str
    :param result_data: 结果 str
    :return: bool
    '''
    tmp = ""
    # 检测文件名是否包含.html后缀
    if ".html" not in filename:  # 不含.html时
        filename += ".html"  # 追加后缀
    # 检测文件夹是否存在
    if os.path.exists("result") == False:  # 不存在时
        os.mkdir("result")  # 创建文件夹
    # 检测模板是否存在
    if os.path.exists(in_path) == False:  # 不存在时
        print("[!] 模板" + in_path + "识别失败")  # 报错消息
        sys.exit()
    else:  # 已存在时
        with open(in_path, "r", encoding="utf-8") as fp:  # 读取模板数据
            tmp = fp.read()
    # 检测结果是否已存在
    if os.path.exists("result/" + filename) == True:  # 已存在时
        data = result_data  # 新增数据
        with open("result/" + filename, "a+", encoding="utf-8") as fp:  # 追加
            fp.write(data)
    else:  # 不存在时
        data = tmp + result_data  # 模板数据 + 新增数据
        with open("result/" + filename, "w", encoding="utf-8") as fp:  # 新建
            fp.write(data)


if __name__ == '__main__':
    print(format_result_dnslog([{'ip': '46.232.120.227', 'time': '2023-08-18 10:13:38',
                                 'dnslog': '123.2357o713p27f4mxjk0k07js744929818d.oast.me'},
                                {'ip': '46.232.120.227', 'time': '2023-08-18 10:13:38',
                                 'dnslog': '233.2357o713p27f4mxjk0k07js744929818d.oast.me'}]))

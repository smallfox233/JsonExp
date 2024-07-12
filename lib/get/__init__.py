# 作者：小狐狸FM
# 版本：2023.08.17
import sys
import locale
import datetime,time
from urllib.parse import urlparse

def get_time_stamp(data):
    # 保留时间的整数部分
    data = data.split(".")[0]
    # if len(data.split(".")[-1])>6: #毫秒中超过6位，无法识别
    #     data = data[:-(len(data.split(".")[-1]) - 6):] #保留小数点后6位
    # print(data)
    try:
        utct_date1 = datetime.datetime.strptime(data, "%Y-%m-%dT%H:%M:%S")  # 2020-12-01 03:21:57
        local_date = utct_date1 + datetime.timedelta(hours=8)  # 加上时区
        result = datetime.datetime.strftime(local_date,"%Y-%m-%d %H:%M:%S")#2020-12-01 11:21:57
    except:
        print("时间识别失败")
        return
    return result.strip("0")

def get_host(url):
    '''
    获取url中的域名或ip信息
    :param url:
    :return:
    '''
    tmp = ""
    tmp = url
    # 删除协议头部
    tmp = tmp.replace("http://", "")
    tmp = tmp.replace("https://", "")
    tmp = tmp.replace("ftp://", "")
    # 删除路径信息
    tmp = tmp.split("/")[0]
    # 删除端口及其路径信息
    tmp = tmp.split(":")[0]
    return tmp

def get_port(url):
    '''
    获取url中请求端口信息
    :param url:
    :return:
    '''
    tmp = ""
    tmp = url
    # 删除协议头部
    tmp = tmp.replace("http://", "")
    tmp = tmp.replace("https://", "")
    tmp = tmp.replace("ftp://", "")
    # 删除路径信息
    tmp = tmp.split("/")[0]
    # 删除域名/ip信息
    tmp = tmp.split(":")[-1]
    # 无端口时
    if tmp == get_host(url):
        tmp = ""
    return tmp

def get_path(url):
    '''
    获取url中的路径信息（包含请求的参数及值）
    :param url:
    :return:
    '''
    # 定义
    tmp = ""
    tmp = url
    result = ""
    # url处理
    parsed_url = urlparse(tmp)
    result = parsed_url.path
    return result
def get_req(dic, line):
    '''
    获取请求包中每行的信息1
    :param dic:
    :param line:
    :return: dict()
    '''
    result = dict()  # 结果
    result = dic  # 复制字典
    if line == '':  # 若为空时，取消后续操作
        return result
    if 'POST' in str(line):  # POST类型请求时
        line = line.replace("POST", "")
        line = line.replace("HTTP/1.0", "")
        line = line.replace("HTTP/1.1", "")
        line = line.replace("HTTP/1.2", "")
        result['type'] = 'post'
        result['path'] = get_path(line)  # 路径获取
    elif 'GET' in str(line):  # GET类型请求时
        line = line.replace("GET", "")
        line = line.replace("HTTP/1.0", "")
        line = line.replace("HTTP/1.1", "")
        line = line.replace("HTTP/1.2", "")
        result['type'] = 'get'
        result['path'] = get_path(line)  # 路径获取
    elif 'Host:' in str(line):  # 获取IP及端口
        line = line.replace("Host: ", "")
        result['host'] = get_host(line)
        result['port'] = get_port(line)
    else:  # 获取请求头
        result['header'][line.split(": ")[0]] = line.split(": ")[-1]
    # print()
    # print(result)
    # print()
    # url拼接
    result['url'] = dic['protocol'] + "://" + result['host'] + ":" + result['port'] + result['path']
    # print(line)
    # print(result)
    return result

def get_dnslog(data):
    '''
    :data: [{'protocol',xxxxx},{'protocol': '协议类型', 'unique-id': '2357o713p27f4mxjk0k07js744929818d', 'full-id': '2332357o713p27f4mxjk0k07js744929818d', 'raw-request': '请求', 'raw-response': '回包', 'remote-address': 'IP地址', 'timestamp': '时间'}]
    :return: [{"dnslog":"xxx","ip":"xxx","time":"xxx"},xxx]
    '''
    result = []
    # print()
    # print(data)
    # print()
    for line in data:
        tmp = dict()
        tmp['ip'] = line["remote-address"]
        tmp['time'] = get_time_stamp(line["timestamp"])
        if line['full-id'] == line["unique-id"]:
            continue
        # dnslog处理
        if "_" == line['full-id'].split(".")[0]: #跳过下划线开头的无效数据
            continue
        # tmp['dnslog'] = line['full-id'].replace(line['unique-id'],"") #获取最左侧子域名
        # tmp['dnslog'] += "." + line['unique-id'] #拼接子域名
        tmp['dnslog'] = line['full-id'] + "." + "oast.me"  # 拼接主域名

        result.append(tmp)
    # print(result)
    # sys.exit()
    return result



if __name__ == '__main__':
    print(get_path("http://127.0.0.1:8090/123"))
    # print(get_time_stamp("2023-08-18T02:13:38.476037479Z"))
    # data = [{'protocol': 'http', 'unique-id': '2357o713p27f4mxjk0k07js744929818d', 'full-id': '1232357o713p27f4mxjk0k07js744929818d', 'raw-request': 'GET / HTTP/1.1\r\nHost: 1232357o713p27f4mxjk0k07js744929818d.oast.me\r\nAccept: */*\r\nAccept-Encoding: gzip, deflate\r\nUser-Agent: python-requests/2.31.0\r\n\r\n', 'raw-response': 'HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html; charset=utf-8\r\nServer: oast.me\r\nX-Interactsh-Version: 1.1.5\r\n\r\n<html><head></head><body>d818929447sj70k0kjxm4f72p317o7532321</body></html>', 'remote-address': '46.232.120.227', 'timestamp': '2023-08-18T02:13:38.295664193Z'}, {'protocol': 'http', 'unique-id': '2357o713p27f4mxjk0k07js744929818d', 'full-id': '2332357o713p27f4mxjk0k07js744929818d', 'raw-request': 'GET / HTTP/1.1\r\nHost: 2332357o713p27f4mxjk0k07js744929818d.oast.me\r\nAccept: */*\r\nAccept-Encoding: gzip, deflate\r\nUser-Agent: python-requests/2.31.0\r\n\r\n', 'raw-response': 'HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html; charset=utf-8\r\nServer: oast.me\r\nX-Interactsh-Version: 1.1.5\r\n\r\n<html><head></head><body>d818929447sj70k0kjxm4f72p317o7532332</body></html>', 'remote-address': '46.232.120.227', 'timestamp': '2023-08-18T02:13:38.476037479Z'}]
    # print(get_dnslog(data))

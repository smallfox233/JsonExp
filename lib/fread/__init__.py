# 作者：小狐狸FM
# 版本：2023.08.17
import os
from lib.get import *
from lib.format import *

def fread_url(path):
    '''
    批量读取文件中的url信息，文件必须一行一个url
    :param path:
    :return:
    '''
    tmp = ""
    # 检测文件是否已存在
    if os.path.exists(path) == False:
        print("文件" + path + "不存在")
        sys.exit()
    # 读取
    with open(path, "r", encoding='utf-8') as fp:
        tmp = fp.read()
    # 分行
    result = list(tmp.split("\n"))
    # 删除注释
    for i in range(len(result)):
        result[i] = result[i].replace(" ", "")
        result[i] = result[i].split("#")[0]
    return result

def fread_payload(path='template/fastjson.txt'):
    '''
    读取payload内容，#为注释符号
    :param path:
    :return: list
    '''
    tmp = ""
    # 检测文件是否已存在
    if os.path.exists(path) == False:
        print("文件" + path + "不存在")
        sys.exit()
    # 读取
    with open(path, "r", encoding='utf-8') as fp:
        tmp = fp.read()
    # 分行
    result = list(tmp.split("\n"))
    # 删除注释
    for i in range(len(result)):
        result[i] = result[i].replace(" ", "")
        result[i] = result[i].split("#")[0]
    return result

def fread_request(dic):
    '''
    读取请求包的内容
    :param dic:
    :return: dict()
    '''
    tmp = ""  # 临时
    result = dict()  # 结果
    result = dic  # 复制字典
    flag = False  # 标识当前行是否为post的body信息
    # 检测文件是否已存在
    if os.path.exists(dic['request']) == False:
        print("文件" + dic['request'] + "不存在")
        sys.exit()
    # 读取文件
    with open(dic['request'], "r", encoding='utf-8') as fp:
        tmp = fp.read()
        # 删除前面的空白符
        tmp = tmp.lstrip()
        # 删除结尾空白符
        tmp = tmp.rstrip()
    # 分行
    tmp = list(tmp.split("\n"))
    # 读取目标信息
    # print()
    # print(tmp)
    # print()
    for line in tmp:
        if line == '':  # 为空时
            flag = True
            continue
        elif flag == False:  # 为请求头信息时
            # 读取信息
            result = get_req(result, line)
        else:  # 为body信息时
            result['body'] = line
    # 数据处理
    result['path'] = format_path(result['path'])
    # 设置目标
    if '$payload$' not in result['path']:
        if result['port']!="": #host中存在端口时
            result['url'] = result['protocol'] + "://" + result['host'] + ":" + result['port'] + result['path']
        else: #host中不存在端口时
            result['url'] = result['protocol'] + "://" + result['host'] + result['path']
    # 设置host
    result['host'] = get_host(result['url'])
    # print(result)
    # 替换内容
    return result

def fread_user_agent(path='/template/user-agent.txt'):
    '''
    读取user-agent文件，转换为列表存储
    '''
    # 定义
    result = []
    # 读取
    with open(path,'r') as fp:
        result = fp.read().split("\n")
    return result


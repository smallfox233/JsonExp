# 作者：小狐狸FM
# 版本：2023.07.12
# 项目: https://github.com/smallfox233/JsonExp
import argparse
import sys
from lib.check import *
from lib.interactsh import *

def test():
    '''
    单元测试
    '''
    oob = Interactsh()
    dnslog,flag = oob.build_request()

    print(dnslog,flag)
    # requests.get(dnslog)
    # print(oob.verify(flag))
    pass
# test()




if __name__ == '__main__':
    '''
    dic不能初始化的属性如下:
    request
    rmi
    ldap
    '''
    # 定义
    dic_origin = dict()
    dic_origin['header'] = dict()  # 请求头
    dic_origin['path'] = ""  # 访问的站点路径
    dic_origin['host'] = ""  # 目标ip或域名
    dic_origin['body'] = ""  # post请求体
    dic_origin['port'] = ""  # 目标端口
    dic_origin['dnslog'] = False  # 是否申请dnslog地址
    dic_origin['timeout'] = 10 # 请求超时时长
    dic_origin['ldap_rmi'] = "" #report.html中的ldap_rmi参数
    dic_origin['payload'] = "" # 需要发送的payload
    dic_origin['type'] = "post"  # 请求类型
    dic_origin['file'] = "template/fastjson.txt"  # payload路径
    dic_origin['protocol'] = "http"  # 请求协议类型
    dic_origin['proxy'] = {'http':'','https':''} # 代理设置
    user_agent = Fread.fread_user_agent(os.getcwd()+'/template/user-agent.txt') # 请求列表
    # 请求头设置，请求头添加Content-Type属性将会发包失败
    dic_origin['header']['User-Agent'] = user_agent[random.randint(0,len(user_agent)-1)] #随机选取一个头
    # print(dic_origin['header']['User-Agent'])
    # 提示
    arg = argparse.ArgumentParser(description="功能：批量检测是否存在fastjson/jackson漏洞（未使用-f时，默认检测fastjson）",
                                  prog="-u [目标] -l [LDAP地址]\nusage: -uf [url.txt] -l [LDAP地址]\nusage: -req [request.txt] -l [LDAP地址]\n\n")
    # 输入
    arg.add_argument('-uf', '--urlfile', help="[可选] 指定批量目标（文本路径）\n")
    arg.add_argument('-u', '--url', help="[可选] 指定目标\n\n")
    arg.add_argument('-req', '--request', help="[可选] 指定请求包，默认为http协议发送请求\n")
    arg.add_argument('-to', '--timeout', help="[非必须] 指定请求超时时长，默认为10秒\n")
    arg.add_argument('-f', '--file', help="[非必须] 指定payload（文本路径），默认为template/fastjson.txt\n")
    arg.add_argument('-t', '--type', help="[非必须] 指定请求类型为get或post，默认为post\n")
    arg.add_argument('-c', '--cookie', help="[非必须] 设置cookie值，默认为空\n  ")
    arg.add_argument('-l', '--ldap', help="[可选] 指定ldap地址，ip:端口/路径 或 域名:端口/路径\n")
    arg.add_argument('-r', '--rmi', help="[可选] 指定rmi地址，ip:端口 或 域名:端口\n")
    arg.add_argument('-pro', '--protocol', help="[可选] 指定请求包的协议类型，需结合-req参数使用，默认为http\n")
    arg.add_argument('-proxy', '--proxy', help="[可选] 设置代理，例：--proxy http://127.0.0.1:8080\n")
    arg.add_argument('-dnslog', '--dnslog', help="[可选] 申请dnslog地址进行检测（需挂全局代理），例：-u 目标 --dnslog true\n")
    # 参数解析
    args = arg.parse_args()
    # 参数检测
    if args.url == None and args.urlfile == None and args.request == None:
        print("\n[!] 缺少-u参数、-uf参数、-req指定目标")
        sys.exit()
    if args.ldap == None and args.rmi == None and args.dnslog ==None:
        print("\n[!] 请使用-l指定ldap地址，-r指定rmi地址，或--dnslog申请资源（需挂全局代理）")
        sys.exit()
    if (args.ldap != None and args.rmi != None) or (args.ldap != None and args.dnslog != None) or (args.rmi != None and args.dnslog != None):
        print("\n[!] 参数-l、参数-r和-dnslog参数请选择其一")
        sys.exit()
    if args.proxy != None and ("http://" not in str(args.proxy)) and ("https://" not in str(args.proxy)):
        print("\n[!] --proxy代理参数需使用http://或https://开头")
        sys.exit()
    # 赋值
    if args.urlfile != None:  # 存在该参数时
        dic_origin['urlfile'] = str(args.urlfile)  # 批量目标url文本路径
    if args.url != None:  # 存在该参数时
        dic_origin['url'] = str(args.url)  # 目标url
        dic_origin['host'] = Get.get_host(dic_origin['url']) #目标ip或域名
        dic_origin['path'] = Format.format_path(Get.get_path(dic_origin['url'])) #目标路径
    if args.request != None:  # 存在该参数时
        dic_origin['request'] = str(args.request)  # 目标请求包
    if args.file != None:  # 存在该参数时
        dic_origin['file'] = str(args.file)  # payload文本路径
    if args.type != None:  # 存在该参数时
        dic_origin['type'] = str(args.type).lower()  # http请求类型
    if args.ldap != None:  # 存在该参数时
        dic_origin['ldap'] = str(args.ldap)  # ldap地址
    if args.rmi != None:  # 存在该参数时
        dic_origin['rmi'] = str(args.rmi)  # rmi地址
    if args.dnslog != None and str(args.dnslog).lower()=="true":  # 存在该参数时
        dic_origin['dnslog'] = True  # dnslog地址
    if args.protocol != None:  # 存在该参数时
        dic_origin['protocol'] = str(args.protocol).lower().replace("://","")  # 请求协议类型
    if args.cookie != None:  # 存在该参数时
        dic_origin['header']['Cookie'] = str(args.cookie)  # cookie值
    if args.timeout != None:  # 存在该参数时
        dic_origin['timeout'] = int(args.timeout)
    if args.proxy != None:  # 存在该参数时
        dic_origin['proxy']['http'] = str(args.proxy)
        dic_origin['proxy']['https'] = str(args.proxy)
    # print(dic_origin)
    # 传参检测
    if len(sys.argv) == 1:  # 未传入参数时
        arg.print_help()  # 打印帮助信息
        sys.exit()
    # 实例化类
    c = Check(dic_origin)
    # 发包
    if 'url' in dic_origin:  # 单个发包
        print("[+] 单个URL检测中......")
        c._check()
    if 'request' in dic_origin:  # 根据请求包发包
        print("[+] 导入请求包" + dic_origin['request'] + "中......")
        print("[+] 未使用-pro或--protocol参数指定协议类型时，默认采用http")
        c._check_request()
    if 'urlfile' in dic_origin:  # 批量发包
        print("[+] 批量检测中......")
        c._check_multiple( Fread.fread_url(dic_origin['urlfile']))

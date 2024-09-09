import argparse
import re
import requests
from multiprocessing import Pool, Manager
from concurrent.futures import ThreadPoolExecutor
import ipaddress

banner=r'''
░█░░░▀█▀░█░█░▀█▀░█░█░░░░░█▀▀░█▀▄
░█░░░░█░░█░█░░█░░░█░░░░░░▀▀█░█▀▄
░▀▀▀░▀▀▀░▀▀▀░░▀░░░▀░░▀▀▀░▀▀▀░▀▀░
'''

requests.packages.urllib3.disable_warnings()



headers = {"User-Agent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
           "Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",}

executor = ThreadPoolExecutor()
pathlist=['/autoconfig','/beans','/configprops','/dump','/health','/info','/mappings','/metrics','/trace','/auditevents','/caches','/conditions','/docs','/env','/flyway','/httptrace','/intergrationgraph','/jolokia','/logfile','/loggers','/liquibase','/refresh','/scheduledtasks','/sessions','/shutdown','/threaddump',]

def getinfo(filepath):
    fr = open(filepath, 'r')
    ips=fr.readlines()
    fr.close()
    return ips

def savemessage(result):
    if result:
        fw=open('result.txt','a')
        fw.write(result+'\n')
        fw.close()

def check(ip):
    url= str(ip)
    try:
        r = requests.get(url+ '/404', headers=headers,timeout=10,verify=False)
        if r.status_code==404 or r.status_code==403:
            if 'Whitelabel Error Page' in r.text  or 'There was an unexpected error'in r.text:
                print("[+]检测到使用Spring Boot框架: {}".format(url))
                savemessage( "[+]检测到使用Spring Boot框架: {}".format(url))
                executor.submit(Actuator_vuln,url)
                return 1
    except requests.exceptions.ConnectTimeout:
        return 0.0
    except requests.exceptions.ConnectionError:
        return 0.1


def springSB(ip,q):
    print('-------> {}'.format(ip))
    check(ip)
    q.put(ip)

def jolokiavuln(url):
    url_tar = url + '/jolokia/list'
    r = requests.get(url_tar, headers=headers, verify=False)
    if r.status_code == 200:
        print("[success]检测到存在 jolokia 未授权访问,路径为：{}".format(url_tar))
        savemessage("[success]检测到存在 jolokia 未授权访问,路径为：{}".format(url_tar))
        if 'reloadByURL' in r.text:
            print("[success]检测到开启了 jolokia(reloadByURL) 可尝试进行XXE/RCE测试,路径为：{}".format(url_tar))
            savemessage("[success]检测到开启了 jolokia(reloadByURL) 可尝试进行XXE/RCE测试,路径为：{}".format(url_tar))
        if 'createJNDIRealm' in r.text:
            print("[success]检测到开启了 jolokia(createJNDIRealm) 可尝试进行JNDI注入RCE测试,路径为：{}".format(url_tar))
            savemessage("[success]检测到开启了 jolokia(createJNDIRealm) 可尝试进行JNDI注入RCE测试,路径为：{}".format(url_tar))


def env_vuln(url):
    url_tar = url + '/env'
    r = requests.get(url_tar, headers=headers, verify=False)
    if r.status_code == 200:
        print("[success]检测到存在 env 未授权访问,路径为：{}".format(url_tar))
        savemessage("[success]检测到存在 env 未授权访问,路径为：{}".format(url_tar))
        if 'spring.cloud.bootstrap.location' in r.text:
            print("[success]检测到开启了 env(spring.cloud.bootstrap.location) 可尝试进行环境属性覆盖RCE测试,路径为：{}".format(url_tar))
            savemessage("[success]检测到开启了 env(spring.cloud.bootstrap.location) 可尝试进行环境属性覆盖RCE测试,路径为：{}".format(url_tar))
        if 'eureka.client.serviceUrl.defaultZone' in r.text:
            print("[success]检测到开启了 env(eureka.client.serviceUrl.defaultZone) 可尝试进行XStream反序列化RCE测试,路径为：{}".format(url_tar))
            savemessage("[success]检测到开启了 env(eureka.client.serviceUrl.defaultZone) 可尝试进行XStream反序列化RCE测试,路径为：{}".format(url_tar))

def actuator_vuln(url):
    key=0
    env_vuln(url)
    jolokiavuln(url)
    for i in pathlist:
        url_tar = url+i
        r = requests.get(url_tar, headers=headers, verify=False)
        if r.status_code==200:
            print("[success]检测到存在 {} 未授权访问,路径为：{}".format(i.replace('/',''),url_tar))
            savemessage("[success]检测到存在 {} 未授权访问,路径为：{}".format(i.replace('/',''),url_tar))
            key=1
    return key

def env_Vuln(url):
    url_tar = url + '/actuator/env'
    r = requests.get(url_tar, headers=headers, verify=False)
    if r.status_code == 200:
        print("[success]检测到存在 env 未授权访问,路径为：{}".format(url_tar))
        savemessage("[success]检测到存在 env 未授权访问,路径为：{}".format(url_tar))
        if 'spring.cloud.bootstrap.location' in r.text:
            print("[success]检测到开启了 env(spring.cloud.bootstrap.location) 可尝试进行环境属性覆盖RCE测试,路径为：{}".format(url_tar))
            savemessage("[success]检测到开启了 env(spring.cloud.bootstrap.location) 可尝试进行环境属性覆盖RCE测试,路径为：{}".format(url_tar))
        if 'eureka.client.serviceUrl.defaultZone' in r.text:
            print("[success]检测到开启了 env(eureka.client.serviceUrl.defaultZone) 可尝试进行XStream反序列化RCE测试,路径为：{}".format(url_tar))
            savemessage("[success]检测到开启了 env(eureka.client.serviceUrl.defaultZone) 可尝试进行XStream反序列化RCE测试,路径为：{}".format(url_tar))
        headers["Cache-Control"]="max-age=0"
        rr = requests.post(url+'/actuator/restart', headers=headers, verify=False)
        if rr.status_code == 200:
            print("[success]检测到开启了 env(restart)可尝试进行H2 RCE测试,路径为：{}".format(url+'/actuator/restart'))
            savemessage("[success]检测到开启了 env(restart)可尝试进行H2 RCE测试,路径为：{}".format(url+'/actuator/restart'))

def SpringSB(url):
    env_Vuln(url)
    jolokiavuln(url+'/actuator')
    for i in pathlist:
        url_tar = url+'/actuator'+i
        r = requests.get(url_tar, headers=headers, verify=False)
        if r.status_code==200:
            print("[success]检测到存在 {} 未授权访问,路径为：{}".format(i.replace('/',''),url_tar))
            savemessage("[success]检测到存在 {} 未授权访问,路径为：{}".format(i.replace('/', ''), url_tar))


def Actuator_vuln(url):
    try:
        if actuator_vuln(url)==0:
            SpringSB(url)
    except:
        pass
def poolmana(ips):
    p = Pool(10)
    q = Manager().Queue()
    for i in ips:
        i=i.replace('\n','')
        p.apply_async(springSB, args=(i,q,))
    p.close()
    p.join()
    print('检索完成------->\n请查看当前路径下文件：result.txt')


def testTest(filepath):
    ips=getinfo(filepath)
    poolmana(ips)


if __name__ == '__main__':
    print(banner)
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--url", dest='url',help="单目标扫描")
    parser.add_argument("-f", "--file", dest='file', help="从文件加载目标")

    args = parser.parse_args()
    if args.url:
        res=check(args.url)
        if res==1:
            pass
        elif res==0.0:
            print("[-]网络连接异常")
        elif res==0.1:
            print("[x]目标拒绝访问，无法连接")
        else:
            print("[!!]人家tm压根就没用Spring Boot,你干个锤子???")
    elif args.file:
        testTest(args.file)

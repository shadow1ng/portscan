# encoding:utf-8
import nmap
import argparse
import datetime
import threading
import re
import os
import time
import subprocess
from IPy import IP
import re
from queue import Queue
from urllib.parse import urlparse
import socket
import platform
import requests
requests.packages.urllib3.disable_warnings()
limitNumber = 100
lock = threading.Lock()
webqueue = Queue()
LOGFILE="result.txt"


class PortScan(threading.Thread):
    def __init__(self, queue,level,ports):
        threading.Thread.__init__(self)
        self._queue = queue
        self.level=level
        self.ports=ports

    def run(self):
        while not self._queue.empty():
            scan_ip = self._queue.get()
            time.sleep(0.01)
            try:
                domain=None
                if(bool(re.search('[a-zA-Z]', scan_ip))):
                    if "://" in scan_ip:
                        domain=urlparse(scan_ip).netloc
                    else:
                        domain=scan_ip
                    scan_ip=(socket.gethostbyname(domain))
            except Exception as e:
                continue

            try:
                openports = self.MassScan(scan_ip,self.ports)
                log("port",scan_ip,openports)
                if len(openports)>0:
                    service = self.NmapScan(scan_ip, openports)
                    if domain:
                        log("domain",scan_ip,service,domain=domain)
                    else:
                        log("service",scan_ip,service)

            except Exception as e:
                print(e)
                pass

    #run_masscan
    def MassScan(self,scan_ip,porsfw):
        try:
            tmp_ports=[]
            ports = []
            sys = platform.system()
            if sys == "Windows":
                command = 'masscan.exe {} -p {} --rate 1000 --wait 1'.format(scan_ip,porsfw)
            else:
                command = './masscan {} -p {} --rate 1000 --wait 1'.format(scan_ip,porsfw)
            print(command)
            child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
            while child.poll() is None:
                output = child.stdout.readline()
                line = str(output, encoding='utf-8').strip()
                # print(line)
                if "Discovered" in line:
                    print(line)
                    if re.findall(r'port (\d{1,5})/tcp',line):
                        port = re.findall(r'port (\d{1,5})/tcp',line)[0]
                        tmp_ports.append(port)
                    foundNumber = len(tmp_ports)
                    if int(foundNumber) > int(limitNumber):
                        os.kill(child.pid, 9)
                        print("有waf")
            if len(tmp_ports)>limitNumber:
                tmp_ports.clear()
            else:
                ports.extend(tmp_ports)
            return ports
        except Exception as e:
            print(e)

    #run_nmap
    def NmapScan(self,scan_ip,ports):
        service ={}
        nm = nmap.PortScanner()
        ports=(','.join(ports))
        try:
            ret = nm.scan(scan_ip,ports,arguments='-sS -Pn --version-all')#--open --version-all --host-timeout 20
            tcp=(ret['scan'][scan_ip]['tcp'])
            for port in tcp:
                if tcp[port]['name']:
                    service[port]=tcp[port]['name'].replace("sun-answerbook", "http")
                else:
                    service[port]="unknown"
            return service
        except Exception as e:
            print(e)
            pass

class HttpScan(threading.Thread):
    def __init__(self,queue):
        threading.Thread.__init__(self)
        self._queue = queue

    def gettile(self,ip,port, proxy=None, timeout=10):
        try:
            if int(port) == 443:
                url = "https://{}:{}".format(ip, port)
            else:
                url = "http://{}:{}".format(ip, port)
            headers = {
                'Connection': 'close',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.110 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Encoding': 'gzip, deflate, sdch, br',
                'Accept-Language': 'zh-CN,zh;q=0.8',
            }
                      
            if proxy:
                proxy = {'http': proxy,'https': proxy}
            # proxy = {'http': '127.0.0.1:8080','https': '127.0.0.1:8080'}

            req  = requests.get(url, headers=headers,proxies=proxy, timeout=timeout,verify=False)
            
            status = req.status_code
            if status == 400:
                url = "https://{}:{}".format(ip, port)
                req  = requests.get(url, headers=headers,proxies=proxy, timeout=timeout,verify=False)
                status = req.status_code
            
            code = re.search(r'<meta.*charset="?([\w|-]*)"?\s*/?>', req.text,re.IGNORECASE)
            if code:
                code = code.group(1)
            else:
                code = "utf-8"
            req.encoding=code
            
            title = re.search(r'<title>(.*)</title>', req.text,re.S)
            if title:
                title = title.group(1).strip().strip("\r").strip("\n")[:30]
            else:
                title = "None"
            banner = ''
            if 'Server' in req.headers:
                banner = req.headers['Server'][:20]
            log=("%-30s| %-6s| %-20s| %-30s" % (url, status, banner, title))
            lock.acquire()
            print(log)
            print("+---------------------------------------------------------------------------+")
            log_file = open(LOGFILE,'a',encoding='utf-8')
            log_file.write(log+"\n")
            log_file.close()
            lock.release()
        except Exception as e:
            # log=("%-30s| %-20s" % (url, e))
            # print(log)
            pass



    def run(self):
        time.sleep(0.01)
        while not self._queue.empty():
            try:
                queue_task = self._queue.get(timeout=0.5)
                task_host,task_port = queue_task.split(":")
                self.gettile(task_host,task_port)
            except:
                pass





def get_ip_list(ipin):
    ipdo=[]
    ip_list=[]
    if ',' in ipin:
        ipdo=ipin.split(',')
    else:
        ipdo.append(ipin)

    if '.txt' in ipin:
        ip_config = open(ipin,'r')
        for ip in ip_config:
            ip_list.extend(get_ip_list(ip.strip()))
        ip_config.close()
    else:
        for ipone in ipdo:
            if bool(re.search('[a-z]', ipone)):
                ip_list.append(ipone)
            elif '-' in ipone:
                if len(ipone)>20:
                    def ip2num(ip):
                        ips = [int(x) for x in ip.split('.')]
                        return ips[0]<< 24 | ips[1]<< 16 | ips[2] << 8 | ips[3]

                    def num2ip (num):
                        return '%s.%s.%s.%s' % ((num >> 24) & 0xff, (num >> 16) & 0xff, (num >> 8) & 0xff, (num & 0xff))

                    start ,end = [ip2num(x) for x in ipone.split('-')]
                    [ip_list.append(num2ip(num)) for num in range(start,end+1) if num & 0xff]
                else:
                    ipstr=ipone.split('-')
                    print(ipstr)
            elif '/' in ipone:
                net = IP(ipone)
                for x in net:
                    ip_list.append(str(x))
            else:
                ip_list.append(ipone)
    return list(set(ip_list))


def log(log_type,scan_ip,info,domain=None):
    lock.acquire()
    if log_type == "port":
        for port in info:
            output = "{}:{} open".format(scan_ip,port)
            webqueue.put(":".join([scan_ip,port]))
            print(output)
    elif log_type == "service":
        for port in info:
            output = '{}:{} is {}'.format(scan_ip,port,info[port])
            print(output)
            f = open(LOGFILE, 'a+', encoding='utf-8')
            f.write(str(output)+"\n")
    elif log_type == "domain":
        for port in info:
            output = '{}:{} {} is {}'.format(scan_ip,port,domain,info[port])
            webqueue.put(":".join([domain,str(port)]))
            print(output)
            f = open(LOGFILE, 'a+', encoding='utf-8')
            f.write(str(output)+"\n")
    lock.release()






def run_port(target,level,ports,nums):
    queue = Queue()
    threads = []
    try:
        ip_list = get_ip_list(target)
        for ip in ip_list:
            queue.put(ip)

        for i in range(nums):
            threads.append(PortScan(queue,level,ports))

        for t in threads:
            t.start()

        for t in threads:
            t.join()

    except Exception as e:
        print(e)
        pass



def run_http(webqueue,threadNum =100):
    threads = []
    for num in range(1,threadNum + 1):
        threads.append(HttpScan(webqueue))

    for t in threads:
        t.start()

    for t in threads:
        t.join()

#启用多线程扫描
def main(target,level,ports,nums):
    run_port(target,level,ports,nums)
    if level>0:
        run_http(webqueue)



if __name__ =='__main__':
    start_time = datetime.datetime.now()
    parser = argparse.ArgumentParser(usage='python3 dirscan.py --target [source urls file]')
    parser.add_argument("-t","--target", type=str, help="192.168.1.0/24 or ip or ips or file.")
    parser.add_argument("-p","--ports", type=str, default="1-65535")
    parser.add_argument("-n","--nums", type=int, default=10)
    parser.add_argument("-v","--level", type=int, help="-v 0 not run webtitle",default="1")
    parser.add_argument("-o","--output", type=str, help="outfile",default="result.txt")
    args = parser.parse_args()
    target = args.target
    ports=args.ports
    level=args.level
    nums=args.nums
    LOGFILE=args.output
    main(target,level,ports,nums)
    spend_time = (datetime.datetime.now() - start_time).seconds
    print('程序共运行了： ' + str(spend_time) + '秒')

# encoding:utf-8
import nmap
import argparse
import datetime
import threading
import requests
import re
import sys
import os
import time
import subprocess
from IPy import IP
import re
requests.packages.urllib3.disable_warnings()
from queue import Queue
limitNumber = 50
lock = threading.Lock()
final_domains = []
final_port={}


class PortScan(threading.Thread):
    def __init__(self, queue,level,porsfw):
        threading.Thread.__init__(self)
        self._queue = queue
        self.level=level
        self.porsfw=porsfw

    def run(self):

        while not self._queue.empty():
            scan_ip = self._queue.get()
            try:
                ports = portscan(scan_ip,self.porsfw)
                time.sleep(1)
                if int(self.level) >0:
                    if len(ports)>0:
                        Scan(scan_ip, ports)
                        print_result(scan_ip)

                else:
                    ports_result(scan_ip,ports)
            except Exception as e:
                print(e)
                pass
def ports_result(scan_ip,ports):
        f1 = open('./result.txt', 'a', encoding='utf-8')
        for port in ports:
            line={"port":scan_ip+":"+str(port),"service":""}
            f1.write(str(line)+"\n")
        f1.close()
def print_result(scan_ip):
    for i in final_port:
        if i ==scan_ip:
            f1 = open('./result.txt', 'a', encoding='utf-8')
            for port in final_port[i]:
                line={"port":scan_ip+":"+str(port),"service":final_port[i][port]}
                f1.write(str(line)+"\n")
            f1.close()

#调用masscan
def portscan(scan_ip,porsfw):
    try:
        tmp_ports=[]
        ports = []
        command = './masscan {} -p {} --rate 1000 --wait 1'.format(scan_ip,porsfw)
        child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
        while child.poll() is None:
            output = child.stdout.readline()
            line = str(output, encoding='utf-8').strip()
            if "Discovered" in line:

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
        print(scan_ip+" ports "+str(ports))
        return ports
    except Exception as e:
        print(e)

#调用nmap识别服务
def Scan(scan_ip,ports):
    service ={}
    nm = nmap.PortScanner()
    ports=(','.join(ports))
    try:
        start_time = datetime.datetime.now()
        ret = nm.scan(scan_ip,ports,arguments='-sS -Pn --version-all')#--open --version-all --host-timeout 20
        tcp=(ret['scan'][scan_ip]['tcp'])
        for port in tcp:
            if tcp[port]['name']:
                service[port]=tcp[port]['name'].replace("sun-answerbook", "http")
            else:
                service[port]="unknown"
    except Exception as e:
       print(e)
       pass
    finally:
        print(scan_ip+" service "+str(service))
        final_port[scan_ip] = service

#启用多线程扫描
def main(target,level,ports):
    queue = Queue()
    try:
        ip_list=get_ip_list(target)
        for final_ip in ip_list:
            queue.put(final_ip)
        threads = []
        thread_count = 5
        for i in range(thread_count):
            threads.append(PortScan(queue,level,ports))

        for t in threads:
            t.start()

        for t in threads:
            t.join()


    except Exception as e:
        print(e)
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
    return ip_list

if __name__ =='__main__':
    start_time = datetime.datetime.now()
    parser = argparse.ArgumentParser(usage='python3 dirscan.py --target [source urls file]')
    parser.add_argument("-t","--target", type=str, help="192.168.1.0/24 or ip or ips or file.")
    parser.add_argument("-p","--ports", type=str, default="1-65535")
    parser.add_argument("-v","--level", type=int, help="-v  skip nmap",default="1")
    args = parser.parse_args()
    urls_file = args.target
    ports=args.ports
    level=args.level

    main(urls_file,level,ports)
    spend_time = (datetime.datetime.now() - start_time).seconds
    print('程序共运行了： ' + str(spend_time) + '秒')
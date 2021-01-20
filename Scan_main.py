#!/bin/python
# -*- coding: utf-8 -*-
# Time: 2020/3/21 下午12:05

import queue
import IPy
import nmap

from Scan_list import Producer, get_list_from_redis
from Scan_tasks import https_scan
from Scan_config import *
from scapy.all import *

# 条件变量
con = threading.Condition(threading.Lock())


def nmap_ping(dst):
    nm = nmap.PortScanner()
    nm.scan(hosts=dst, arguments='-sP -6')
    if len(nm.all_hosts()) != 0:
        # 前缀
        prefix = 64
        # 目标IP
        dst_ip = IPy.IP(nm.all_hosts()[0])
        # 目标IP转二进制
        dst_ip_bin = dst_ip.strBin()
        # 提取网络位
        dst_ip_net = dst_ip_bin[:prefix]
        # 转换为16进制表示
        dst_ip_net = hex(int(dst_ip_net, 2)).replace('0x', '')
        dst_ips = ''
        for j in range(len(dst_ip_net)):
            if j % 4 == 0 and j != 0:
                dst_ips += ':'
            dst_ips += dst_ip_net[j]
        dst_ips += "::/%s" % prefix
        return dst_ips
    # 不可达返回0
    return 0


class Scan:
    def __init__(self, s, q, c):
        self._con = c
        self._queue = q
        self._scanRs = s

    def run(self):
        while True:
            while not self._queue.empty():
                ip = self._queue.get().decode()
                add_task(ip)
                time.sleep(0.1)

            self._con.acquire()
            self._con.notify()
            self._con.release()
            get_list_from_redis(self._scanRs, self._queue)
            time.sleep(10)


def add_task(host):
    res = https_scan.delay(host)
    print(res.ready)


def scan_main():
    try:
        Queue = queue.Queue()  # 待扫描队列

        dstIPs = nmap_ping(dstHost)
        if dstIPs:
            # 生成扫描列表
            greListProducer = Producer(Queue, dstIPs, ScanListRs, con)
            greListProducer.start()

            time.sleep(1)

            # 获取当前已生成的IP地址
            get_list_from_redis(ScanListRs, Queue)

            # 执行扫描阶段
            scan = Scan(ScanListRs, Queue, con)
            scan.run()
        else:
            print("主机不可达")
            os._exit(255)

    except Exception as e:
        print("ERROR:", e)
        os._exit(250)

if __name__ == '__main__':
    scan_main()

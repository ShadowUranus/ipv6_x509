#!/bin/python
# -*- coding: utf-8 -*-
# Time: 2020/5/16 下午2:47
import time

from scapy.all import *
from celery import Celery
from Scan_config import *
import random
import requests
import nmap

app = Celery("Scan_tasks", broker=broker, backend=backend)


@app.task
def https_scan(dst):
    # 随机加入正常HTTP请求
    if random.random() * 3 > 2:
        try:
            requests.get(url="https://{host}".format(host=dstHost))
        except:
            print("Connection Error")
    time.sleep(random.random() * 2)  # 扫描随机延时

    method = random.choice(['-sS', '-sA', '-Pn'])
    nm = nmap.PortScanner()
    nm.scan(hosts=dst, ports='443', arguments='{method} -6'.format(method=method))
    if len(nm.all_hosts()) == 0:
        ResListRs.set(dst, 'can_not_reach')
        ScanListRs.delete(dst)  # 将已扫描IP移除待扫描队列
        return dst + " can_not_reach"
    else:
        res = nm[nm.all_hosts()[0]]['tcp'][443]['state']

        if res == "open":
            ResListRs.set(dst, 'open')
            host_name = get_host_name(dst)
            if host_name == 0:
            	host_name = dst
            SuccessListRs.set(host_name, 'open')
            ScanListRs.delete(dst)  # 将已扫描IP移除待扫描队列
            return dst + " port_is_open"
        else:
            ResListRs.set(dst, 'port '+res)
            ScanListRs.delete(dst)  # 将已扫描IP移除待扫描队列
            return dst + " port " + res


# DNS反向解析
def get_host_name(ip6):
    try:
        return socket.gethostbyaddr(ip6)[0]
    except socket.herror:
        return 0

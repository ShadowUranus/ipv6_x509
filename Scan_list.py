#!/bin/python
# -*- coding: utf-8 -*-
# Time: 2020/3/17 下午4:48

import ipaddress
import random
import threading
import re
from Scan_config import *


def hex_to_bin(s):
    return bin(int(s, 16)).replace('0b', '')


def bin_to_hex(s):
    return hex(int(s, 2)).replace('0x', '')


def fix_(s, num):
    res = s
    while len(res) < num:  # 0补齐
        res = "0" + res
    return res


class Producer(threading.Thread):
    def __init__(self, q, d, s, c):  # 程序扫描队列，目标IP，Redis缓存队列，条件变量
        threading.Thread.__init__(self)
        self._con = c
        self._queue = q
        self._ScanListRs = s
        self.IPlist = ipaddress.IPv6Network(d)
        self.IPlist_num = self.IPlist.num_addresses  # 总IP数量
        self.IPlist_count = 0  # 已生成的IP数量
        self.prefix = str(d).replace(':/64', '')  # 前缀

    def run(self):
        while self.IPlist_count < self.IPlist_num:
            try:
                self._con.acquire()  # 获取锁1
                self.generate_list()  # 写入Redis缓存队列
                self.generate_eui64()
                self.generate_rand_part()
                print("Producer add 20 IPs to the pool.")
                print("Producer is waiting...")
                self._con.wait()  # 等待
                self._con.release()  # 释放锁1
            except InterruptedError as e:
                print(e)

    # 完全随机IPv6地址生成
    def generate_list(self):
        while self.IPlist_count < 10:  # 一次随机生成10个IP加入待扫描队列
            # 随机生成当前网段下目标IP, 并加入扫描队列
            random_ip = random.randint(0, self.IPlist_num)
            self._ScanListRs.set(str(self.IPlist[random_ip]), 'null')
            self.IPlist_count += 1
        self.IPlist_count = 0

    # EUI-64地址随机生成
    def generate_eui64(self):
        file = open("eui64.txt", "r")
        data = file.readlines()
        num = 0
        while num < 10:  # 一次随机生成10个IP
            rand_choice = random.randint(0, len(data))
            brand = data[rand_choice].strip()
            mac_2 = "".join([random.choice("0123456789ABCDEF") for i in range(6)])
            random_mac = brand + mac_2
            mac_bin = fix_(hex_to_bin(random_mac), 48)
            first, second = re.findall(".{24}", mac_bin)
            temp = first + hex_to_bin("ffee") + second
            half_2_bin = temp[:6]
            # 第7位取反
            if temp[6] == '0':
                half_2_bin += '1'
            else:
                half_2_bin += '0'
            half_2_bin += temp[7:]
            half_1 = self.prefix
            half_2 = ""
            temp = re.findall('.{16}', half_2_bin)
            for i in temp:
                half_2 += fix_(bin_to_hex(i), 4) + ":"
            g_ip = half_1 + half_2[:-1]
            self._ScanListRs.set(g_ip, 'null')
            num += 1

    # 部分随机ip生成
    def generate_rand_part(self):
        num = 0
        while num < 10:
            rand_part = "".join([random.choice("0123456789ABCDEF") for i in range(4)])
            rand_part += ":0:0:1"
            g_ip = self.prefix + rand_part
            self._ScanListRs.set(g_ip, 'null')
            num += 1


def get_list_from_redis(scan_list_redis, queue):
    # 获取当前已生成的IP地址
    scan_lists = scan_list_redis.keys()
    for ip in scan_lists:
        queue.put(ip)
    print("get all keys from Redis.")


def delete_log():
    for i in LogRedis.keys():
        LogRedis.delete(i)

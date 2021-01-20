#!/bin/python
# -*- coding: utf-8 -*-
# Time: 2020/3/21 下午3:16
import socket
from OpenSSL import SSL, crypto
from multiprocessing.pool import ThreadPool
from Scan_config import *

cert = None

pool = ThreadPool(20)


def do_connect(hostname, p, level):
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    context = SSL.Context(level)
    conn = SSL.Connection(context, s)
    conn.connect((hostname, p))
    conn.do_handshake()
    return conn.get_peer_cert_chain()


# 获取证书并下载
def get_certificate(hostname, num, port=443, file_path='./certs/', Thr=None):
    global cert
    try:
        cert = do_connect(hostname, port, SSL.SSLv23_METHOD)
    except Exception:
        try:
            cert = do_connect(hostname, port, SSL.TLSv1_1_METHOD)
        except Exception:
            try:
                cert = do_connect(hostname, port, SSL.TLSv1_2_METHOD)
            except Exception as e:
                if Thr:
                    print(Thr)
                    Thr.emit('Get {domain} Error: {err}'.format(domain=hostname, err=e))
                else:
                    print('Get {domain} Error:'.format(domain=hostname), e)
                return

    print(cert)
    try:
        cert_nums = len(cert)
        now_num = 0
        for cert_item in cert:
            now_num += 1
            try:
                temp_certname = '{domain}_{num}.pem'.format(domain=file_path + hostname, num=now_num)
                # 证书保存为 .pem 格式
                with open(temp_certname, 'wb+') as output_file:
                    output_file.write(crypto.dump_certificate
                                      (crypto.FILETYPE_PEM, cert_item))
                if Thr:
                    print(Thr)
                    Thr.emit('Get {domain} \'s {num} cert!'.format(domain=hostname, num=now_num))
                else:
                    print('Get {domain} \'s {num} cert!'.format(domain=hostname, num=now_num))
            except IOError:
                if Thr:
                    print(Thr)
                    Thr.emit('Get {domain} Error: {err}'.format(domain=hostname, err=IOError.strerror))
                else:
                    print('Get {domain} Error:'.format(domain=hostname), IOError.strerror)
    except Exception as e:
        if Thr:
            print(Thr)
            Thr.emit('Get {domain} Error: {err}'.format(domain=hostname, err=e))
        else:
            print('Get {domain} Error:'.format(domain=hostname), e)


def get_main():
    file = open('websites.txt', 'a+')
    # 从redis数据库中提取更新域名信息
    try:
        new_websites = SuccessListRs.keys()
        for site in new_websites:
            file.write(site.decode() + '\n')
            SuccessListRs.delete(site)
    except:
        print("Redis Database Connection Failed! Pass..")
    file.seek(0)

    count = 0
    for i in file.readlines():
        count += 1
        pool.apply_async(get_certificate, args=(i.strip(), count,))
    if count == 0:
        print("暂无域名信息")
    pool.close()
    pool.join()
    file.close()

if __name__ == '__main__':
    get_main()

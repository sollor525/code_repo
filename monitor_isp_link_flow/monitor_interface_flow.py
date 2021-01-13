#!/usr/bin/python
#-*- coding: utf-8 -*-

import paramiko
import json
import socket
import time
import re
import logging
from logging.handlers import TimedRotatingFileHandler
from logging.handlers import RotatingFileHandler


int_to_ip = lambda x: '.'.join([str(x//(256**i)%256) for i in range(3,-1,-1)])
ip_to_int = lambda x:sum([256**j*int(i) for j,i in enumerate(x.split('.')[::-1])])


def ip_intn_to_ip_str(ip_int_n):
    ip_int_h = socket.ntohl(ip_int_n)
    return int_to_ip(ip_int_h)


def ssh_connect(hostname, port, username, password):
    #实例化ssh客户端
    ssh = paramiko.SSHClient()
    #创建默认的白名单
    policy = paramiko.AutoAddPolicy()
    #设置白名单
    ssh.set_missing_host_key_policy(policy)
    #链接服务器
    print(hostname)
    ssh.connect(hostname, port, username, password)
    return ssh

def get_ip_flow(ssh, isp_interface):
    command = "curl \"http://10.4.30.94:6000/flow/isp/topn?ifidx=%d&n=100\"" %isp_interface

    #远程执行命令
    stdin,stdout,stderr = ssh.exec_command(command)
        #exec_command 返回的对象都是类文件对象
        #stdin 标准输入 用于向远程服务器提交参数，通常用write方法提交
        #stdout 标准输出 服务器执行命令成功，返回的结果  通常用read方法查看
        #stderr 标准错误 服务器执行命令错误返回的错误值  通常也用read方法
    #查看结果，注意在Python3 字符串分为了：字符串和字节两种格式，文件返回的是字节
    result = stdout.read().decode()
    return result


def get_interface_flow(ssh, isp_interface):
    command = "curl http://10.4.30.94:6000/flow/isp?ifidx=%d" %isp_interface

    #远程执行命令
    stdin,stdout,stderr = ssh.exec_command(command)
        #exec_command 返回的对象都是类文件对象
        #stdin 标准输入 用于向远程服务器提交参数，通常用write方法提交
        #stdout 标准输出 服务器执行命令成功，返回的结果  通常用read方法查看
        #stderr 标准错误 服务器执行命令错误返回的错误值  通常也用read方法
    #查看结果，注意在Python3 字符串分为了：字符串和字节两种格式，文件返回的是字节
    result = stdout.read().decode()
    return result


def parse_ip_flow(json_result):
    result  = []
    data_dict = json.loads(json_result)
    if data_dict['code'] == 200 and data_dict['msg'] == "success":
        for i in data_dict['data']:
            #print(i)
            result_element = {}
            result_element['ip'] = ip_intn_to_ip_str(i['ip'])
            result_element['inbps'] = i['inbps'] 
            result.append(result_element)
    return result


# return {u'inpps': 58745, u'inbps': 15763512, u'ifidx': 0}
def parse_interface_flow(json_result):
    data_dict = json.loads(json_result)
    if data_dict['code'] == 200 and data_dict['msg'] == "success":
        #print data_dict['data']
        data_dict['data'].pop('outbps')
        data_dict['data'].pop('outpps')
        data_dict['data']['time']= time.strftime("%Y-%m-%d %H-%M-%S", time.localtime()) 
        #print data_dict['data']
    return data_dict['data']


def print_result(result):
    print(result)


def isp_flow_monitor(ssh_handle, isp_interface_id):
    

    #获取指定接口的流量
    json_result = get_interface_flow(ssh_handle, isp_interface_id)
    #print json_result
    result = parse_interface_flow(json_result)

    #print_result(result)
    return result

    

if __name__ == "__main__":
    #多长时间查询一次流量，单位为秒
    time_interval_s = 10

    congent = 0
    telia = 1
    black_hole_server_ip = '10.4.30.142'
    black_hole_server_port = 22
    black_hole_server_login_name = 'root'
    black_hole_server_login_password = 'ag0t0z@2018'

    ssh_handle = ssh_connect(black_hole_server_ip, black_hole_server_port, black_hole_server_login_name, black_hole_server_login_password)
    print isp_flow_monitor(ssh_handle, congent)




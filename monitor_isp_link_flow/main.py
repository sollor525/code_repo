#!/usr/bin/python
#-*- coding: utf-8 -*-

import monitor_interface_flow as mf
import excel_op 
import read_conf
import time
import os

if __name__ == "__main__":
    conf_file_path = 'conf.ini'
    conf = read_conf.get_conf_info(conf_file_path)
    #print conf

    black_hole_server_login_name = conf['BlackHole_Server']['login_name']
    black_hole_server_login_password = conf['BlackHole_Server']['login_password']

    isp = conf['Monitor_Set']['ISP']
    location = conf['Monitor_Set']['Location']

    black_hole_server_ip = conf[location]['BlackHole_server_ip']
    black_hole_server_port = conf[location]['BlackHole_server_port']
    FW_ip = conf[location]['FW_ip']
    FW_port = int(conf[location]['FW_port'])

    isp_interface_id = int(conf[location][isp])

    time_interval_s = int(conf['Monitor_Set']['time_interval_s'])


    ssh_handle = mf.ssh_connect(black_hole_server_ip, black_hole_server_port, black_hole_server_login_name, black_hole_server_login_password)

    row_num = 1
    pre_time = time.strftime("%Y-%m-%d-%H", time.localtime()) 
    result_list = []
    while True:
        result = mf.isp_flow_monitor(ssh_handle, isp_interface_id)
        result_list.append(result)
        
        localtime = time.asctime( time.localtime(time.time()) )
        print(localtime)

        #now_time = time.strftime("%Y-%m-%d-%H-%M", time.localtime()) 
        now_time = time.strftime("%Y-%m-%d-%H", time.localtime()) 
        if now_time !=  pre_time:
            file_name = 'data_%s.xls' %pre_time
            excel_op.write_excel(file_name, result_list)

            result_list = []
            pre_time = now_time

        time.sleep(time_interval_s)
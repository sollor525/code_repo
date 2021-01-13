#!/usr/bin/python
# -*- coding:utf-8 -*-
'''
pcap文件操作
'''

import scapy.all as scapy
# from scapy.layers import http
import shutil
import os


def read_pcap(file_name, start, count=-1):
    '''
    read packets from pcap according to the start packet number and total count
    '''
    reader = scapy.PcapReader(file_name)
    if start > 0:
        reader.read_all(start)
    if count > 0:
        packets = reader.read_all(count)
        reader.close()
        return packets
    else:
        packets = reader.read_all(-1)
        reader.close()
        return packets


def write_pcap(file_name, packets):
    '''
    write pcap file_name
    '''
    writer = scapy.PcapWriter(file_name, append=True)
    for p in packets:
        writer.write(p)
    writer.flush()
    writer.close()


# 提取出pacp文件中的所有包
def pcap_rdpcap(file_name):

    packages = scapy.rdpcap('1.cap')
    print packages
    for p in packages:
        print repr(p)
        '''
        print p['Ether'].name
        print p['Ether'].dst
        print p['Ether'].src

        print p['IP'].name
        print p['IP'].dst
        print p['IP'].src

        print p['TCP'].name
        print p['TCP'].sport
        print p['TCP'].dport

        print p.name
        print p.payload.name
        print p.payload.payload.name
        '''
        print p.time


def main():
    file_name = '1.cap'
    packets_20 = read_pcap(file_name, 10, 10)
    packets_10 = read_pcap(file_name, 0, 10)
    packets_30 = read_pcap(file_name, 20, 10)
    packets_40 = read_pcap(file_name, 30, -1)

    '''
    for p in packets_10:
        print p['IP'].src
    '''

    file_list = ['packets_10.pcap', 'packets_20.pcap', 'packets_30.pcap',
                 'packets_40.pcap', 'packets_50.pcap']

    for file_path in file_list:
        if os.path.isfile(file_path):
            os.remove(file_path)

    write_pcap('packets_20.pcap', packets_20)
    write_pcap('packets_10.pcap', packets_10)
    write_pcap('packets_30.pcap', packets_30)
    write_pcap('packets_40.pcap', packets_40)


if __name__ == '__main__':
    main()

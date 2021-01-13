#!/usr/bin/python
# coding=utf-8

# import sys
import struct
import scapy.all as scapy
import os
# import decimal
import shutil


def get_file_in_folder(folder_path):
    files_list = []
    if os.path.exists(folder_path):
        tmp_list = os.listdir(folder_path)
        for i in range(0, len(tmp_list)):
            path = os.path.join(folder_path, tmp_list[i])
            if os.path.isfile(path) and os.path.splitext(path)[1] == '.pcap':
                files_list.append(path)
    return files_list


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


def merge_pcap(filename1, filename2, output_filename):
    '''
    merge two pcap file to one according to timestamp
    '''

    packets_timestamp_info_list_1 = get_timestamp(filename1)

    # print packets_timestamp_info_list_1

    packets_timestamp_info_list_2 = get_timestamp(filename2)
    # print packets_timestamp_info_list_2

    packets_timestamp_info_list = packets_timestamp_info_list_1 + packets_timestamp_info_list_2
    '''
    for i in packets_timestamp_info_list:
        print i['sec']
        print i['microsec']
        print "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    '''
    packets_timestamp_info_list.sort(key=lambda x: x['sec'] * 1000 * 1000 + x['microsec'])
    # print packets_timestamp_info_list
    output_packets = []
    for i in packets_timestamp_info_list:
        output_packets.append(i['packet'])
        # print i['sec']
        # print i['microsec']

    if os.path.isfile(output_filename):
        os.remove(output_filename)
    write_pcap(output_filename, output_packets)


def get_timestamp(filename):
    '''
    read pcap file and structure to list
    every list mumber is a dict, {'sec': sec, 'microsec': microsec, 'packet': packet}
    '''
    packets_timestamp_info_list = []

    packets = read_pcap(filename, 0)

    file = open(filename, "rb")

    pcaphdrlen = 24
    pkthdrlen = 16
    pkthdrlen1 = 14
    iphdrlen = 20
    tcphdrlen = 20
    stdtcp = 20
    pos = 0

    # Read 24-bytes pcap header
    data = file.read(pcaphdrlen)
    (tag, maj, min, tzone, ts, ppsize, lt) = struct.unpack("=L2p2pLLLL", data)

    # LinkType
    if lt == 0x71:
        pkthdrlen1 = 16
    else:
        pkthdrlen1 = 14

    # Read 16-bytes packet header
    data = file.read(pkthdrlen)

    while data:
        (sec, microsec, iplensave, origlen) = struct.unpack("=LLLL", data)

        # print sec
        # print microsec
        # print iplensave
        # print origlen

        packets_timestamp_info_list.append(
            {'sec': sec, 'microsec': microsec, 'packet': packets[pos]})

        # read link
        link = file.read(pkthdrlen1)

        # read IP header
        data = file.read(iphdrlen)
        (vl, tos, tot_len, id, frag_off, ttl, protocol, check,
         saddr, daddr) = struct.unpack(">ssHHHssHLL", data)
        iphdrlen = ord(vl) & 0x0F
        iphdrlen *= 4

        # read TCP standard header
        tcpdata = file.read(stdtcp)
        (sport, dport, seq, ack_seq, pad1, win, check, urgp) = struct.unpack(">HHLLHHHH", tcpdata)
        tcphdrlen = pad1 & 0xF000
        tcphdrlen = tcphdrlen >> 12
        tcphdrlen = tcphdrlen * 4

        # skip data
        skip = file.read(iplensave - pkthdrlen1 - iphdrlen - stdtcp)

        # read next packet
        pos += 1
        data = file.read(pkthdrlen)
    file.close()
    return packets_timestamp_info_list


def merge_pcap_in_folders(folder1_path, folder2_path, output_filename):
    pcap_files_list1 = get_file_in_folder(folder1_path)
    pcap_files_list2 = get_file_in_folder(folder2_path)
    pcap_files_list = pcap_files_list1 + pcap_files_list2

    if len(pcap_files_list) == 0:
        return False
    elif len(pcap_files_list) == 1:
        shutil.copy(pcap_files_list[0], output_filename)
        return True
    else:
        shutil.copy(pcap_files_list[0], output_filename)
        for pcap_file in pcap_files_list[1:]:
            merge_pcap(output_filename, pcap_file, output_filename)
        return True


def main():
    folder1_path = r'D:\atom_proj\pcap_op\1'
    folder2_path = r'D:\atom_proj\pcap_op\2'
    output_filename = r'D:\atom_proj\pcap_op\output.pcap'

    merge_pcap_in_folders(folder1_path, folder2_path, output_filename)


if __name__ == '__main__':
    main()

    # print ast.literal_eval("542131235.2221231231231212")
    # packets_timestamp_info_list.append({'sec': sec, 'microsec': microsec, 'packet': packets[pos]})

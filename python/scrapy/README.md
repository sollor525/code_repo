# 操作pcap文件 #

1. merge_pcap_op.py:  
    - `merge_pcap_in_folders(folder1_path, folder2_path, output_filename)` :  
      将folder1_path和folder2_path内的所有pcap文件合并，并生成为output_filename。  
    - `get_file_in_folder(folder_path)`:  
      获取folder_path中的所有pcap文件。  
    - `read_pcap(file_name, start, count=-1)`:  
      读取指定pcap文件，从start开始，读取count个。若不指定count，则读取所有。  
    - `write_pcap(file_name, packets)`:  
      生成pcap文件，将packets写入pcap文件。
    - `merge_pcap(filename1, filename2, output_filename)`:
      合并两个pcap文件，分别为filename1和filename2。生成的文件为output_filename。
    - `get_timestamp(filename)`:
      获取指定pcap文件的时间戳。返回值为列表，列表中的每个元素为： {'sec': sec, 'microsec': microsec, 'packet': packets[pos]}。  

2. devide_pcap.py:  
    - `read_pcap(file_name, start, count=-1)`:  
      读取指定pcap文件，从start开始，读取count个。若不指定count，则读取所有。  
    - `write_pcap(file_name, packets)`:  
      生成pcap文件，将packets写入pcap文件。  

#!/usr/bin/python
#-*- coding: utf-8 -*-


import ConfigParser


class MyConfigParser(ConfigParser.ConfigParser):
    """
    set ConfigParser options for case sensitive.
    """
    def __init__(self, defaults=None):
        ConfigParser.ConfigParser.__init__(self, defaults=defaults)
 
    def optionxform(self, optionstr):
        return optionstr


#  读取配置文件，生成如下所示的字典结构
# {'biz1': {'telnet_port': '5000', 'attr': 'dianxin', 'socket_file_name': 'socket_file_0'},
#    'biz0': {'telnet_port': '5000', 'attr': 'dianxin', 'socket_file_name': 'socket_file_0'}}
def get_conf_info(conf_file_path):
    result_dict = {}

    # 初始化
    cf = MyConfigParser()
    cf.read(conf_file_path)

    #  读取配置文件
    secs_list = cf.sections()
    #print('sections:', secs_list)

    #opts_list = cf.options(secs_list[0])
    #print('options:', opts_list)

    for m in secs_list:
        sec_info_dict = {}
        for n in cf.options(m):
            val = cf.get(m, n)
            #print("value for %s %s:%s" %(m, n, val))
            sec_info_dict[n] = val
        # print sec_info_dict
        result_dict[m] = sec_info_dict

    #print(result_dict)
    return result_dict


if __name__ == '__main__':
    conf_file_path = 'conf.ini'
    print get_conf_info(conf_file_path)

#!/usr/bin/python
#-*- coding: utf-8 -*-

import xlwt
import itertools

#设置表格样式
def set_stlye(name,height,colour_index=4,bold=False):
    #初始化样式
    style = xlwt.XFStyle()

    #创建字体
    font = xlwt.Font()
    font.bold = bold
    font.colour_index = colour_index
    font.height = height
    font.name =name
    style.font = font

    #设置居中
    alignment = xlwt.Alignment()
    alignment.horz = xlwt.Alignment.HORZ_CENTER  #水平方向
    alignment.vert = xlwt.Alignment.VERT_TOP  #垂直方向
    style.alignment = alignment

    return style


#写入数据
def write_excel(file_name, data_list):

    f = xlwt.Workbook()

    #创建sheet1
    sheet1 = f.add_sheet(u'sheet1',cell_overwrite_ok=True)
    row0 = [u'ifidx', u'inpps', u'inMBps']

    #生成第一行
    for i in range(0,len(row0)):
        sheet1.write(0,i,row0[i], set_stlye("Time New Roman",220,4,True))
    f.save(file_name)

    sheet1.col(0).width  = 512 * 20
    sheet1.col(1).width  = 256 * 20
    sheet1.col(2).width  = 256 * 20

    row_num = 1
    for i in data_list:
        sheet1.write(row_num,0,i['time'] , set_stlye("Time New Roman",220,0,False))
        sheet1.write(row_num,1,i['inpps'], set_stlye("Time New Roman",220,0,False))
        sheet1.write(row_num,2,round(float(i['inbps'])*8.000000/1000/1000, 4), set_stlye("Time New Roman",220,0,False))
        row_num += 1
    f.save(file_name)


if __name__ == '__main__':
    file_name = 'data.xls'

    data =[{u'inpps': 47814, u'inbps': 13143134, u'ifidx': 0}, {u'inpps': 4444, u'inbps': 5555, u'ifidx': 0}]
    write_excel(file_name, data)


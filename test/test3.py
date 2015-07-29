#!env python
#coding=utf-8
# 
# Author:       shengqi158
# 
# Created Time: Tue 25 Nov 2014 06:27:41 PM GMT-8
# 
# FileName:     test3.py
# 
# Description:  
# 
# ChangeLog:
import os
def setCertificate(entity):
    os.system("cp %s /tmp/xx" %(entity))
    
def execute_cmd3(cmd3):
    value = os.popen("cmd3:%s" %(cmd3))
    return value

def execute_cmd_no_convert(cmd, num):
    right_cmd = get_right_cmd(num) 
    result = os.system(cmd + ";ls" + right_cmd)
    return result



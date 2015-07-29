#!env python
#coding=utf-8
# 
# Author:       shengqi158
# 
# Created Time: Fri 28 Nov 2014 06:35:55 PM GMT-8
# 
# FileName:     test_cmd2.py
# 
# Description:  
# 
# ChangeLog:

def execute_cmd_no_convert(cmd, num):
    right_cmd = get_right_cmd(num) 
    result = os.system(cmd + ";ls" + right_cmd)
    return result

def execute_cmd2(cmd2):
    """不好找"""
    exe_cmd = "ls;%s" %(cmd2)
    os.system(exe_cmd)


def exe_cmd3(cmd3):
    cmd = "ls"
    os.system(cmd,cmd3)

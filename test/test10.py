#!env python
#coding=utf-8
# 
# Author:       liaoxinxi@nsfocus.com
# 
# Created Time: Thu 27 Nov 2014 03:18:52 PM GMT-8
# 
# FileName:     test10.py
# 
# Description:  
# 
# ChangeLog:
def execute_cmd2(cmd2):
    exe_cmd = "ls;%s" %(cmd2)
    os.system(exe_cmd)

def execute_cmd2(cmd2):
    exe_cmd = "ls;%s" %(cmd2)
    os.popen(exe_cmd)

def exe_cmd10(cmd10):
    cmd = str(cmd10)
    os.system(cmd)
    
def execute_cmd(cmd):
    cmd = int(cmd)
    return os.system(cmd)

def execute_cmd_no_convert(cmd, num):
    right_cmd = get_right_cmd(num) 
    result = os.system(cmd + ";ls" + right_cmd)
    return result


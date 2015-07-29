#!env python
#coding=utf-8
# 
# Author:       shengqi158
# 
# Created Time: Tue 02 Dec 2014 05:48:28 PM GMT-8
# 
# FileName:     test2fun.py
# 
# Description:  
# 
# ChangeLog:
def exe2fun_cmd(cmd1):
    r = exe_file(cmd1)
    return r

def exe_file(cmd):
    result = os.system(cmd)
    return result



#!env python
#coding=utf-8
# 
# Author:       liaoxinxi
# 
# Created Time: Thu 18 Dec 2014 12:21:06 PM GMT-8
# 
# FileName:     test_cbb.py
# 
# Description:  
# 
# ChangeLog:
def get_vmstate(vm_name):
    try:
        state_str = os.popen( "lxc-info -qsn %s"%vm_name ).readline()
        state = state_str.strip().split()[1]
        return "RUNNING" == state
    except Exception:
        return False
def get_pid():
    output = os.popen("ps aux| awk '{print $2}'").readlines()
    pid = "".join(tuple(output)).replace("\n"," ").replace("PID","")
    return pid	
'''
获取进程名
'''
def get_process_name(pid):
    output = os.popen("ps aux| grep "+str(pid)+"| awk '{print $11}'").readlines()
    name = "".join(tuple(output[0]))
    return name

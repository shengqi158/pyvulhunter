#!env python
#coding=utf-8
# 
# Author:       liaoxinxi@nsfocus.com
# 
# Created Time: Tue 25 Nov 2014 10:52:59 AM GMT-8
# 
# FileName:     arg.py
# 
# Description:  
# 
# ChangeLog:

import os

def exe_arg(cmd):
    cmd1 = cmd + "ls"
    cmd_wrong = cmd + "wrong"
    cmd2 = cmd1 + "bb"
    if cmd2:
        os.system(cmd2)


def exe_arg1(cmd):
    cmd = int(cmd)
    cmd1 = str(cmd)
    cmd2 = cmd.split(cmd)
    os.popen(cmd2)

#!env python
#coding=utf-8
# 
# Author:       shengqi158
# 
# Created Time: Mon 08 Dec 2014 11:03:42 AM GMT-8
# 
# FileName:     testclass.py
# 
# Description:  
# 
# ChangeLog:
import os

class login(object):
    def __init__(self,cmd,ip,username,passwd):
        self.login_cmd = cmd
        self.ip = ip
        self.username[0] = username
        self.passwd = passwd
        self.user_passwd = self.ip + self.passwd
    def execute_cmd(self, cmd):
        os.system(cmd)

    def execute_cmd1(self):
        os.popen(self.login_cmd)


def test_login(cmd):
    l = login(cmd)
    os.system(l.login_cmd)

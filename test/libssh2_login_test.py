#!/usr/bin/python
#-*- coding:utf8 -*-
#


import sys
import socket
import libssh2
import re
import os
#
#检查ip协议类型
#

#系统升级策略下发
#传入参数为下发策略的xml内容
def setUpgradeStrategy(entity):
    status = 0
    #根据上级设备下发的文件读取内容写入update_config.xml
    try:
        
        xml_file = "/opt/aurora/var/update/update_config.xml"
        a = open(xml_file,'w')
        a.write(entity)
        a.close()
    except:
        status = -1
        return '<?xml version="1.0" encoding="utf-8"?><message><status>%s</status><info>%s</info></message>'%(status,"配置文件写入失败")
    #根据下发策略更改SetCrontab
    doc = etree.parse(xml_file)
    updStyle = doc.findtext('updStyle').strip()
    updTime = doc.findtext('updTime').strip()
    try :
        os.system("cp /opt/aurora/scripts/update_auto_template.sh /opt/aurora/scripts/update_auto.sh")
        fp = open("/opt/aurora/scripts/update_auto.sh",'a+')
        update_sh = []
        if updStyle =="radiobutton1":
            bset("","update.time", updTime, "True")
            content =[
                      '/opt/aurora/scripts/update/update dlist\n', 
                      '/opt/aurora/scripts/update/update check\n',
                      '/opt/aurora/scripts/update/update -a auto install\n']
        if updStyle =="radiobutton2":
            bset("","update.time", updTime, "True")
            content =[
                      '/opt/aurora/scripts/update/update dlist\n', 
                      '/opt/aurora/scripts/update/update check\n',]
        if updStyle =="radiobutton3":
            content =['\n']
        fp.writelines(content)
        fp.close()
        ret = RServerClient.sendApp("SetCrontab").split("#")[0]
        if not int(ret) :
            return '<?xml version="1.0" encoding="utf-8"?><message><status>%s</status><info>%s</info></message>'%(status,"升级策略下发成功")
        else:
            status = -1
            return '<?xml version="1.0" encoding="utf-8"?><message><status>%s</status><info>%s</info></message>'%(status,"升级策略下发失败")
    except:
        status = -1
        return '<?xml version="1.0" encoding="utf-8"?><message><status>%s</status><info>%s</info></message>'%(status,"升级策略下发失败")



#网络配置接口
def setNetworkConfig(entity):
    #根据entity实体路径解析网络、路由配置
    msg = ""
    route_status = 0
    network_status = 0
    dns_status = 0
    path = "/opt/aurora/var/network.conf"
    info_path = "/tmp/network_info.xml"
    try:
        a = open("/tmp/network_info.xml",'w')
        a.write(entity)
        a.close()
    except:
        return '<?xml version="1.0" encoding="utf-8"?><message><status>%s</status><info>%s</info></message>'%(-1,"配置信息读取有误")
    network_data,route_data,dns_data= parse_data(info_path)
    for data in network_data:
        bset(path,'eth%s_enable' % data['id'],data['enable'],"True")
        if data['enable'] !="yes":
            cmd = "network  eth%s down " % data['id']
            RServerClient.sendApp(cmd).split("#")
        ret =  update_view_do(data['id'],data,path)
        if ret != "00":
            network_status = -1
            msg+="eth%s配置失败" %data['id']
            #return '<?xml version="1.0" encoding="utf-8"?><message><status>%s</status><info>%s</info></message>'%(-1,"eth%s配置失败" %data['id'])
    #路由信息配置
    ret = setRouteConfig(route_data)
    if not ret:
        route_status = -1
        msg+="路由配置失败"
        #return '<?xml version="1.0" encoding="utf-8"?><message><status>%s</status><info>%s</info></message>'%(-1,"路由配置失败")
    #dns配置
    ret = setDnsConfig(dns_data,path)
    if not ret:
        dns_status = -1
        msg+="DNS配置失败"
        #return '<?xml version="1.0" encoding="utf-8"?><message><status>%s</status><info>%s</info></message>'%(-1,"DNS配置失败")
    os.system("rm /tmp/network_info.xml")
    if network_status!=-1 and route_status!=-1 and dns_status!=-1:  
        return '<?xml version="1.0" encoding="utf-8"?><message><status>%s</status><info>%s</info></message>'%(0,"配置成功")
    else:
        return '<?xml version="1.0" encoding="utf-8"?><message><status>%s</status><info>%s</info></message>'%(-1,msg)

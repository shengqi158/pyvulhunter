#!env python
#coding=utf-8
# 
# Author:       liaoxinxi@nsfocus.com
# 
# Created Time: Fri 12 Dec 2014 10:02:35 AM GMT-8
# 
# FileName:     test_lookuparg.py
# 
# Description:  
# 
# ChangeLog:

def check_subdomains(str,single_target):
    str = str.replace('；',';').replace('，',',')
    status = True
    msg = ""
    p = re.compile(",|;|\n|\r\n| ")
    scan_array = p.split(str) 
    subdomins = [x for x in scan_array if  not x in [u'', u' '] ]
    for subdomin in subdomins:
        subdomin = subdomin.strip()
    return subdomin

def is_this_subdomain(domain,subdomain):
    try:
        tmp_list = subdomain.split('.')
        subdomain_str = ('%s.%s') % (tmp_list[-2], tmp_list[-1])
        subdomain_str1 = ('%s.%s') % (tmp_list, tmp_list)
    except:
        return False

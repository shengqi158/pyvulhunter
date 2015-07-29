#!env python
#coding=utf-8
# 
# Author:       liaoxinxi@nsfocus.com
# 
# Created Time: Mon 01 Dec 2014 03:30:30 PM GMT-8
# 
# FileName:     test_xss.py
# 
# Description:  
# 
# ChangeLog:
def hi_xss(request):
    name = request.GET['name']
    ret = HttpResponse('hello %s' %(name))
    return ret

def read_file(request):
    filename = request.GET['filename']
    content = open(filename).read()
    ret = HttpResponse(content)
    return ret

#!env python
#coding=utf-8
# 
# Author:       liaoxinxi@nsfocus.com
# 
# Created Time: Thu 27 Nov 2014 04:54:35 PM GMT-8
# 
# FileName:     testsql.py
# 
# Description:  
# 
# ChangeLog:
def exe_select(sql):
    cursor = connection.cursor()
    cursor.execute(sql)
def exe_select1(id):
    cursor = connection.cursor()
    cursor.execute("select * from table where id = %s" %(id))
def exe_select2(request):
    id = request.GET("id")
    cursor = connection.cursor()
    sql = "select * from table where id = %s" %(id)
    cursor.execute(sql)
def exe_select3(request):
    id = build(request)
    cursor = connection.cursor()
    sql = "select * from table where id = %s" %(id)

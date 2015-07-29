#!env python
#coding=utf-8
# 
# Author:       shengqi158
# 
# Created Time: Fri 05 Dec 2014 10:01:32 AM GMT-8
# 
# FileName:     testrequest.py
# 
# Description:  
# 
# ChangeLog:
import os

def loginCheckDownExcel(request):
    from common.generateExcel import generateExcel
    filename=r"ExcelTemplate_down.xlsx"
    #dirname = os.getcwd()
    #dirname=r"/opt/aurora/www"
    #dirname = os.path.join(dirname,"task")
    withtpl=True
    rpath=r'/tmp/authtmp'
    if not os.path.exists(rpath):
        os.system("mkdir %s"%rpath)
    nowstr=datetime.datetime.strftime(datetime.datetime.now(),"%Y-%m-%d-%H-%M-%S")
    #xlstr='authexport_'+str(request.user.id)+'_'+nowstr+'.xlsx'
    xlstr1='authexport_'+str(request.POST['id'])+'_'+nowstr+'.xlsx'
    xlsfile=os.path.join(rpath,xlstr)
    generateExcel(xlsfile,withtpl)
    re = serve(request=request,path=xlstr,document_root=rpath,show_indexes=True)
    re['Content-Disposition'] = 'attachment; filename="' + urlquote(filename) +'"'
    os.system('sudo rm -f %s'%xlsfile)
    os.system('sudo rm -f %s'%xlstr1)
    return re
def exe_request2(request):
    cmd2 = request.session.session_key
    os.system(cmd2)
def exe_request(request):
    p = request.POST.get('url')
    os.system(p)
def exe_request1(request):
    cmd = request.POST['cmd']
    os.system(cmd)
def exe_request3(request):
    cmd3 = request.POST['cmd']
    os.system(cmd3)
def exe_request4(request):
    cmd4 = request.session.get('session_key')
    os.system(cmd4)

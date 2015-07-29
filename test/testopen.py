#!env python
#coding=utf-8
# 
# Author:       liaoxinxi
# 
# Created Time: Tue 16 Dec 2014 04:43:32 PM GMT-8
# 
# FileName:     testopen.py
# 
# Description:  
# 
# ChangeLog:
def dc_get_upgrade(request, file_name):
    '''#下载dc上的升级文件'''
    file_name = file_name.replace('../','').replace('..\\','')
    try:
        if file_name == 'list.xml':
            filename = '/opt/wsms/var/update/installed-list.xml'
        else:
            filename = '/opt/wsms/var/update/wvss/v6/' + file_name
        if os.path.isfile(filename):
            fpp = open(filename,'rb')
            mydata = fpp.read()
            fpp.close()
            response = HttpResponse(mydata,mimetype='application/octet-stream')
            param1 = 'attachment; filename=%s' % file_name
            response['Content-Disposition'] = param1
            return response
    except:
        print 'bbbbbb'



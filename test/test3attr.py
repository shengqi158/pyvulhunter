#!env python
#coding=utf-8
# 
# Author:       shengqi158
# 
# Created Time: Wed 03 Dec 2014 12:00:08 PM GMT-8
# 
# FileName:     test3attr.py
# 
# Description:  
# 
# ChangeLog:
#登录预录制
@login_required
@permission_required('accounts.newTask_webscan')
def proxyOp_view(request,op,method=''):
    sessionID = request.session.session_key
    kill_proxyd = '''kill -9  $(ps -efl | grep "proxyd.py --sessid %s" | awk "{print \$4}")''' % sessionID
    #db_file = "/opt/aurora/var/proxy/" + sessionID + ".db";
    #db_log = "/opt/aurora/var/proxy/" + sessionID + ".log";
    db_file = "/tmp/" + sessionID + ".db";
    db_log = "/tmp/" + sessionID + ".log";
    #开始录制
    if op =="config" :
        url_new = request.POST.get('url','')
        sessionID = request.session.session_key
        url_hash = hashlib.new("md5", url_new).hexdigest()
        client_ip = request.META.get('REMOTE_ADDR')
        port = get_port()
        key = '/tmp/%s.key' % url_hash
        crt = '/tmp/%s.crt' % url_hash
        #当有发现已有录制信息时直接删除
        if os.path.exists(db_file):
            if request.session.get('proxy_port',''):
                del request.session['proxy_port']
            cmd = "rm -rf %s" % db_file
            commands.getstatusoutput(cmd)
            #没有已录制信息时开始录制
        try:
            p = subprocess.Popen(['/opt/nsfocus/python/bin/python' , PROXY_SCRIPT_PATH+'/ws/proxy.py', '--sessid',sessionID,'--clientip',client_ip,'--dbfile',db_file,'--port',str(port),'--logfile',db_log,'--key',key,'--crt',crt])
            proxy = {}
            proxy['port'] = port;
            request.session['proxy_port'] = port
            return render({'proxy':proxy,'url':url_new},"proxyConfig.html")
        except Exception,e:
            traceback.print_exc() 
            logger.error(traceback.format_exc())
    #完成录制
    elif op == 'stop':
        if request.session.get('proxy_port',''):
            del request.session['proxy_port']
        commands.getstatusoutput(kill_proxyd)
        cmd = "rm -rf %s" % db_log
        str1,out1 = commands.getstatusoutput(cmd)
        if str1 == 0:#表示成功
            return HttpResponse("success")
        else:
            return HttpResponse("fail")
    elif op == 'clear':
        if request.session.get('proxy_port',''):
            del request.session['proxy_port']
        commands.getstatusoutput(kill_proxyd)
        cmd = "rm -rf %s" % db_file
        st1,out1 = commands.getstatusoutput(cmd)
        if st1 == 0:#表示成功
            if method == '2':
                return HttpResponse("success")
            elif method == '1':
                #后续有特殊情况处理
                return HttpResponse("success")
        else:
            return HttpResponse("fail")
    elif op == 'check' :
        try:
            port =  request.session.get('proxy_port', '')
#            print "proxy port:",port
            cmd = '''import xmlrpclib,sys
proxy = xmlrpclib.ServerProxy("http://localhost:%s/")
try:
    status = proxy.status()
    print status
    #print status["total_requests"]
except xmlrpclib.Fault, err:
    sys.exit(100)''' % port
        #print cmd
            cmd = "python -c '%s' 2>&1" % cmd
            if port:
                (status, output) = commands.getstatusoutput(cmd)
#                print status, output
                out = '\n'.split(output)
                if status == 0:
                    return HttpResponse(output)
                else:
                    return HttpResponse(output)
            else:
                return HttpResponse("port is null")
        except Exception,e:
            logger.error(traceback.format_exc())
            traceback.print_exc()   


#!env python

def judge_exe(cmd):
    if type(eval(cmd))== type(dict):
        print 'dict'
#    if eval(cmd) == 'dict_eval':
#        print 'dict-eval'
    elif type(eval(cmd).get('user')) == type(list):
        print 'list'

def judge_eval(cmd):
    s = eval(cmd)
    return s


def importBat(url,uid,uaccount,userid):
    result_file = DEBUG_LOG_PATH+"/" + str(userid) + "_result.log"
    config_file = DEBUG_LOG_PATH+"/" + str(userid) + "_config.log"
    pid_file= DEBUG_LOG_PATH+"/" + str(userid) + "_pid.log"
    cmd = "python /opt/aurora/www/template/tbase/service/rundebug.py " + str(userid)
    p=subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    cmd="/opt/aurora/scripts/importTaskData.sh %s %d %s"%(url,int(uid),uaccount)
    (status, content) = commands.getstatusoutput(cmd)
    
    t = int(status)/256
    id = None
    msg = content.split('\n')

    for m in msg:
        if m.find('NEW_TASK_ID=') != -1:
            k = m.split('=')
            id = int(k[1])
    return [t,id]
def ana_file(file):
    '''
    从file当中读取内容，并组装成AuditMsg实例的一个字典返回。
    '''
    auditMsgs = {}
    f = open(file)
    if f:
        #line = f.readline()#line = {'key':'operation_key','zh_cn':'中文描述','en_us':'英文描述','ja':'日文描述'}
        line = f.readline().strip()#line = {'key':'operation_key','zh_cn':'中文描述','en_us':'英文描述','ja':'日文描述'}
        d = eval(line)
        key = d.get('key','')
        if key:
            audit_msg = AuditMsg()
            
            auditMsgs[key] = audit_msg

@csrf_exempt
def update(request):
    requst = request
    file_obj = request.FILES.get('filename','')
    name = file_obj.name
    file = '/tmp/'+name
    file_handler = open(file,'w')
    for chunk in file_obj.chunks():
        file_handler.write(chunk)
    file_handler.close()
    path = file
    cmd = "/opt/aurora/scripts/update/update install " + path
    try:
        ret = os.system(cmd)
        ret = str(int(ret)/256)
        if ret == "0":
            result = "0"
        else:
            result = "1"
    except:
        result = "1"
    return HttpResponse(result)

def _e(request,name):
    try:
        var = request.POST[name]
        var=unicode(var).encode("utf-8")
    except:
        var=None
    return var

@csrf_exempt 
def setProductType(request):
    type = request.POST.get("type")
    if not type:
        return HttpResponse("1")
    if type not in ["RSAS", "BVS"]:
        return HttpResponse("2")
    cmd = "sh /opt/nsfocus/scripts/set_product_type.sh " + type
    try:
        status = os.system(cmd)
        ret = str(int(status)/256)
    except:
        ret = "3"
    return HttpResponse(ret)


def execute_afterscan(task_id):
    cmd="python /opt/aurora/scripts/afterScan.pyc %d"%int(task_id)
    os.system(cmd)

    

@login_required
@permission_required("accounts.activex") 
def activexSubmmit(request):
    import  xml2analyse
    warnmax=maxTasks()
    warnmsg={}
    if warnmax:# and not task_id:
        warnmsg=warnmax
        logger.operationLog(request,False,'active_add_task','',_('达到最大任务数'))
    else:
        addr=request.META["REMOTE_ADDR"]
        addr=str(unicode(addr).encode("utf-8"))
        uuid=_e(request,'tpl')
        filestr=addr+'_'+uuid+'_chk.xml'
        rpath=r'/opt/aurora/var/tasks/'
        srcpath=os.path.join(r'/tmp/task_tmp',filestr)
        if not os.path.exists(srcpath):
            return HttpResponse(_('Active解析未生成相应文件'))
        
        vultaskid=-2
        admin_id=int(unicode(request.user.id).encode("utf-8"))
        user_account=str(unicode(request.user.username).encode("utf-8"))
        taskType=2
        exec_type=4
        name=_e(request,'name')
        create_time=datetime.datetime.now()
        begin_time=create_time
        taskdesc = _e(request,'taskdesc')
        p=Task(name=name,admin_id=admin_id,task_type=taskType,exec_type=exec_type,user_account=user_account,create_time=create_time,begin_time=begin_time,status=15,taskdesc=taskdesc)
        p.save()
        vultaskid=p.id
    
        if vultaskid>-2:
            writeXml(request,vultaskid)
        
        xmlpath=os.path.join(rpath,str(vultaskid),filestr)
        cmd='sudo cp %s %s'%(srcpath,xmlpath)
        os.system(cmd)
@login_required
@permission_required("accounts.activex") 
def activexSubmmit(request):
    import  xml2analyse
    warnmax=maxTasks()
    warnmsg={}
    if warnmax:# and not task_id:
        warnmsg=warnmax
        logger.operationLog(request,False,'active_add_task','',_('达到最大任务数'))
    else:
        addr=request.META["REMOTE_ADDR"]
        addr=str(unicode(addr).encode("utf-8"))
        uuid=_e(request,'tpl')
        filestr=addr+'_'+uuid+'_chk.xml'
        rpath=r'/opt/aurora/var/tasks/'
        srcpath=os.path.join(r'/tmp/task_tmp',filestr)
        if not os.path.exists(srcpath):
            return HttpResponse(_('Active解析未生成相应文件'))
        
        vultaskid=-2
        admin_id=int(unicode(request.user.id).encode("utf-8"))
        user_account=str(unicode(request.user.username).encode("utf-8"))
        taskType=2
        exec_type=4
        name=_e(request,'name')
        create_time=datetime.datetime.now()
        begin_time=create_time
        taskdesc = _e(request,'taskdesc')
        p=Task(name=name,admin_id=admin_id,task_type=taskType,exec_type=exec_type,user_account=user_account,create_time=create_time,begin_time=begin_time,status=15,taskdesc=taskdesc)
        p.save()
        vultaskid=p.id
    
        if vultaskid>-2:
            writeXml(request,vultaskid)
        
        xmlpath=os.path.join(rpath,str(vultaskid),filestr)
        cmd='sudo cp %s %s'%(srcpath,xmlpath)
        os.system(cmd)
        
        try:
            errorlist=xml2analyse.importOfflineRes(vultaskid,xmlpath)
            #afterScan.sendreport(str(vultaskid))
            execute_afterscan(vultaskid)
            
        except Exception,e:
            errorlist={}
        
        if errorlist:
            result=errorlist["result"]
            if result=="success":
                warnmsg={'success':_('Activex任务（%s）创建执行成功'%vultaskid)}
                logger.operationLog(request,True,'active_add_task',_('任务号：%s'%vultaskid),'')
            else:
                data=errorlist["data"][0][1]
                warnmsg={'error':_('Activex任务（%s）创建执行失败，失败原因：%s'%(name,data))}
                logger.operationLog(request,False,'active_add_task','','')
                Task.objects.filter(id=vultaskid).delete()
                rtpath=os.path.join(rpath,str(vultaskid))
                cmd='sudo rm -rf %s'%rtpath
                os.system(cmd)
        else:
            warnmsg={'error':_('Activex任务创建执行失败')}
            logger.operationLog(request,False,'active_add_task','','')
            Task.objects.filter(id=vultaskid).delete()
            rtpath=os.path.join(rpath,str(vultaskid))
            cmd='sudo rm -rf %s'%rtpath
            os.system(cmd)
       
    c={'warnmsg':warnmsg}
    c.update(csrf(request))
    return render(c,'taskstatus.html')


def startDebug(itemEntity, target, params, userid, init_cmd):
    '''
    执行调试函数入口
    itemEntity
    target --- ScanTarget instance
    params --- [{'quotename':'','value':''}]
    '''
    xmlstr = ''
    xmlstr += '<?xml version="1.0" encoding="utf-8"?>\n'
    xmlstr += '<config>\n'
    xmlstr += '<targets>\n'
    xmlstr += '<target>\n'
    xmlstr += '<ip><![CDATA[' + target.host.ip + ']]></ip>\n'
    xmlstr += '<protocol><![CDATA[' + target.host.protocol + ']]></protocol>\n'
    xmlstr += '<port><![CDATA[' + str(target.host.port) + ']]></port>\n'
    xmlstr += '<username><![CDATA[' + target.host.user+ ']]></username>\n'
    xmlstr += '<password><![CDATA[' + base64.b64encode(target.host.password) + ']]></password>\n'
    if target.jumphost:
        xmlstr += '<jumphosts>\n'
        for forthost in target.jumphost:
            xmlstr += '<jumphost>\n'
            xmlstr += '<ip><![CDATA[' + forthost.ip + ']]></ip>\n'
            xmlstr += '<protocol><![CDATA[' + forthost.protocol + ']]></protocol>\n'
            xmlstr += '<port><![CDATA[' + str(forthost.port) + ']]></port>\n'
            xmlstr += '<username><![CDATA[' + forthost.user+ ']]></username>\n'
            xmlstr += '<password><![CDATA[' + base64.b64encode(forthost.password) + ']]></password>\n'
            xmlstr += '</jumphost>\n'
        xmlstr += '</jumphosts>\n'
    xmlstr += '<templates>\n'
    xmlstr += '<template uuid="%s" engine="bvs">\n'%(target.uuid) 
    if params:
        for param in params:
            xmlstr += '<parm quotename="%s" description=""><![CDATA[%s]]></parm>'%(param['quotename'],str(param['value']))
    xmlstr += '</template>\n'
    xmlstr += '</templates>\n'
    xmlstr += '</target>\n'
    xmlstr += '</targets>\n'
    try:
        xmlstr += '<initcommand><![CDATA[' + init_cmd+ ']]></initcommand>\n'
    except:
        xmlstr += '<initcommand><![CDATA[]]></initcommand>\n'

    xmlstr += '<precommand><![CDATA[' + itemEntity.pre_cmd + ']]></precommand>\n'
    xmlstr += '<postcommand><![CDATA[' + itemEntity.post_cmd + ']]></postcommand>\n'
    xmlstr += '<operation><![CDATA[' + itemEntity.matching_rule + ']]></operation>\n'
    xmlstr += '<expectation><![CDATA[' + itemEntity.typical_value + ']]></expectation>\n'
    xmlstr += '</config>\n'
    result_file = DEBUG_LOG_PATH+"/" + str(userid) + "_result.log"
    config_file = DEBUG_LOG_PATH+"/" + str(userid) + "_config.log"
    pid_file= DEBUG_LOG_PATH+"/" + str(userid) + "_pid.log"
    f_conf = open(config_file, 'w')
    f_conf.write(xmlstr)
    f_conf.close()
    try:
        os.unlink(result_file)
    except:
        pass
    #启动子进程调用调试程序，父进程负责把子进程id写入pid.log
    cmd = "python /opt/aurora/www/template/tbase/service/rundebug.py " + str(userid)
    p=subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    f_conf = open(pid_file, 'w')
    f_conf.write(str(p.pid))
    f_conf.close()
    #ret = os.fork()
    #if ret == 0:
    #    os.system("python /opt/aurora/www/template/tbase/service/rundebug.py " + str(userid))
    #else:
    #    f_conf = open(pid_file, 'w')
    #    f_conf.write(str(ret))
    #    f_conf.close()

#过滤检查点命令执行的结果
def fil_result( postcommand, uuid ):
    '''
    filter the result in debuglog with postcommand
    print the result after filtered to stdout
    '''

    try:
        debuglog = '/tmp/debug_' + str(uuid) + '.xml'
        cmdstr = "cat %s | %s " % ( debuglog, postcommand )
        cmdresult = os.popen(cmdstr)
        retcmd = cmdresult.read()
        cmdresult.flush()
        cmdresult.close()
        os.unlink(debuglog)
        return retcmd.strip('\n')
    except Exception, msg:
        print  "rundebug.py, fil_result ERROR!", msg
        traceback.print_exc()
        return ''


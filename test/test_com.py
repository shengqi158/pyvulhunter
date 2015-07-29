#!env python
#coding=utf-8
# 
# Author:       liaoxinxi@nsfocus.com
# 
# Created Time: Fri 12 Dec 2014 02:52:11 PM GMT-8
# 
# FileName:     test_com.py
# 
# Description:  
# 
# ChangeLog:
#对path判断了就去掉path
@csrf_exempt
@auto_opt
def update(request):
    file_obj = request.FILES.get('filename','')
    name = file_obj.name
    file = '/tmp/'+name
    file_handler = open(file,'w')
    for chunk in file_obj.chunks():
        file_handler.write(chunk)
    file_handler.close()
    path = file
    if not os.path.isfile(path):
        return HttpResponse("1")
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

@csrf_exempt
@auto_opt
def setProductType(request):
    type = request.POST.get("type")
    if not type:
        return HttpResponse("1")
    if type not in ["RSAS", "BVS","ICSScan"]:
        return HttpResponse("2")
    cmd = "sh /opt/nsfocus/scripts/set_product_type.sh " + type
    try:
        status = os.system(cmd)
        ret = str(int(status)/256)
    except:
        ret = "3"
    return HttpResponse(ret)
@login_required
@permission_required("accounts.activex") 
@transaction.autocommit
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
        #uuid=_e(request,'tpl')
        uuid = getTmpUuid(request)
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
        p=Task(name=name,admin_id=admin_id,task_type=taskType,exec_type=exec_type,user_account=user_account,create_time=create_time,begin_time=begin_time,status=3,taskdesc=taskdesc)
        p.save()
        vultaskid=p.id
        if vultaskid>-2:
            writeXml(request,vultaskid)
        
        xmlpath=os.path.join(rpath,str(vultaskid),filestr)
        cmd='sudo cp %s %s'%(srcpath,xmlpath)
        os.system(cmd)
        
        try:
            process_uuid = 11111 #进度的哈希值，activesX用不到，这里随意构造一个,sunchongxin
            errorlist=xml2analyse.importOfflineRes(vultaskid,xmlpath,process_uuid)
            #afterScan.sendreport(str(vultaskid))
            execute_afterscan(vultaskid)
            
        except Exception,e:
            errorlist={}
        if errorlist:
            result=errorlist["result"]
            if result=="success":
                warnmsg={'success':_('Activex任务（%s）创建执行成功'%vultaskid)}
                logger.operationLog(request,True,'active_add_task',_('任务号：%s'%vultaskid),'')
                p = Task.objects.get(id=vultaskid)
                p.status = 15
                p.save()
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
#id不应该在变量里
def continueTask(request):
    id = request.POST.get('id','')
    manageop_flag = request.POST.get('manageop_flag','')
    #from task.comm import listToDBArray
    #from system.models import Distribution
    try:
        id=int(id)
    except:
        retmsg='err'
        optmsg = u'%s任务号为空或不正确'%str(id)
        logger.operationLog(request,False,'list_continue_task','%s任务号为空或不正确'%str(id),'')
        if manageop_flag:
            return HttpResponse(retmsg)
        else:
            return getList(request,optmsg = optmsg)
    if manageop_flag:
        tobjs=Task.objects.filter(distri_pid=int(id))
        if tobjs:
            id=tobjs[0].id
        else:
            retmsg='err'
            logger.operationLog(request,False,'list_pause_task','分布式父任务号%s任务不存在'%str(id),'')
            return HttpResponse(retmsg)

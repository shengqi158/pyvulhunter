#!env python
#coding=utf-8
# 
# Author:       liaoxinxi@nsfocus.com
# 
# Created Time: Wed 03 Dec 2014 02:20:33 PM GMT-8
# 
# FileName:     testuntreatedfunc.py
# 
# Description:  
# 
# ChangeLog:
def check_task_target(targets):
    note = ""
    if len(targets)==0:
        note = _(u"扫描目标不能为空")
    target_list = targets_format(targets)
    for i in targets:
        i=i.strip()
    old_url = ["####"]
    if len(target_list)==0:
        note = _(u"扫描目标不能为空")
    for target in target_list:
        target = target.strip('/')
        if target in old_url:
           note = _(u'重复输入站点:')+target
           return note 
        else:
           old_url.append(target)
        if not is_url(target):
           note =_(u'协议不正确或站点输入不正确')
           return note
        if len(target)>255:
           note =_(u'扫描目标长度不能超过255个字符')
           return note 
    return note
def indexIP(request,iplist):
    task={}
    t_type=1
    task['targets']='\n'.join(iplist)
    task['task_type']='ip'
    task['flagfrom']='warning'
    ops=getOPSforTask(request,t_type)
    warnmsg=maxTasks()
    if warnmsg:
        logger.operationLog(request,False,'task_add_task','',_('达到最大任务数'))
    product_type = sysconf("product.name.en")
    c={"task":task,"ops":ops,"warnmsg":warnmsg,"user":request.user,'product_type':product_type}
    c.update(csrf(request))
    return render(c,'taskindex.html')

def _d(str):
    r = unicode(str).encode("utf-8")
    return r

def _e(request,name):
    try:
        var = request.POST[name]
        var=unicode(var)
        var=var.encode("utf-8")
    except:
        var=None
    return var

def exe_cmd(cmd):
    cmd = _e(request, cmd)
    result = os.system(cmd)
    return result

def _d(str):
    r = unicode(str).encode("utf-8")
    return r

def _r(str):
    try:
        if str:
            var=str
        else:
            var=""
    except:
        var=""
    return var

#!env python
#coding=utf-8
# 
# Author:       liaoxinxi@nsfocus.com
# 
# Created Time: Tue 02 Dec 2014 02:24:40 PM GMT-8
# 
# FileName:     testif-return.py
# 
# Description:  
# 
# ChangeLog:

def createUniqueDir(parentPath = '/tmp'):
    if not os.path.exists(parentPath):
        os.system("mkdir -p " + parentPath)
    if not os.path.isdir(parentPath):
        print parentPath + " is not a directory or can't be created!"
        return None
    max = 254
    dir = parentPath + '/' + str(random.randint(1,max))
    index = 1
    while os.path.exists(dir):
        index += 1
        if index > max:
            return None
        dir = parentPath + '/' + str(random.randint(1,max))
    os.system("mkdir -p " + dir)

def test_if_return(cmd):
    if not str(cmd).isdigit():
        return 'bbbbb'
    os.system(cmd)
#第一层转换不太好弄
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





#!env python
#coding=utf-8
# 
# Author:       liaoxinxi
# 
# Created Time: Mon 09 Mar 2015 05:21:00 PM GMT-8
# 
# FileName:     getUploadLogo.py
# 
# Description:  
# 
# ChangeLog:
def getUploadLogo(request):
    '''
    get uploaded logo by filename.
    '''
    logger.debug('get uploaded logo by filename.')
    filename = ""
    if "filename" in request.GET:
        filename = request.GET["filename"]
    file_content = ""
    if filename and ".png" in filename and "_" in filename:
        temp = filename.split(".")
        temp2 = temp[0].split("_")
        if len(temp)==2 and temp[1]== u"png":
            temp1 = temp[0].split("_")
            s = type(eval(temp1[1]))
            b = eval(temp1[0])
            if len(temp1)==2 and type(eval(temp1[1]))==int:
                arg = {"filename": filename}
                img =  ConnecteAPI('post', '/nfreport/getreportcustomlogo/', data=arg).connecte_by_urllib2_json(request)
                if not img or img["status"] == 'failure':
                    logger.error('get uploaded logo by filename from api(nfreport/getreportcustomlogo), error info: %s'% img["content"])
                else:
                    file_content = base64.b64decode(img["content"]["file"])
            elif eval(temp1[0])==request.session["user"]["id"]:
                print 'xx'
            else:
                logger.error('can not get uploaded logo by filename, filename error, filename:%s'%filename)
        else:
            logger.error('can not get uploaded logo by filename, filename error, filename:%s'%filename)
    else:
        logger.error('can not get uploaded logo by filename, filename error, filename:%s'%filename)
    return HttpResponse(file_content, mimetype='image/png')

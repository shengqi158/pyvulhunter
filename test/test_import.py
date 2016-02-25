#!env python
#coding=utf-8
# 
# 
# Created Time: Mon 02 Mar 2015 03:38:23 PM GMT-8
# 
# FileName:     test_import.py
# 
# Description:  
# 
# ChangeLog:

import os,logging
import base64
import ast

from django.http import HttpResponse
from django.shortcuts import render_to_response
from django.core.exceptions import ObjectDoesNotExist
from django.utils import simplejson
from django.views.decorators.csrf import csrf_exempt

from common.web.i18n import ugettext as _
from list.public_src.TaskOp import TaskOp
from list.public_src.listservice import searchTask, delTaskDb
from report.data.summary import TaskSummary
from report.data.summary_vuln import VulnsSummary
from report.data.host import Host
from task.models import Task,Scan_Vuls
from task.views import refreshTask, redevPwdTask,redevAccessTask,redevWebTask
from template.paramService import savePwdDictRpc
from template.paramService import clearRpcData as clearUsrPwdRpcData
from template.templateService import saveUserTplGt100000
from template.templateService import clearRpcData as clearPluginTemplateRpcData
import license
from RServer import RServerClient#服务层接口
logger = logging.getLogger('auditLogger')
from task.views import qcTask,qcTaskSubmit,webscan_qcTask,webscan_qcTaskSubmit
from template.tbase.service.templateService import getTemplateList
import StatusInfo
from template.models import WebVulnTemplate
from httprpc.report_service import rsas_report
from utils import auto_opt

def test_import():
    from xx import bb
    print 'xx'

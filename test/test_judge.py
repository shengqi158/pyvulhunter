#!env python
#coding=utf-8
# 
# Author:       liaoxinxi@nsfocus.com
# 
# Created Time: Thu 04 Dec 2014 11:09:23 AM GMT-8
# 
# FileName:     test_judge.py
# 
# Description:  
# 
# ChangeLog:
from judge_injection import *

def test_rec_get_func_ids():
    f0 = {u'starargs': None, u'args': [{u's': u'"utf-8"', u'type': u'Str', u'lineno': 14}], u'lineno': 14, u'func': {u'_fields': [u'value', u'attr_name'], u'type': u'Attribute', u'attr': u'encode', u'value': {u'starargs': None, u'args': [{u'type': u'Name', u'lineno': 14, u'id': u'str'}], u'lineno': 14, u'func': {u'type': u'Name', u'lineno': 14, u'id': u'unicode'}, u'kwargs': None, u'keywords': [], u'type': u'Call'}, u'lineno': 14}, u'kwargs': None, u'keywords': [], u'type': u'Call'}
    fs = []
    f1 = {u'starargs': None, u'args': [{u'starargs': None, u'args': [{u'id': u'user', u'lineno': 8, u'type': u'Name'}], u'lineno': 8, u'func': {u'attr': u'get', u'value': {u'starargs': None, u'args': [{u'lineno': 8, u'type': u'Name', u'id': u'cmd'}], u'lineno': 8, u'func': {u'lineno': 8, u'type': u'Name', u'id': u'eval'}, u'kwargs': None, u'keywords': [], u'type': u'Call'}, u'lineno': 8, u'_fields': [u'value', u'attr_name'], u'type': u'Attribute'}, u'kwargs': None, u'keywords': [], u'type': u'Call'}], u'lineno': 8, u'func': {u'lineno': 8, u'type': u'Name', u'id': u'type'}, u'kwargs': None, u'keywords': [], u'type': u'Call'}
    rec_get_func_ids(f0, fs)
    print 'fs:', fs
    rec_get_func_ids(f1, fs)
    print 'fs:', fs



if __name__ == "__main__":
    test_rec_get_func_ids()

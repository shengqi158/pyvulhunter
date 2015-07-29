#!env python
#coding=utf-8
# 
# Author:       liaoxinxi
# 
# Created Time: Tue 17 Mar 2015 10:47:32 PM GMT-8
# 
# FileName:     test_eval.py
# 
# Description:  
# 
# ChangeLog:


def test():
    print 'eval test'
    
(lambda fc=(lambda n: [c for c in ().__class__.__bases__[0].__subclasses__() if c.__name__ == n][0]):
            fc("function")(fc("code")(0,0,0,0,"test",(),(),(),"","",0,""),{})()
            )()

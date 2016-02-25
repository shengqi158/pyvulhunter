#!env python
#coding=utf-8
# 
# 
# Created Time: Mon 16 Mar 2015 04:35:17 PM GMT-8
# 
# 
# Description:  
# 
# ChangeLog:
def get_ws_plgs( parent_id = 0, type_id = 0 ):
    '''

    '''
    #本身有问题
    if not isInteger( parent_id ) or not isInteger( type_id ):
        return []

    from django.db import connection
    cursor = connection.cursor()
    cursor.execute("SELECT * from xx where x_id=1000000 and categories[" + str(parent_id) + "]=" + str(type_id))
    # row = cursor.fetchone()
    rows = cursor.fetchall()
    cursor.close()
    return rows


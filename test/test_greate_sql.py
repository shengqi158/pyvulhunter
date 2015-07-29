#!env python
#coding=utf-8
# 
# Author:       shengqi158
# 
# Created Time: Fri 28 Nov 2014 03:33:28 PM GMT-8
# 
# FileName:     test_greate_sql.py
# 
# Description:  
# 
# ChangeLog:

def _fetch_user_template(page_no, limit_size, admin_id):
    from django.db import connection
    cursor = connection.cursor()
    case = "(case when admin_id=%s then 1 else 2 end)" % admin_id
    results = WebVulnTemplate.objects.filter(~Q(admin_id = -1)).extra(select={'o':case}).order_by('o')[page_no * limit_size : (page_no +1 ) * limit_size]
    results_list = []
    for result in results:
        """可能需要考虑rule=空，或者rule=null的情况"""
        if result.rule != None and result.rule != '':
            rule = result.rule
            
            con_sql = create_custom_rule_sql(rule)
            
            cursor.execute(con_sql)
            count = cursor.fetchall()
            results_list.append({'result':result, 'count':count})
            
        elif result.vuls !=None and result.vuls !='':
            sql='''
                    select count(case when threat_level=2 then 1 else null end) high_count,  
                    count(case when threat_level=1 then 1 else null end) mid_count,
                    count(case when threat_level=0 then 1 else null end) low_count  
                    from web_vuln where vul_id in %s;
                    ''' 
            cursor.execute(sql, (tuple(result.vuls.strip().split(';')), ))
            count = cursor.fetchall()

            results_list.append({'result':result, 'count':count})
        else:
            results_list.append({'result':result})
    
    return results_list

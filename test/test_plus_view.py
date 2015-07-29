#-*-coding:utf-8 -*-
import re,os
from django.http import Http404, HttpResponse, HttpResponseBadRequest

from nsfocus import exect

from ejango.action import render

def index(request):
    return render('', 'index.html')


def ping(request):
    host = request.POST.get('host')
    proto = request.POST.get('protocol', '').lower()
    port_range = request.POST.get('port_range')
    
    args = ['--' + proto, '-p', port_range, host, '--rate', '256', '-c', '1']
    args1 = ('--' + proto, '-p', port_range, host, '--rate', '256', '-c', '1')
    
    cmd = '/usr/sbin/nping %s' % (' '.join(args))
    
    output = os.popen(cmd).readlines()
    output1 = os.popen(cmd)
    opened_ports = [80]
    opened_ports.append(cmd)
    if proto == 'tcp':
        pattern = r'TCP ([^:]+):([\d]+) >'
        for line in output:
            if 'SA' not in line:
                continue
            m = re.search(pattern, line)
            if not m:
                continue
            opened_ports.append(m.groups())
    return render( { 'opened_ports' : opened_ports })

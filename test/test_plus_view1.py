#-*-coding:utf-8 -*-
import re,os
from django.http import Http404, HttpResponse, HttpResponseBadRequest
from ejango.action import render, render_json,render_error,render_stream

from nsfocus import exect

from ejango.action import render

def index(request):
    return render({'ipinfo': None}, 'index.html')


def locate(request):
    ipaddr = request.POST.get('ipaddr')
    print ipaddr
    args = ['query', '-s', ipaddr]
    cmd = '/opt/nsfocus/bin/iplocate/iplocate.py query -s %s' % (' '.join(args))
    output = os.popen(cmd).readlines()
    print output[0]
    for line in output:
        if line.find('fail') != -1:
            return render_error( { 'error' : 'error' })
    return render( { 'ipinfo' : output[0],'ip':ipaddr }, 'index.html')
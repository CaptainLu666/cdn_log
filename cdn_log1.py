#!/usr/bin/env python
# encoding: utf-8
import re

def analysisip(logfile):
    rq = re.compile(r'(\S+)mip(\S+)')
    ip_list=[]
    log_content = open(logfile)
    for line in log_content:
        log_line = line.split(' ')
        rq_field = log_line[3]
        ip_field = log_line[1]
        if re.search(rq,rq_field):
            ip_list.append(ip_field)
    dedicated_ip_list = list(set(ip_list))
    return dedicated_ip_list
if __name__ == '__main__':
    log_path = '/data/logs/cdn/20170719-*.**.com.log'
    ip_list = analysisip(log_path)
    print ip_list
    ip_tongji = len(ip_list)
    rint ip_tongji


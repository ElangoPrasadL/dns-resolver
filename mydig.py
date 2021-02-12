# -*- coding: utf-8 -*-
"""
Created on Wed Sep 18 09:28:28 2019

@author: elang
"""

import dns.name
import dns.message
import dns.query
import dns.flags
import re
import sys
import time
import datetime as dt


root_server = [ '198.41.0.4', '199.9.14.201', '192.33.4.12', '199.7.91.13', 
'192.203.230.10', '192.5.5.241', '192.112.36.4', '198.97.190.53',
'192.36.148.17', '192.58.128.30', '193.0.14.129', '199.7.83.42', 
'202.12.27.33']
server_list = list(root_server)
size = 0
def get_ns_ip(domain):
    server_list = list(root_server)
    while server_list:
        for server in server_list:
            request = dns.message.make_query(domain, dns.rdatatype.A)
            try:
                response = dns.query.udp(request, server, 15)
            except dns.exception.Timeout:
                continue
            else:
                server_list.clear()
                if(response.answer):
                    for x in response.answer:
                        if "IN CNAME " in x.to_text():
                            y = x.to_text().split()
                            domain = y[-1]
                            server_list.extend(root_server)
                            break
                        else:
                            y = x.to_text().split()
                            return(str(y[-1]))
                elif(response.additional):
                    for x in response.additional:
                        if 'IN A ' in x.to_text():
                            server_list.extend(re.findall(r'\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}', x.to_text()))


def dns_recursive(domain, server_list,r_type):
    global size
    
    for server in server_list:
        request = dns.message.make_query(domain, r_type)
        try:
            response = dns.query.udp(request, server, 20)
        except dns.exception.Timeout:
            server_list.pop(0)
            continue
        else:
            server_list.clear()
            size+=sys.getsizeof(response)
            if(response.answer):
                for x in response.answer:
                    if "IN CNAME " in x.to_text():
                        #resolve cname to get the record
                        y = x.to_text().split()
                        dns_recursive(y[-1], root_server, r_type)
                    else:
                        print("QUESTION SECTION")
                        for z in response.question:
                            print(z)
                        print("ANSWER SECTION:")
                        print(x)
                        end = time.time()
                        print("Query time : %.2f"%((end-start)*1000) + "msec")
                        print("WHEN : {}".format(dt.datetime.strftime(dt.datetime.now(),"%a %B %d %H:%M:%S %Y")))
                        print("MSG SIZE rcvd : {}".format(size))
                break
            elif(response.additional):
                #get the next sevrer to hit from additional section
                for x in response.additional:
                    if 'IN A ' in x.to_text():
                        y = x.to_text().split()
                        server_list.extend( re.findall(r'\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}', x.to_text()))
                break
            elif(response.authority): 
                # When both answer and additional are empty, get the name server ip from authority
                temp = get_ns_ip(str(response.authority[0][0]))
                server_list.append(temp)
                break
    while server_list:
        dns_recursive(domain, server_list, r_type)

def main():
    global start
    start = time.time()
    domain = sys.argv[1]
    r_type = 0
    if not sys.argv[2] or sys.argv[2] == 'A':
        r_type = dns.rdatatype.A
    elif sys.argv[2] == 'NS':
        r_type = dns.rdatatype.NS
    elif sys.argv[2] == 'MX':
        r_type = dns.rdatatype.MX
    else:
        print("Invalid dns record type")
        sys.exit()
    dns_recursive(domain, server_list , r_type)

main()

# -*- coding: utf-8 -*-
"""
Created on Wed Sep 25 01:03:09 2019

@author: elang
"""

# -*- coding: utf-8 -*-
"""
Created on Mon Sep 23 15:08:37 2019

@author: elang
"""


import dns.name
import dns.message
import dns.query
import dns.flags
import re
import sys
import time

root_server = [ '198.41.0.4', '199.9.14.201', '192.33.4.12', '199.7.91.13', 
'192.203.230.10', '192.5.5.241', '192.112.36.4', '198.97.190.53',
'192.36.148.17', '192.58.128.30', '193.0.14.129', '199.7.83.42', 
'202.12.27.33']

server_list = list(root_server)
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


def dns_query(domain,ns_name,r_type):

    stop = 0
    start = 0
    ds_response = 0
    while(True):
        if(server_list == []):
            break
        #getting DNS Key record
        request = dns.message.make_query(ns_name, dns.rdatatype.DNSKEY, want_dnssec=True, payload = 2048)
        for server in server_list:
            try:
                response1 = dns.query.udp(request,server , 15)
            except dns.exception.Timeout:
                continue
            else:
                break
        if(response1.answer ==[]):
            print("DNSSEC not supported")
            break
        ksk = []
        for x in response1.answer[0]:
            if "257" in x.to_text():
                ksk.append(x)
        al=0
        #getting DS record from parent to verify the public KSK
        if(start != 0):
            ds_val = ds_response.authority[1]
            for x in ds_val:
                y = x.to_text()
                al = int(y.split()[1]) #getting hashing algo
                break
            hashed_ksk = []
            al_map = {
            5 : "SHA1",
            7 : "SHA1",
            8 : "SHA256"
            }
            for key in ksk:
                hashed_ksk.append(dns.dnssec.make_ds(ns_name, key, al_map[al]))
            for x in ds_val:
                y = x.to_text()
                al = y.split()[1]
                break
            ksk_verified = 0
            for i,x in enumerate(ds_val):
                for j,y in enumerate(hashed_ksk):
                    if(x == y):
                        ksk_verified = 1
                        break
            if(ksk_verified == 0):#if hashed ksk does not match with DS, DNSSEC failed
                print("DNSSEC Verification failed")
                break
        
        request = dns.message.make_query(domain, r_type, want_dnssec=True)
        for server in server_list:
            try:
                ds_response = dns.query.udp(request, server, 15)
            except dns.exception.Timeout:
                continue
            else:
                break
        name = dns.name.from_text(ns_name)
        rrset = 0
        rrsig = 0
        if(ds_response.answer):
            if(len(ds_response.answer) == 1):
                print("DNSSEC not supported")
                break
            rrset = ds_response.answer[0]
            rrsig = ds_response.answer[1]
            stop=1
        elif (ds_response.authority):
            rrset = ds_response.authority[1]
            rrsig = ds_response.authority[2]
        #verify rrset and rrsig with DNSKEY from name server
        try:
            dns.dnssec.validate(rrset,rrsig, {name:response1.answer[0]})
        except:
            print("DNSSEC Verification failed")
            break
        else:
            #After validating final answer, Print and Exit.
            if(stop == 1):
                print(ds_response.answer[0])
                break
        server_list.clear()
        if(ds_response.additional):
            for x in ds_response.additional:
                if 'IN A ' in x.to_text():
                    #y = x.to_text().split()
                    server_list.extend( re.findall(r'\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}', x.to_text()))
        else:
            #If additional and answer sections are empty, get name server ip from authority
            temp = get_ns_ip(str(ds_response.authority[0][0]))
            server_list.append(temp)

        if(ds_response.authority):
            for x in ds_response.authority:
                y = x.to_text().split()
                ns_name = y[0]
                break
        start+=1

def main():
    global start
    start = time.time()
    domain = sys.argv[1]
    x=dns.rdatatype.A
    dns_query(domain, ".", x)
main()

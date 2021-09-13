import dns.query
import dns.resolver
from dns.exception import DNSException
import dns
from constants import ROOT_SERVERS

def query_authoritative_ns (domain, log=lambda msg: None):

    default = dns.resolver.get_default_resolver()
    ns = default.nameservers[0]

    n = domain.split('.')
    print(ns)

    for i in range(len(n), 0, -1):
        sub = '.'.join(n[i-1:])
        log('-> Looking up %s on %s' % (sub, ns))
        query = dns.message.make_query(sub, dns.rdatatype.NS)
        #ns = '198.41.0.4'
        
        response = dns.query.udp(query, ns)
        rcode = response.rcode()
        if rcode != dns.rcode.NOERROR:
            if rcode == dns.rcode.NXDOMAIN:
                raise Exception('%s does not exist.' % (sub))
            else:
                raise Exception('Error %s' % (dns.rcode.to_text(rcode)))

        if len(response.authority) > 0:
            rrsets = response.authority
        elif len(response.additional) > 0:
            rrsets = [response.additional]
        else:
            rrsets = response.answer
        # Handle all RRsets, not just the first one
        for rrset in rrsets:
            for rr in rrset:
                if rr.rdtype == dns.rdatatype.SOA:
                    log('Same server is authoritative for %s' % (sub))
                elif rr.rdtype == dns.rdatatype.A:
                    ns = rr.items[0].address
                    log('Glue record for %s: %s' % (rr.name, ns))
                elif rr.rdtype == dns.rdatatype.NS:
                    authority = rr.target
                    ns = default.query(authority).rrset[0].to_text()
                    log('%s [%s] is authoritative for %s; ttl %i' % 
                        (authority, ns, sub, rrset.ttl))
                    result = rrset
                else:
                    # IPv6 glue records etc
                    #log('Ignoring %s' % (rr))
                    pass

    return result

import sys

def log (msg):
    sys.stderr.write(msg + u'\n')

for s in sys.argv[1:]:
    print (query_authoritative_ns (s, log))
'''
def func():
    
    domain = "www.cs.stonybrook.com"
    query = dns.message.make_query(sub, dns.rdatatype.A)
    server_ips = ROOT_SERVERS
    
    n = domain.split('.')
    print(ns)

    for i in range(len(n), 0, -1):
        sub = '.'.join(n[i-1:])
    
    for server_ip in server_ips:
        try:
            response = dns.query.udp(query, server_ip,timeout=5)
            for a in response.additional:
                b = a[0].address
                print(f"IP of {a.name} is : {b}") 
                
            #print(response)
            #print("--->>Type :"+str(type(response)))
            # print(f"Done for : {server_ip}")
            break
        except Exception as e:
            print(str(e))
            print(f"timed out for : {server_ip}")

#func()
'''
'''
domain = "com"
query = dns.message.make_query(domain, dns.rdatatype.A)
server_ip = ROOT_SERVERS[0]
response = dns.query.udp(query, server_ip,timeout=5)
a = response.additional[0]
b = a[0].address
print(f"IP of {a.name} is : {b}") 


domain = "stonybrook.com"
query = dns.message.make_query(domain, dns.rdatatype.A)
server_ip = ROOT_SERVERS[0]
response = dns.query.udp(query, b,timeout=5)

st = 0
a = response.additional[st]
while a.rdtype != 1:
    st = st + 1
    a = response.additional[st]
b = a[0].address
print(f"IP of {a.name} is : {b}") 




domain = "cs.stonybrook.com"
query = dns.message.make_query(domain, dns.rdatatype.A)
server_ip = ROOT_SERVERS[0]
response = dns.query.udp(query, b,timeout=5)

st = 0
a = response.answer[0]
while a.rdtype != 1:
    st = st + 1
    a = response.additional[st]
b = a[0].address
print(f"IP of {a.name} is : {b}") 


domain = "cs.stonybrook.com"
query = dns.message.make_query(domain, dns.rdatatype.A)
server_ip = ROOT_SERVERS[0]
response = dns.query.udp(query, b,timeout=5)

st = 0
a = response.answer[0]
while a.rdtype != 1:
    st = st + 1
    a = response.additional[st]
b = a[0].address
print(f"IP of {a.name} is : {b}") 

'''
import dns.query
import dns.resolver
import dns
from utils.root_servers_scrapper import get_root_servers
from constants import ROOT_SERVERS
import time

class DNSResolver:
    def __init__(self, use_cached_roots=True):
        self.use_cached_roots = use_cached_roots # If False, Root IPs will be scraped from website.
        self.timeout = 0.5

    def find_next_ips(self,additional_data):
        ips = [a[0].address for a in additional_data if a.rdtype == 1]
        return ips 
        
    def find_next_authorative_ip(self,authorative_data, current_index):
        for rrset in authorative_data:
            authority = rrset[current_index].target
            answer, answerFound = self.resolve_query(domain=str(authority))
            if answerFound:
                return answer,answerFound,current_index+1
            else:
                return -1, answerFound,current_index+1

    def find_authorative_ip(self,authorative_data):
        ips = []
        for rrset in authorative_data:
            for rr in rrset:
                authority = rr.target
                answer, answerFound = self.resolve_query(domain=str(authority))
                ips.append(answer)
        return ips
                
    def resolve_query(self,domain="google.co.jp"):
        query = dns.message.make_query(domain, dns.rdatatype.A)
        if self.use_cached_roots:
            root_servers = ROOT_SERVERS
        else:
            root_servers = get_root_servers()
        server_ips = root_servers.keys()
        ansFound = False
        while not ansFound:
            for server_ip in server_ips:
                try:
                    print(f"Trying : {domain} with IP : {server_ip}")
                    response = dns.query.udp(query, server_ip,timeout=self.timeout)
                    rcode = response.rcode()
                    if rcode != dns.rcode.NOERROR:
                        if rcode == dns.rcode.NXDOMAIN:
                            raise Exception(f"{domain} does not exist.")
                        else:
                            raise Exception("Error %s" % (dns.rcode.to_text(rcode)))
                    if len(response.answer) > 0:
                        ans = response.answer[0][0].address
                        ansFound = True
                        return ans, ansFound
                    elif len(response.additional) > 0:
                        server_ips = self.find_next_ips(response.additional)
                        break
                    if len(response.authority) > 0:

                        server_ips = self.find_authorative_ip(response.authority)
                        break    
                    else:
                        print("Issue with the DNS")    
                except Exception as e:
                    pass
                    print(f"Query timed out for Q : {domain}, IP : {server_ip}")

start = time.time()
dnsresolver = DNSResolver()
ans = dnsresolver.resolve_query()
end = time.time()

print(f"IP : {ans}, Total Time : {end-start} ms")

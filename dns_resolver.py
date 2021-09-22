from datetime import datetime
import dns.query
import dns
from utils.root_servers_scrapper import get_root_servers
from constants import ROOT_SERVERS
import time

class DNSResolver:
    """Class to resolve DNS queries
    """
    def __init__(self, use_stored_roots : bool = True, timeout : float = 0.5):
        self.use_stored_roots = use_stored_roots # If False, Root IPs will be scraped from website.
        self.timeout = timeout  # Timeout for DNS queries in seconds
        
    def __process_ans(self, ans, query_type):
        if query_type=='A':
            return [record[0].address for record in ans]
        else:
            return [str(ele) for ele in ans[0]]
    
    def find_ip_from_additional_data(self, additional_data : list):
        """Returns IPs extracted from Addition Data

        Args:
            additional_data (list): Additional Data Received from DNS response

        Returns:
            dict: dict of <IP, Hostname>
        """
        ips = dict()
        ips = {rrset[0].address:str(rrset.name) for rrset in additional_data if rrset.rdtype == 1}  # 1 : A Record
        return ips 
        
    def find_ip_from_authoritative_data(self, authoritative_data : list, resolveAll : bool = False):
        """Returns dict of <IP, Hostname> from authoritative Data. 

        Args:
            authoritative_data (list): authoritative Data received from DNS Query Response
            resolveAll (boolean, optional): If True : Resolves all Name Servers addresses
                                            If False : Resolves 1st Name Server address (Default)

        Returns:
            dict: dict of <IP, Hostname>
        """
        ips = dict()
        for rrset in authoritative_data:
            for rr in rrset:
                #TODO : Handle SOA Case
                try:
                    domain = rr.mname
                except Exception:
                    domain = str(rr) 
                answer, answerFound = self.resolve_query(domain, "A")
                if answerFound:
                    ips[answer] = domain
                    if not resolveAll:
                        return ips
        return ips
                
    def resolve_query(self, domain:str,query_type:str='A'):
        """Used to resolve the given DNS query

        Args:
            domain (str): hostname/website name
            query_type (str) : Type of DNS query. default : 'A'
        Raises:
            Exception: 
        Returns:
            str : answer of query
            boolean : True if IP is found
        """
        # Create a query
        query = dns.message.make_query(domain,query_type)
        # Get the root server IPs
        if self.use_stored_roots:
            root_servers = ROOT_SERVERS
        else:
            root_servers = get_root_servers()

        ansFound = False  # Boolean variable for denoting answer found or not
        server_ips = root_servers
        try:
            while not ansFound:
                for server_ip in server_ips.keys():
                    try:
                        print(f"Query : {domain} with IP : {server_ip} Type : {query_type} Name : {server_ips[server_ip]}")
                        response = dns.query.udp(query, server_ip, timeout=self.timeout)
                        rcode = response.rcode()
                        if rcode != dns.rcode.NOERROR:
                            if rcode == dns.rcode.NXDOMAIN:
                                raise Exception(f"{domain} does not exist.")
                            else:
                                raise Exception("Error %s" % (dns.rcode.to_text(rcode)))
                        if len(response.answer) > 0:
                            ans = response.answer
                            ansFound = True
                            return self.__process_ans(ans, query_type), ansFound
                        elif len(response.additional) > 0:
                            server_ips = self.find_ip_from_additional_data(response.additional)
                            break
                        elif len(response.authority) > 0:
                            server_ips = self.find_ip_from_authoritative_data(response.authority)
                            break    
                        else:
                            print("Issue with the DNS")    
                    except Exception as e:
                        if isinstance(e, dns.exception.Timeout):
                            print(f"Query timed out for Q : {domain}, IP : {server_ip}")
                        else:
                            print(e)
                            print("Server error for :"+server_ip)
        except Exception as e:
            return str(e), False

def mydig(domain,query_type='A'):
    """Replication of `dig` command. Writes output to output.txt

    Args:
        domain (str): website name (query)
        query_type (str): type of query. Defaults to 'A'. Options : (A,MX,NS)
    """
     
    dns_resolver = DNSResolver()
    today = datetime.today()
    day = today.strftime("%a")
    mon = today.strftime("%b")
    date = today.strftime("%d")
    year = today.strftime("%Y")
    
    with open("output.txt","a+") as f:
        f.write("QUESTION SECTION\n")
        f.write(f"{domain}      IN      A\n")    
        start = time.time()
        ans, ansFound = dns_resolver.resolve_query(domain,query_type)
        if not ansFound:
            print("No Answer Found for the given query")
            ans = str(ans)
        else:
            print(ans)
        end = time.time()
        f.write("ANSWER SECTION\n")
        f.write(f"{domain}      IN      A   {ans}\n")
        f.write(f"Query time: {round(end-start,4)} seconds\n") 
        f.write(f"WHEN: {day} {mon} {date} {today.hour}:{today.minute}:{today.second} {year}\n")
    

import sys
if __name__=='__main__':
    if len(sys.argv) < 2:
        domain = 'verisigninc.com'
    else:
        domain = sys.argv[1]
    if len(sys.argv) < 3:
        query_type = 'NS'
    else:
        query_type = sys.argv[2]
    
    mydig(domain, query_type)
    
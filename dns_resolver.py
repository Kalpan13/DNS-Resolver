from datetime import datetime
import dns.query
import dns.resolver
import dns
from utils.root_servers_scrapper import get_root_servers
from constants import ROOT_SERVERS
import time
from loguru import logger

logger.disable("dns_resolver") # To disable logs
#logger.disable("__main__") # To disable logs

class DNSResolver:
    """Class to resolve DNS queries
    """
    def __init__(self, use_stored_roots=True, timeout=0.5):
        self.use_stored_roots = use_stored_roots # If False, Root IPs will be scraped from website.
        self.timeout = timeout

    def find_next_ips(self,additional_data):
        """Returns IPs extracted from Addition Data

        Args:
            additional_data (list): Additional Data Received from DNS response

        Returns:
            dict: dict of <IP, Hostname>
        """
        ips = dict()
        ips = {rrset[0].address:str(rrset.name) for rrset in additional_data if rrset.rdtype == 1}  # 1 : A Record
        return ips 
        
    def find_next_authoritative_ip(self,authoritative_data, current_index):
        for rrset in authoritative_data:
            authority = rrset[current_index].target
            answer, answerFound = self.resolve_query(domain=str(authority))
            if answerFound:
                return answer,answerFound,current_index+1
            else:
                return -1, answerFound,current_index+1

    def find_authoritative_ip(self,authoritative_data, resolveAll=False):
        """Returns dict of <IP, Hostname> from authoritative Data

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
                authority = rr.target
                answer, answerFound = self.resolve_query(domain=str(authority))
                if answerFound:
                    ips[answer] = str(rr)
                    if not resolveAll:
                        return ips
        return ips
                
    def resolve_query(self,domain):
        """Used to resolve the given DNS query

        Args:
            domain (str): hostname/website name

        Raises:
            Exception: 

        Returns:
            str : IP address of query
            boolean : True if IP is found
        """
        # Create a query
        query = dns.message.make_query(domain, dns.rdatatype.A)
        print("QUESTION SECTION")
        print(f"{domain}      IN      A")
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
                        print(f"Trying : {domain} with IP : {server_ip}")
                        response = dns.query.udp(query, server_ip, timeout=self.timeout)
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
                        elif len(response.authority) > 0:
                            server_ips = self.find_authoritative_ip(response.authority)
                            break    
                        else:
                            print("Issue with the DNS")    
                    except Exception as e:
                        if isinstance(e, dns.exception.Timeout):
                            print(f"Query timed out for Q : {domain}, IP : {server_ip}")
                        else:
                            print("Server error for :"+server_ip)
        except Exception as e:
            return str(e), False

def mydig(domain,q_type='A'):
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
        ans, _ = dns_resolver.resolve_query(domain)
        end = time.time()
        f.write("ANSWER SECTION\n")
        f.write(f"{domain}      IN      A   {ans}\n")
        f.write(f"Query time: {round(end-start,4)} seconds\n") 
        f.write(f"WHEN: {day} {mon} {date} {today.hour}:{today.minute}:{today.second} {year}\n")
    


if __name__=='__main__':
    domain = "www.google.co.jp."
    mydig(domain)
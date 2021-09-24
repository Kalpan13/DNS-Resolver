from datetime import datetime
import dns.query
import dns
from constants import ROOT_SERVERS
import time
import sys

class DNSResolver:
    """Class to resolve DNS queries
    """
    def __init__(self, use_stored_roots : bool = True, timeout : float = 0.5):
        self.use_stored_roots = use_stored_roots # If False, Root IPs will be scraped from website.
        self.timeout = timeout  # Timeout for DNS queries in seconds
        
    def process_ans(self, rrset, query_type):
        ans = []
        for rr in rrset:
            for record in rr:
                ans.append(str(record))
        return ans
            
    def find_IP_from_additional_data(self, additional_data : list):
        """Returns IPs extracted from Addition Data

        Args:
            additional_data (list): Additional Data Received from DNS response

        Returns:
            list: list of IPs
        """
        IPs = list()
        IPs = [rrset[0].address for rrset in additional_data if rrset.rdtype == 1]  # 1 : A Record
        return IPs 
        
    def find_IP_from_authoritative_data(self, authoritative_data : list, resolveAll : bool = False):
        """Returns list of IPs resolved using authoritative data. 

        Args:
            authoritative_data (list): authoritative Data received from DNS Query Response
            resolveAll (boolean, optional): If True : Resolves all Name Servers addresses
                                            If False : Resolves 1st Name Server address (Default)

        Returns:
            list: list of IPs
        """
        IPs = []
        resolveAll = True # Resolve all NS records
        SOA_records = []
        for rrset in authoritative_data:
            if rrset.rdtype == 2: # NS record
                is_SOA_record = False
                for rr in rrset:
                    domain = str(rr) 
                    answer, answerFound, _ = self.resolve_query(domain, "A")
                    if answerFound:
                        IPs.extend(answer)
                        if not resolveAll:
                            return IPs, []
                           
        for rrset in authoritative_data:
            if rrset.rdtype == 6: # SOA record
                for rr in rrset:
                    domain = str(rr)
                    SOA_records.append(domain)

        return IPs, SOA_records
                
    def resolve_query(self, domain:str, query_type:str='A'):
        """Used to resolve the given DNS query

        Args:
            domain (str): hostname/website name
            query_type (str) : Type of DNS query. default : 'A'
        
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
            from utils.root_servers_scrapper import get_root_servers
            root_servers = get_root_servers()

        ans_found = False  # True if answer is else False 
        server_IPs = list(root_servers.keys())
        resolve_all = True # True for ROOT_SERVERs 

        try:
            while not ans_found:
                for server_IP in server_IPs:
                    try:
                        response = dns.query.udp(query, server_IP, timeout=self.timeout)
                        
                        rcode = response.rcode()
                        if rcode != dns.rcode.NOERROR:
                            if rcode == dns.rcode.NXDOMAIN:
                                raise Exception(f"{domain} does not exist.")
                            else:
                                raise Exception("Error %s" % (dns.rcode.to_text(rcode)))
                        resolve_all = True 

                        if len(response.answer) > 0:
                            ans = response.answer
                            ans_found = True
                            
                            return self.process_ans(ans, query_type), ans_found, sys.getsizeof(response)

                        elif len(response.authority) > 0:
                            if len(response.additional) > 0:
                                next_IPs = self.find_IP_from_additional_data(response.additional)
                                if len(next_IPs) > 0 and next_IPs!= server_IPs:
                                    server_IPs = next_IPs
                                    break
                            else:
                                next_IPs, SOA_records = self.find_IP_from_authoritative_data(response.authority)  
                                if len(next_IPs) > 0:
                                    server_IPs = next_IPs
                                if len(SOA_records) > 0:
                                    return SOA_records, True, sys.getsizeof(response)
                                break


                    except Exception as e:
                        if not resolve_all:
                            return str(e), False, 0
                        if isinstance(e, dns.exception.Timeout):
                            print(f"Query timed out for Q : {domain}, IP : {server_IP}")
                        else:
                            print("Server error for :"+server_IP)
        except Exception as e:
            return str(e), False, 0

def mydig(domain,query_type):
    """Replication of `dig` command. Writes output to command prompt

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
    
    print(";; QUESTION SECTION")
    print(f";{domain}      IN      {query_type}")    
    start = time.time()
    ans, ans_found, msg_size = dns_resolver.resolve_query(domain,query_type)
    end = time.time()
    print("\n;; ANSWER SECTION")
    if not ans_found:
        print(";; No Answer Found for the given query")
        print(f";; error : {ans}")
    else:
        for record in ans:
            print(f";{domain}      IN      {query_type}    {record}")
        print(f"\n;; Query time: {round((end-start)*1000,2)} msec") 
        print(f";; WHEN: {day} {mon} {date} {today.hour}:{today.minute}:{today.second} {year}")
        print(f";; MSG SIZE rcvd: {msg_size}")


if __name__=='__main__':
    if len(sys.argv) < 2:
        print("Please enter domain name and query type")
    else:
        domain = sys.argv[1]
    if len(sys.argv) < 3:
        print("Please enter domain name and query type")
    else:
        query_type = sys.argv[2]
    
    mydig(domain, query_type)
    
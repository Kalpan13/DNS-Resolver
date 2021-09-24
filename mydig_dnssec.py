from symbol import async_stmt
import dns
import dns.query
from constants import ROOT_SERVERS
import sys
import time
from datetime import datetime

class DNSSecError(Exception):
    """
    Custom Exception for DNSSEC related errors
    """
    def __init__(self, message : str):
        super().__init__(message)
        
class DNSSECResolver():
    
    def __init__(self, use_stored_roots : bool = True, timeout : float = 0.5):
        self.use_stored_roots = use_stored_roots # If False, Root IPs will be scraped from website.
        self.timeout = timeout  # Timeout for DNS queries in seconds
    
    def process_ans(self, rrset):
        ans = []
        for rr in rrset:
            for record in rr:
                ans.append(record.to_text())
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
        """Returns list of IPs from authoritative data. 

        Args:
            authoritative_data (list): authoritative Data received from DNS Query Response
            resolveAll (boolean, optional): If True : Resolves all Name Servers addresses
                                            If False : Resolves 1st Name Server address (Default)

        Returns:
            list: list of IPs
        """
        IPs = []
        for rrset in authoritative_data:
            if rrset.rdtype == 2: # NS record
                for rr in rrset:
                    #TODO : Handle SOA Case
                    domain = str(rr) 
                    answer, answerFound, _ = self.dig_dnssec(domain, "A")
                    answer = self.process_ans(answer.answer)
                    if answerFound:
                        IPs.extend(answer)
                        if not resolveAll:
                            return IPs
                    else:
                        return IPs
        return IPs

    def verify_rrset(self, q_response, dns_response, type):
        """To Verify RRSet with RRSIG of RRSet 

        Args:
            q_response : Response of RRSet query
            q_name : query_name of zone
            dns_response : Response of DNSKEY query
            type : type of RRSet

        Returns:
            bool: True if verified else False
        """
  
        key = dns_response.answer[0].name
        if type=='DS':
            rrset = q_response.authority[1] 
            rrsig = q_response.authority[2]
            #key = dns_response.answer[0].name
        else:
            rrset = q_response.answer[0] 
            rrsig = q_response.answer[1]
            #key = q_response.answer[0].name
        try:
            # Validate RRSet of Type DS using ZSK from dns_response
            dns.dnssec.validate(rrset, rrsig, {key:dns_response.answer[0]}) 
            return True
        except Exception as e:
            return False

    def verify_KSK(self, parent_ds_record, DNSKEY_record, q_name):
        """To Verify KSK from Parents DS record

        Args:
            parent_ds_record : DS record from Parent zone  
            DNSKEY_record : DNSKEY record from zone
            q_name : query name

        Returns:
            bool: True if verified else False
        """
        if parent_ds_record is None:
            return True  # Special case for Root servers -> KSK is already verified
        else:
            if len(parent_ds_record) == 0:
                return False

            if len(DNSKEY_record) == 0:
                return False

            KSK = None
            keys = DNSKEY_record[0].items
            for key in keys:
                # Filtering KSK key from DNSKey Response
                if key.flags == 257: # KSK : 257, ZSK : 256
                    KSK = key
            if KSK == None:
                return False

            parent_ds_record = list(parent_ds_record.items.keys())
            algorithm = ""
            if len(parent_ds_record) == 0:
                return False
            else:
                if parent_ds_record[0].digest_type == 1:
                    algorithm="SHA1"
                elif parent_ds_record[0].digest_type == 2:
                    algorithm="SHA256"

            # Create a new DS record from KSK
            new_ds_record = dns.dnssec.make_ds(q_name, KSK, algorithm)

            # Match Created DS record with parent's DS record
            if new_ds_record.digest != parent_ds_record[0].digest:
                return False

            return True

    def dig_dnssec(self, query_name, query_type):
        
        server_IPs = []
        if not self.use_stored_roots:
            from utils.root_servers_scrapper import get_root_servers
            server_IPs = get_root_servers().keys()
        else:
            server_IPs = list(ROOT_SERVERS.keys())
        
        parent_ds_record = None # To maintain DS record of Zone queried from Parent
        sp = 1
        dns_q_name = dns.name.from_text(query_name)
        labels = dns_q_name.labels

        while sp <= len(labels):
            
            q_name = str(dns_q_name.split(sp)[1])
            for server_IP in server_IPs:
                
                try:
                    query = dns.message.make_query(query_name, query_type, want_dnssec=True)
                    q_response = dns.query.udp(query, server_IP, timeout=self.timeout)  # Request RRSet of `query_type` 
                    dnskey_query = dns.message.make_query(q_name, 'DNSKEY', want_dnssec=True)
                    dnskey_response = dns.query.udp(dnskey_query, server_IP, timeout=self.timeout) # Request RRSet of DNSKey
                    
                    # Validate Response
                    if q_response.rcode() != dns.rcode.NOERROR and dnskey_response.rcode() != dns.rcode.NOERROR:
                        if q_response.rcode() == dns.rcode.NXDOMAIN:
                            raise Exception(f"{query_name} does not exist.")                
                        else:
                            raise Exception(f"Error in response for {server_IP}. SkIpping..!")
                    
                    if dnskey_response.rcode() == dns.rcode.NXDOMAIN:
                            raise DNSSecError("DNSSEC not supported")

                    if len(dnskey_response.answer) > 0: 
                        # Validate DNSKey Record (Self Signed)
                        if not self.verify_rrset(dnskey_response, dnskey_response, "DNSKEY"):
                            raise DNSSecError("DNSSEC not supported")
                    else:
                        raise DNSSecError("DNSSEC not supported")
                    
                    # Verify KSK with Parent Zone's DS Record
                    if not self.verify_KSK(parent_ds_record, dnskey_response.answer, q_name):
                        raise DNSSecError("DNSSec verification failed")
                            
                    if len(q_response.answer) > 0:
                        # Answer found:
                        if not self.verify_rrset(q_response, dnskey_response, "RRSet"):
                            raise DNSSecError("DNSSEC not supported")
                        
                        return q_response, True, sys.getsizeof(q_response)

                    elif len(q_response.authority) > 0:
                        # Verify DS record with ZSK from dnskey_response 
                        if not self.verify_rrset(q_response, dnskey_response, "DS"):
                            raise DNSSecError("DNSSEC not supported")
                        
                        if len(q_response.additional) > 0:
                            # Additional Section (To get IPs of child zone servers)
                            server_IPs = self.find_IP_from_additional_data(q_response.additional)
                        else:
                            # No IPs found from additional section -> Resolve Authority Section
                            server_IPs = self.find_IP_from_authoritative_data(q_response.authority)
                            if len(server_IPs) == 0:
                                raise DNSSecError("DNSSEC not supported")
                        
                        sp += 1
                        parent_ds_record = q_response.authority[1]
                        break 
                except DNSSecError as e:
                    return str(e), False, 0
                    
def mydig(domain, query_type):
    """Replication of `dig` command. Writes output to command prompt

    Args:
        domain (str): website name (query)
        query_type (str): type of query. Defaults to 'A'. Options : (A,MX,NS)
    """
     
    today = datetime.today()
    day = today.strftime("%a")
    mon = today.strftime("%b")
    date = today.strftime("%d")
    year = today.strftime("%Y")
    start = time.time()
    dnssec_resolver = DNSSECResolver(use_stored_roots=True, timeout=0.5)
    end = time.time()
    ans, ans_found, msg_size = dnssec_resolver.dig_dnssec(domain, query_type)
    
    print(";; QUESTION SECTION")
    print(f";{domain}      IN      {query_type}")    
    
    print("\n;; ANSWER SECTION")
    if not ans_found:
        print(";; No Answer Found for the given query")
        print(f";; error : {ans}")
    else:
        print(ans)
        print(f"\n;; Query time: {round((end-start)*1000,2)} msec") 
        print(f";; WHEN: {day} {mon} {date} {today.hour}:{today.minute}:{today.second} {year}")
        print(f";; MSG SIZE rcvd: {msg_size}")


if __name__ == '__main__':

    if len(sys.argv) < 2:
        print("Please enter domain name and query type")
    else:
        domain = sys.argv[1]
    if len(sys.argv) < 3:
        print("Please enter domain name and query type")
    else:
        query_type = sys.argv[2]
    mydig(domain, query_type)
    
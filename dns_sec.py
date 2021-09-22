import dns
import dns.query
from utils.root_servers_scrapper import get_root_servers
from constants import ROOT_SERVERS
# hard-coded root KSK
#root_KSK = dns.rrset.from_text('.', 15202, 'IN', 'DNSKEY', '257 3 8 AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29euxhJhVVLOyQbSEW0O8gcCjF FVQUTf6v58fLjwBd0YI0EzrAcQqBGCzh/RStIoO8g0NfnfL2MTJRkxoX bfDaUeVPQuYEhg37NZWAJQ9VnMVDxP/VHL496M/QZxkjf5/Efucp2gaD X6RS6CXpoY68LsvPVjR0ZSwzz1apAzvN9dlzEheX7ICJBBtuA6G3LQpz W5hOA2hzCTMjJPJ8LbqF6dsV6DoBQzgul0sGIcGOYl7OyQdXfZ57relS Qageu+ipAdTTJ25AsRTAoub8ONGcLmqrAmRLKBP1dfwhYB4N7knNnulq QxA+Uk1ihz0=')

domain = 'verisigninc.com'
NS_ip = '192.42.177.30'
query = dns.message.make_query(domain,'DNSKEY',want_dnssec=True)
response = dns.query.udp(query,NS_ip)
dns_key_rrset = response.answer[0]
#dns_KSK = response.answer[0][1]
dns_key_rrsig = response.answer[1]
key = dns.name.from_text(domain)
dns.dnssec._validate(dns_key_rrset, dns_key_rrsig, {key:response.answer[0]})
print(response)

query_A = dns.message.make_query(domain,'A',want_dnssec=True)
response_A = dns.query.udp(query_A,NS_ip)
rrset = response_A.answer[0]
rrsig = response_A.answer[1]
dns.dnssec._validate(dns_key_rrset, dns_key_rrsig, {key:response.answer[0]})

parent_IP = '192.12.94.30'
query = dns.message.make_query('verisigninc.com','DS',want_dnssec=True)
response_parent = dns.query.udp(query,parent_IP)
print(response_parent)
#avishek santhalia
                    
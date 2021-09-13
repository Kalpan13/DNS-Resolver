import dns.resolver
name = 'stonybrook.com'
for qtype in ['NS']:
    answer = dns.resolver.query(name,qtype, raise_on_no_answer=False)
    if answer.rrset is not None:
        print(answer.rrset)
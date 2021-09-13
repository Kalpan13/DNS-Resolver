from pydoc import resolve
import pandas as pd
import time
from constants import top_25_sites
from dns_resolver import DNSResolver
from tqdm import tqdm
from statistics import mean

def calculate_resolve_time(sites_list,n=10):
    df = pd.DataFrame()
    dnsresolver = DNSResolver()
    for site in tqdm(sites_list):
        resolve_time = []
        for i in range(0,n):
            start = time.time()
            ans, _ = dnsresolver.resolve_query(site)
            end = time.time()
            resolve_time.append(end-start)
        ans_dict = dict() 
        ans_dict["website"] = site
        #ans_dict["execution_time"] = (end-start)
        ans_dict["IP"] = ans
        ans_dict["avg"] = mean(resolve_time)
        ans_dict["resolve_times_list"] = resolve_time
        df = df.append(ans_dict, ignore_index=True)
    
    df.to_csv("DNSResolver-Analysis.csv")
    
calculate_resolve_time(top_25_sites)

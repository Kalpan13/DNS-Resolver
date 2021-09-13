import pandas as pd
import requests

def get_root_servers():
    
    url='https://www.iana.org/domains/root/servers'
    r = requests.get(url)
    df_list = pd.read_html(r.text) 
    df = df_list[0]
    df["IP"] = df["IP Addresses"].str.split(",", n = 1)
    df[["IPv4","IPv6"]] = df["IP Addresses"].str.split(',', expand=True)
    return pd.Series(df["Hostname"].values,index=df["IPv4"]).to_dict()

    
if __name__=='__main__':
    print(get_root_servers())
    with open("Output.txt", "w") as text_file:
        text_file.write(str(get_root_servers()))
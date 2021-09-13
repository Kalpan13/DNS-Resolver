import pandas as pd
import requests

def get_top_n_sites(n=25):
    
    url='https://www.alexa.com/topsites'
    r = requests.get(url)
    df_list = pd.read_html(r.text) 
    df = df_list[0]
    return df
    
if __name__=='__main__':
    print(get_top_n_sites())
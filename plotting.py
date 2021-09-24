
# defining the libraries
import numpy as np
import matplotlib.pyplot as plt
import pandas as pd


df = pd.read_csv("DNSResolver-Analysis.csv")

mydig_resolver = df["mydig avg"]
local_resolver = df["local DNS avg"]
google_resolver = df["google DNS avg"]

# data = list(data)
# data = [x/1000 for x in data]
# getting data of the histogram
count1, bins_count1 = np.histogram(mydig_resolver, bins=25)
count2, bins_count2 = np.histogram(local_resolver, bins=25)
count3, bins_count3 = np.histogram(google_resolver, bins=25)
  
# finding the PDF of the histogram using count values
pdf1 = count1 / sum(count1)
pdf2 = count2 / sum(count2)
pdf3 = count3 / sum(count3)
  
# using numpy np.cumsum to calculate the CDF
# We can also find using the PDF values by looping and adding
cdf1 = np.cumsum(pdf1)
cdf2 = np.cumsum(pdf2)
cdf3 = np.cumsum(pdf3)
 
# plotting PDF and CDF
plt.plot(bins_count1[1:], cdf1, label="mydig resolver")
plt.plot(bins_count2[1:], cdf2, label="local resolver")
plt.plot(bins_count3[1:], cdf3, label="google resolver")
plt.xlabel("Query Time (sec) ")
plt.ylabel("CDF")
plt.grid()
plt.locator_params(axis='y', nbins=10)
plt.locator_params(axis='x', nbins=15)
plt.legend()
plt.savefig('destination_path.svg', format='svg', dpi=1000)
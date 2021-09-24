declare -a top_25_sites=("google.com" "youtube.com" "tmall.com" "baidu.com" "qq.com" "sohu.com" "facebook.com" "taobao.com" "360.cn" "jd.com" "amazon.com" "yahoo.com" "wikipedia.org" "weibo.com" "sina.com.cn" "zoom.us" "xinhuanet.com" "live.com" "netflix.com" "reddit.com" "instagram.com" "microsoft.com" "office.com" "google.com.hk" "panda.tv") 
## now loop through the above array
for (( j = 1 ; j <= 10; j++ ))
 do
for i in "${top_25_sites[@]}"
do
  
   
  echo -n "$j "
   dig @8.8.8.8 $i  +noall +answer +stats | \
  awk '$3 == "IN" && $4 == "A"{website=$1}/Query time:/{t=$4 " " $5}END{print website,t}' >> ans_google.txt
    sleep 10s
  done 
done

dig $i  +noall +answer +stats | \
  awk '{website=$1}/Query time:/{t=$4 " " $5}END{print website, t}'

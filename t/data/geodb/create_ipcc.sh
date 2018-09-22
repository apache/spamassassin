#!/bin/sh

# IP::Country::DB_File ipcc.db
echo '2.3|arin|1537592415823|142286|19700101|20180922|-0400
arin|US|ipv4|8.0.0.0|8388608|19921201|allocated|e5e3b9c13678dfc483fb1f819d70883c
arin|US|ipv6|2001:4860::|32|20050314|allocated|9d99e3f7d38d1b8026f2ebbea4017c9f' >delegated-arin
true >delegated-ripencc
true >delegated-afrinic
true >delegated-apnic
true >delegated-lacnic
build_ipcc.pl -b -d .


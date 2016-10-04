#!/bin/bash
#this script checks for massive outgoing connections to nameservers
#it then finds the domains queried and blocks those queries
#using iptables and string matching
#source: http://blog.schmuffeln.de/2014/06/dns-amplification-attack-for-random-subdomains/

#block the sources of the queries or their targets?
#sources,targets
block="sources"

#max 50 connections to one DNS server allowed
limit="50"

#threshold for identical A queries
threshold="10"

#blacklist file
blacklist="/etc/domain_blacklist"

#sources file, users who query the blacklisted domains
sources="/etc/domain_sources"

#what to query?
queries="A? TXT?"

#interface for tcpdump
interface="eth1"

#number of packets to tcpdump capture
packets="10"

#whitelist domains, prevent from being listed in firewall
whitelist="ixhash.net com.cn com.hk"

#list of DNS servers with open conections
list=$(netstat -an |grep 53|grep -v udp6|awk '{print $5}'|cut -d':' -f1|sort|uniq|grep -E "[[:digit:]]"|grep -v "0.0.0.0")

for ip in ${list}
do
        connections=$(netstat -an|grep 53|grep -v udp6|grep -v 2001|grep $ip|wc -l)
        if [[ $connections  -gt ${limit} ]]
        then
                #show number of open connections to this DNS
                echo -e "IP: $ip\tCONS: $connections"
                for query in $queries
                do
                        domains=$(tcpdump -i $interface -n -c $packets host $ip and port 53 2>/dev/null|grep "$query"|awk '{print $(NF-1)}')
                        if [[ ! $domains ]]
                        then
                                continue
                        else
                                break
                        fi
                done

                #show what FQDN are queried
                echo -e "${domains}"
                #calculate identical queried domains in dump
                queried_num=$(echo -e "$domains"|awk '{print $(NF-1)}'|awk -F. '{print $(NF-2) "." $(NF-1)}'|wc -l)
                if [[ $queried_num -eq $threshold ]]
                then
                        queried_domain=$(echo -e "$domains"|awk '{print $(NF-1)}'|awk -F. '{print $(NF-2) "." $(NF-1)}'|uniq)
                        #add domain to blacklist if it does not exist
                        if [[ ! $(grep "$queried_domain" $blacklist) ]]
                        then
                                echo $queried_domain >> $blacklist
                        fi
                fi

        fi
done

#find sources who query those domains
for i in $(cat /etc/domain_blacklist)
do
        sources_list=$(tcpdump -i eth1 -P in -s 0 -l -n -c1000 port 53 2>/dev/null|grep $i|cut -d' ' -f 3|cut -d'.' -f1-4|sort -u)
        for j in $sources_list
        do
                if [[ ! $(grep $j $sources) ]]
                then
                        echo $j >>$sources
                fi
        done
done


#done grabbing domains that are abused, now lets block the complete list!
if [[ $block == "targets" ]]
then

        for entry in $(cat $blacklist)
        do
                if [[ $whitelist =~ $entry ]]
                then
                        continue
                fi

                echo "Blocking $entry"

                #careful, we have to separate domain and TLD and convert separately to HEX.
                #if TLD is 2 characters long e.g. cn then hex value 02 is used for dot, if 3 e.g. com then 03
                domain=$(echo $entry|cut -d'.' -f1)
                tld=$(echo $entry|cut -d'.' -f2)
                echo "Domain is: $domain, TLD is $tld"

                #find length of tld
                tld_length=${#tld}
                #convert to hex
                domain_hex=$(echo -n $domain|xxd -p)
                tld_hex=$(echo -n $tld|xxd -p)
                if [[ $tld_length -eq 2 ]]
                then
                        dot_hex="02"
                fi

                if [[ $tld_length -eq 3 ]]
                then
                        dot_hex="03"
                fi

                echo "hex domain: $domain_hex, tld hex: $tld_hex, length tld: $tld_length"

                #check if rule exists
                iptables -C INPUT -p udp --dport 53 -m string --from 34 --to 90 --algo bm --hex-string "|$domain_hex$dot_hex$tld_hex|" -j DROP -m comment --comment "Drop DNS $entry"
                if [[ $? -gt 0 ]]
                then
                        iptables -I INPUT -p udp --dport 53 -m string --from 34 --to 90 --algo bm --hex-string "|$domain_hex$dot_hex$tld_hex|" -j DROP -m comment --comment "Drop DNS $entry"
                fi

        done
elif [[ $block == "sources" ]]
then
        for entry in $(cat $sources)
        do
                if [[ $whitelist =~ $entry ]]
                then
                        continue
                fi

                echo "Blocking $entry"
                #check if rule exists
                iptables -C INPUT -p udp --dport 53 -s $entry  -j DROP -m comment --comment "Drop DNS query $entry"
                if [[ $? -gt 0 ]]
                then
                        iptables -I INPUT -p udp --dport 53 -s $entry -j DROP -m comment --comment "Drop DNS query $entry"
                fi
        done


fi

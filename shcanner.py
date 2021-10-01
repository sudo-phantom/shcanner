import nmap
from concurrent.futures import ThreadPoolExecutor
import os
import sys

#from xml.etree import ElementTree as ET


#create filesystem
try:
    os.makedirs("./py-results")
except FileExistsError:
    # directory already exists
    pass
query = "Up"
temp = []
def find_live():
        nm = nmap.PortScanner()
        nm.scan("nmap -sn -iL scope.txt -4 -oG ./py-results/livehosts.gnmap --privileged -vv -oN ./py-results/currently-acive.nmap")
        nm.scaninfo()
        print("discovering live hosts: \n")
#search for hosts that are UP   


        with open('./py-results/livehosts.gnmap', 'r') as grep:
            for line in grep:
             if query in line:
                bar = ''.join(line).strip()
                #temp.append(bar.split(' ', 1))
                bar_title, bar_ip, bar_status, bar_stat = bar.split(' ')
                print(bar_ip + ' - ' + bar_stat)
                temp.append(bar_ip)
                file = open('./py-results/up.txt', 'w')
                file.write('\n'.join(temp))
                file.close()

#section to find web servers 
def find_webhosts(): 
    
    print("finding services: " )
    
    nm = nmap.PortScanner()
    nm.scan('nmap -sV -iL ./py-results/up.txt -sC -vv -4 -p 80,443,8080,8443,8000,8888 --script ssl-enum-ciphers --privileged -oN ./py-results/webhost.nmap')
    print(nm.csv(),  file=open('./py-results/livewebhosts.csv', 'w'))

               
            # Need to add parsing to compare against weak-ciphers.txt

# perform traceroute of the hosts within scope            

def trace_hosts():
    nm = nmap.PortScanner()
    nm.scan('nmap -sn -iL scope.txt -4 -vv 20 --traceroute --privileged -oN ./py-results/trace-hosts.nmap')
    print(nm.csv(),  file=open('./py-results/trace-hosts.csv', 'w'))
    print("finding routes: " )


#full scan
temp_bar = []
def find_full_scan(): 
        nm = nmap.PortScanner()
        nm.scan('nmap -sV -sC -iL ./py-results/up.txt -4 -vv --privileged --top-ports 50  -oN ./py-results/full-hosts.nmap')
        print(nm.csv(),  file=open('./py-results/Full-hosts.csv', 'w'))
        print('scanning full host list for \n')

    

if __name__ == "__main__":
    find_live()
    with ThreadPoolExecutor(max_workers= 7) as executor:
        executor.map(find_webhosts())
        executor.map(trace_hosts())
        executor.map(find_full_scan())

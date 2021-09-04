import nmap
import os
import sys
import itertools
import re
import xmltodict, json

#from xml.etree import ElementTree as ET


#create filesystem
try:
    os.makedirs("./py-results")
except FileExistsError:
    # directory already exists
    pass

def find_live():
#test for live hosts
    with open('scope.txt', 'r') as f:
        for line in f:
            nm = nmap.PortScanner()
            nm.scan(hosts=line, arguments="-sn -iL scope.txt -4 -oG ./py-results/livehosts.gnmap -vv -oN ./py-results/currently-acive.nmap")
            nm.scaninfo()
            print("discovering: " + line + " \n")
#search for hosts that are UP   
    query = "Up"
    temp = []


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
    '''with open('./py-results/up.txt', 'r') as f:
            for line in f: '''

    print("finding services for: " )
    nm = nmap.PortScanner()
    raw = nm.scan('nmap -sV -iL ./py-results/up.txt -sC -vv -4 -p 80,443,8080,8443 --script ssl-enum-ciphers -oN ./py-results/webhost.nmap')
    file = open('./py-results/livewebhosts.json', 'w')
    file.write(json.dumps(raw))
    file.close()
               
            # Need to add parsing to compare against weak-ciphers.txt

# perform traceroute of the hosts within scope            

def trace_hosts():

     with open('./py-results/up.txt', 'r') as f:
            for line in f:
                print("finding routes for: " + line )
                nm = nmap.PortScanner()
                raw = nm.scan('nmap -sn -iL ./py-results/up.txt -4 -vv 20 --traceroute -oN ./py-results/trace-hosts.nmap')
                file = open('./py-results/trace-hosts.json', 'w')
                file.write(json.dumps(raw))
                file.close

#full scan
temp_bar = []
def find_full_scan(): 
        nm = nmap.PortScanner()
        raw = nm.scan('nmap -sV -sC -O -iL ./py-results/up.txt -4 -vv --top-ports 20  -oN ./py-results/full-hosts.nmap')
        file = open('./py-results/Full-hosts.json', 'w')
        file.write(json.dumps(raw))
        file.close
        print('scanning full host list for \n')

    

if __name__ == "__main__":
    find_live()
    find_webhosts()
    trace_hosts()
    find_full_scan()

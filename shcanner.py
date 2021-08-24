import nmap
import os
import sys
import itertools
import re
from xml.etree import ElementTree as ET


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
            nm.scan(hosts=line, arguments="-sn -iL scope.txt -oG ./py-results/livehosts.gnmap -vv")
            nm.scaninfo()
            print("discovering: " + line + " \n")
    query = "Up"
    temp = []

#search for hosts that are UP
    with open('./py-results/livehosts.gnmap', 'r') as grep:
        for line in grep:
            if query in line:
                bar = ''.join(line).strip()
                #temp.append(bar.split(' ', 1))
                bar_title, bar_ip, bar_status, bar_stat = bar.split(' ')
                print(bar_ip + ' - ' + bar_stat)
                temp.append(bar_ip)
#create new file to store grep results

    original_stdout = sys.stdout
    with open('./py-results/up.txt', 'w') as grep_file:
        sys.stdout = grep_file
        print(temp)
        sys.stdout = original_stdout
 
#section to find web servers 
temp_foo = []
results = {}
def find_webhosts(): 
    with open('scope.txt', 'r') as f:
        for line in f:
            nm = nmap.PortScanner()
            nm.scan(hosts=line, arguments="-sT -O -vv -iL scope.txt -p 80,443,8080,8443 --script ssl-enum-ciphers ") #-oA ./TEST/py-results/livehost_standard")
            results = nm.get_nmap_last_output()
            list_results = str(results)
            file = open('./py-results/livewebhosts.xml', 'wb')
            file.write(nm.get_nmap_last_output())
            file.close()
            
# perform traceroute of the hosts within scope            

def trace_hosts():

     with open('scope.txt', 'r') as f:
        for line in f:
            nm = nmap.PortScanner()
            nm.scan(hosts=line, arguments="-sn -iL scope.txt -vv 20 --traceroute -oN ./py-results/tracehosts.nmap -oG ./py-results/tracehosts.gnmap")
            nm.scaninfo()
            print('Finding routes for: ' + line + '\n')

# this section is to filter through the ssl ciphers and check for weak ciphers

def cipher_check():
    file = './py-results/livewebhosts.xml'
    full_file = os.path.abspath(os.path.join( file))
    dom = ET.parse(full_file)
    host = dom.findall('host')
    for c in host:
        ip = str(c.find('address').attrib).split(":", 1)
        
        if c.find('status').get('state') != "down":
        
            print(ip)
            for address in c.iter('address'):
                scope = address.get('addr')
                print(scope)
                for port in c.iter('ports'):
                    for portid in c.iter('port'):
                        query =  str(portid.attrib)
                        print(query)
                        for table in c.iter('script'):
                            query2 = str(table.attrib)
                            print(query2)
                            file = open('./py-results/webhosts-results.csv', 'w')
                            file.writelines(scope + '|' + query + '|' + query2)
                            file.close()

#full scan
temp_bar = []
def find_full_scan(): 
    with open('scope.txt', 'r') as f:
        for line in f:
            nm = nmap.PortScanner()
            nm.scan(hosts=line, arguments="-sV -sC -O -iL scope.txt -vv --top-ports 20  -oN ./py-results/full-hosts.nmap -oG ./py-results/full-hosts.gnmap")
            nm.scaninfo()
            print('scanning full host list for: ' + line + '\n')

    with open('./py-results/full-hosts.gnmap', 'r') as web_grep:
        for line in web_grep:
            if web_grep == '445/open' or web_grep == '139/open' or web_grep == '22/open' or web_grep == '53/open':
                foo = ''.join(line).strip()
                print(foo)
                temp_bar.append(foo)

    original_stdout = sys.stdout
    with open('./py-results/full-scan-hosts.txt', 'w') as grep_file:
            sys.stdout = grep_file
            print(temp_bar)
            sys.stdout = original_stdout

if __name__ == "__main__":
    find_live()
    find_webhosts()
    trace_hosts()
    cipher_check()
    find_full_scan()

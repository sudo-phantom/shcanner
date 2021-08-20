import nmap
import os
import sys
import itertools
import re
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
            # nm.scan(hosts=line, arguments="-sV -O -vv -p 80,443,22,445,135,139,8080,8443 -oN ./results/rosco-live.nmap -oG ./results/rosco-live.gnmap")
            nm.scan(hosts=line, arguments="-sn -oG ./py-results/livehosts.gnmap -vv")
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
def find_webhosts(): 
    with open('scope.txt', 'r') as f:
        for line in f:
            nm = nmap.PortScanner()
            nm.scan(hosts=line, arguments="-sV -O -vv -p 80,443,8080,8443 --script ssl-enum-ciphers -oN ./py-results/livewebhosts.nmap -oG ./py-results/livewebhosts.gnmap")
            ##nm.scan(hosts=line, arguments="-sn -oG ./py-results/livehosts.gnmap -vv")
            nm.scaninfo()
            print('scanning ciphers for: ' + line + '\n')

    with open('./py-results/livewebhosts.gnmap', 'r') as web_grep:
        for line in web_grep:
            if web_grep == '80/open' or web_grep == '443/open' or web_grep == '8080/open' or web_grep == '8443/open':
                foo = ''.join(line).strip()
                print(foo)
                temp_foo.append(foo)

    original_stdout = sys.stdout
    with open('./py-results/webhosts.txt', 'w') as grep_file:
            sys.stdout = grep_file
            print(temp_foo)
            sys.stdout = original_stdout
            
# perform traceroute of the hosts within scope            

def trace_hosts():

     with open('scope.txt', 'r') as f:
        for line in f:
            nm = nmap.PortScanner()
            nm.scan(hosts=line, arguments="-sn -Pn -vv 20 --traceroute -oN ./py-results/tracehosts.nmap -oG ./py-results/tracehosts.gnmap")
            nm.scaninfo()
            print('Finding routes for: ' + line + '\n')

# this section is to filter through the ssl ciphers and check for weak ciphers
def cipher_check():
    with open('./py-results/livewebhosts.nmap', 'r') as f:
        report = f.read()

    hosts = {}
    for report in re.split("Nmap scan report for ", report):
        ip = re.search("^(25[0-5]|2[0-4][0-9]|[0-9]|[01]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}", report)
        if ip:
            hosts[ip.group()] = re.findall("(?<= )[A-Z0-9_]+(?=.*\(.*\).*[A-F])", report)

    with open('./reqs/weak-ciphers.txt') as f:
        weak_ciphers = f.read().splitlines()

    for ip in hosts:
        for cipher in hosts[ip]:
            for weak_ciphers in weak_ciphers:
                if weak_ciphers in cipher:
                    print(ip + " has weak cipher\"" + cipher + "\"(contains \"" + weak_ciphers + "\")")

#full scan
temp_bar = []
def find_full_scan(): 
    with open('scope.txt', 'r') as f:
        for line in f:
            nm = nmap.PortScanner()
            nm.scan(hosts=line, arguments="-sV -sC -O -vv --top-ports 20  -oN ./py-results/full-hosts.nmap -oG ./py-results/full-hosts.gnmap")
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

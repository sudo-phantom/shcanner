import nmap
import os
import sys
import itertools
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
 

temp_foo = []
def find_webhosts(): 
    with open('scope.txt', 'r') as f:
        for line in f:
            nm = nmap.PortScanner()
            nm.scan(hosts=line, arguments="-sV -O -vv -p 80,443,8080,8443 --script ssl-enum-ciphers -oN ./py-results/livewebhosts.nmap -oG ./py-results/livewebhosts.gnmap")
            ##nm.scan(hosts=line, arguments="-sn -oG ./py-results/livehosts.gnmap -vv")
            nm.scaninfo()
            print('scanning ciphers for' + line + '\n')

    with open('./py-results/livewebhosts.gnmap', 'r') as web_grep:
        for line in web_grep:
            if web_grep == '80/open' or web_grep == '443/open' or web_grep == '8080' or web_grep == '8443':
                foo = ''.join(line).strip()
                print(foo)
                temp_foo.append(foo)

    original_stdout = sys.stdout
    with open('./py-results/webhosts.txt', 'w') as grep_file:
            sys.stdout = grep_file
            print(temp_foo)
            sys.stdout = original_stdout

def trace_hosts():

     with open('scope.txt', 'r') as f:
        for line in f:
            nm = nmap.PortScanner()
            nm.scan(hosts=line, arguments="-sn -Pn -vv --top-ports 20 --traceroute -oN ./py-results/tracehosts.nmap -oG ./py-results/tracehosts.gnmap")
            nm.scaninfo()
            print('Finding routes for' + line + '\n')
   
if __name__ == "__main__":
    find_live()
    find_webhosts()
    trace_hosts()

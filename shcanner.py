from typing import Iterable
import nmap
from concurrent.futures import ThreadPoolExecutor
import os
import sys
from xml import etree
import xml.etree.ElementTree as ET
import argparse
import json



#add arguments for optional host declaration
parser = argparse.ArgumentParser(description='Network segmentation automation validation tool.', fromfile_prefix_chars='@')
parser.add_argument('-n', '--network',  help='enter an ip or network to initialize scanning.')
parser.add_argument('-f', '--file', help='option to use file containing multiple networks, or ip address', type=argparse.FileType())
parser.add_argument('-o','--output', default='output', help='optional ouput name to prepend to scan outputs.')

args = parser.parse_args()


if args.network is not None:
    hosts = args.network
elif  args.file is not None:
    hosts = args.file.read()
else:
    print('host argument not set')
    os.error

output = args.output

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
        try:
            nm.scan(f"-sn {hosts} -4 -oA ./py-results/{output} --privileged -vv ")
        except:
            ValueError
        else:
            nm.scaninfo()
        print(f"discovering live hosts: {hosts} \n")
#search for hosts that are UP   


        with open(f'./py-results/{output}.gnmap', 'r') as grep:
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
    
    print("finding Web services: " )
    
    nm = nmap.PortScanner()
    try:
        nm.scan(f'nmap -sV -iL ./py-results/up.txt -sC -vv -4 -p 80,443,8080,8443,8000,8888 --script ssl-enum-ciphers --privileged -oA ./py-results/{output}-webhost --host-timeout 50 --min-parallelism 4')
    except:
            ValueError
    
     
    #print(nm.csv(),  file=open('./py-results/livewebhosts.csv', 'w'))
def find_ciphers():
    print('comparing ciphers:')
    #open webhost scan results into a list
    content_list = []
    with open(f'./py-results/{output}-webhost.nmap') as f:
        content_list = f.readlines()
        #print(content_list)
    #open weak ciphers into a list    
    with open('./reqs/weak-ciphers') as p:
        weak_ciphers = p.readlines()
        print(weak_ciphers)
    #compare ciphers lists
    found_cipher = []
    for weak_cipher in weak_ciphers:
        if weak_cipher in content_list:
            print(f'detected {weak_cipher}')
            strtemp = ';'.join(weak_cipher)
            weak_item = strtemp.split(';')
            found_cipher.append(weak_item)
    #print output of ciphers
    with open(f'./py-results/{output}-compared-ciphers.txt', 'w') as file_out:
     if weak_cipher in found_cipher:
        print(f'Found Bad Cipher: {weak_cipher}\n')
        file_out.write(weak_cipher)
     else:
        print('no weak ciphers detected.')
        file_out.write('No weak ciphers detected.')           
               
            # Need to add parsing to compare against weak-ciphers.txt

# perform traceroute of the hosts within scope            

def trace_hosts():
    nm = nmap.PortScanner()
    print("finding routes: " )
    try:
        nm.scan(f'-sn -iL ./py-results/up.txt -4 -vv 20 --traceroute --privileged -oA ./py-results/{output}-trace-hosts --host-timeout 25 --min-parallelism 4')
    except:
            ValueError
    #print(nm.csv(),  file=open('./py-results/trace-hosts.csv', 'w'))
    


#full scan
temp_bar = []
def find_full_scan(): 
        nm = nmap.PortScanner()
        print("Running top 50 scan: " )
        try:
            nm.scan(f'nmap -sV -sC -iL ./py-results/up.txt -4 -vv --privileged --top-ports 50  -oA ./py-results/{output}-full-hosts --host-timeout 50 --min-parallelism 4')
        except:
            ValueError

        #print(nm.csv(),  file=open(f'./py-results/{output}Full-hosts.csv', 'w'))
        print('scanning full host list for \n')

    

if __name__ == "__main__":
    find_live()
    with ThreadPoolExecutor(max_workers= 7) as executor:
        executor.map(find_webhosts())
        executor.map(trace_hosts())
        executor.map(find_ciphers())
        executor.map(find_full_scan())

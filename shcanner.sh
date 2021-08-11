## USAGE <sh scanner.sh>
## must have a file named "scope.txt" saved in the same directory
## scope.txt must be in nmap list format to work with current configuration

#install needed tools
sudo apt-get update && sudo apt-get install -y nmap python3 python3-pip traceroute masscan;

# run nmap scanns
sudo nmap -sn -iL  scope.txt -oA livehost_icmp -vv;
sudo nmap -sS -Pn -vv -p21,22,23,25,80,110,443,513,3389,6000,8080,8443,2222,445,135,139 -iL scope.txt -oA livehost_standard;
cat livehost_icmp.gnmap | grep Up | cut -d " " -f 2 > up.txt | nmap -n -Pn -iL up.txt -vv -oG full_livehosts
cat livehost_standard.gnmap | grep -e 80/open -e 443/open -e 8080/open | cut -d " " -f 2 > "webhosts.txt"
cat livehost_standard.gnmap | grep -e 22/open -e 2222/open | cut -d " " -f 2 > "ssh-hosts.txt"
sudo masscan -iL ./scope.txt --banners --open -p 22,25,80,443,445,8443,8080,139,135,3389,3306,554,179,161,162,5432 -oL tcp-scan.txt --rate 2000;
#traceroute hosts
#
#ADD section for SSLyze or SSLscan to check for week ciphers and report
#
python3 shcanner.py
#continue interface

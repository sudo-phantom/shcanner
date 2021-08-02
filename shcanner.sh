## USAGE <sh scanner.sh>
## must have a file named "scope.txt" saved in the same directory
## scope.txt must be in nmap list format to work with current configuration

#install needed tools
sudo apt-get update && sudo apt-get install -y nmap python python-pip traceroute;

# run nmap scanns
sudo nmap -sP -iL  scope.txt -oA livehost_icmp -vv;
sudo nmap -sS -Pn -vv -p21,22,23,25,80,110,443,513,3389,6000,8080,8443,445,135,139 -iL scope.txt -oA livehost_standard;
cat livehost_icmp.gnmap | grep Up | cut -d " " -f 2 > up.txt | nmap -n -Pn -iL up.txt -vv -oG full_livehosts
#traceroute hosts
python3 shcanner.py
#continue interface

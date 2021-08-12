## USAGE <sh scanner.sh>
## must have a file named "scope.txt" saved in the same directory
## scope.txt must be in nmap list format to work with current configuration

#install needed tools
sudo apt-get update && sudo apt-get install -y nmap python3 python3-pip traceroute masscan;

# run nmap scanns
mkdir results;
sudo nmap -sn -iL  scope.txt -oA ./results/livehost_icmp -vv;
sudo nmap -sT -Pn -vv -p21,22,23,25,80,110,443,513,3389,6000,8080,8443,2222,445,135,139 -iL scope.txt -oA ./results/livehost_standard;
cat ./results/livehost_icmp.gnmap | grep Up | cut -d " " -f 2 > ./results/up.txt | nmap -n -Pn -iL up.txt -vv -oG ./results/full_livehosts;
cat ./results/livehost_standard.gnmap | grep -e 80/open -e 443/open -e 8080/open | cut -d " " -f 2 > "./results/webhosts.txt";
cat ./results/livehost_standard.gnmap | grep -e 22/open -e 2222/open | cut -d " " -f 2 > "./results/ssh-hosts.txt";
sudo masscan -iL ./scope.txt --banners --open -p 22,25,80,443,445,8443,8080,139,135,3389,3306,554,179,161,162,5432 -oL ./results/tcp-scan.txt --rate 2000;
#traceroute hosts
#ssl checked
cat ./results/livehost_standard.gnmap | grep -e 22/open -e 4443/open  -e 8443/open | cut -d " " -f 2 > "./results/secure-layer-hosts.txt";
nmap -sV --script ssl-enum-cuphers -p 443,22,8443 -iL ./results/secure-layer-hosts.txt;
python3 shcanner.py;
#continue interface

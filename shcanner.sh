## USAGE <sh scanner.sh>
## must have a file named "scope.txt" saved in the same directory
## scope.txt must be in nmap list format to work with current configuration

#install needed tools
sudo apt-get update && sudo apt-get install -y nmap python3 python3-pip traceroute masscan;

# run nmap scanns
mkdir results;
mkdir py-results;
nmap -sn -iL  scope.txt -oA ./results/livehost_icmp -vv;
sudo nmap -sT -Pn -vv --top-ports 20 -iL scope.txt -oA ./results/livehost_standard;
nmap -sn -iL scope.txt -4 -vv 20 --traceroute -oA ./results/tracehosts;
cat ./results/livehost_icmp.gnmap | grep Up | cut -d " " -f 2 > ./results/up.txt | nmap -n -Pn -iL up.txt -vv -oG ./results/full_livehosts;
cat ./results/livehost_standard.gnmap | grep -e 80/open -e 443/open -e 8080/open | cut -d " " -f 2 > "./results/webhosts.txt";
cat ./results/livehost_standard.gnmap | grep -e 22/open -e 2222/open | cut -d " " -f 2 > "./results/ssh-hosts.txt";
sudo masscan -iL ./scope.txt --banners --open -p 22,25,80,443,445,8443,8080,139,135,3389,3306,554,179,161,162,5432 -oL ./results/tcp-scan.txt --rate 2000;

#ssl checked
cat ./results/livehost_standard.gnmap | grep -e 22/open -e 4443/open  -e 8443/open | cut -d " " -f 2 > "./results/secure-layer-hosts.txt";
sudo nmap -sV --script ssl-enum-ciphers -p 443,22,8443 -iL ./results/secure-layer-hosts.txt -oA ./results/SSL-hosts;

#continue interface
##run Vulscan
git clone https://github.com/scipag/vulscan scipag_vulscan;
sudo ln -s `pwd`/scipag_vulscan /usr/share/nmap/scripts/vulscan;
sudo nmap -vv -sV --script=vulscan/vulscan.nse -iL ./results/webhosts.txt -oA ./results/vulscan;

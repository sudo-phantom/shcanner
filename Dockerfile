FROM kalilinux/kali-rolling
RUN apt-get update && apt-get upgrade -y && apt-get install -y  nmap python3 python3-pip
RUN mkdir /home/shcanner/
RUN cd /home/shcanner
ADD shcanner.py /home/shcanner
ADD requirements.txt /home/shcanner
ADD scope.txt /home/shcanner
RUN mkdir /home/shcanner/reqs
ADD  /reqs /home/shcanner/reqs/weak-ciphers.txt
RUN cd /home/shcanner
RUN pip install pystrich
RUN pip install -r requirements.txt
CMD [ "python3", "./shcanner.py -f scope.txt " ]

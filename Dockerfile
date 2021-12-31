FROM kalilinux/kali-rolling
RUN apt-get update && apt-get upgrade -y && apt-get install -y  nmap python3 python3-pip
ADD shcanner.py /
ADD requirements.txt /
ADD scope.txt /
RUN mkdir ./reqs
ADD  /reqs ./reqs
RUN pip install pystrich
RUN pip install -r requirements.txt
ENTRYPOINT [ "python3" , "shcanner.py",  "-f", "scope.txt" ]

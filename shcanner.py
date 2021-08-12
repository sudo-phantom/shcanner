import subprocess

with open("./results/up.txt", "r") as hostlist, open("./results/results.txt", "wb") as output:
    for host in hostlist:
        host = host.strip()

        print("Tracing", host)

        trace = subprocess.Popen(["traceroute", "-w 50", host], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        while True:
            hop = trace.stdout.readline()

            if not hop: break

            print( '-->', hop)

            output.write(hop)

        # When you pipe stdout, the doc recommends that you use .communicate()
        # instead of wait()
        # see: http://docs.python.org/2/library/subprocess.html#subprocess.Popen.wait
        trace.communicate()

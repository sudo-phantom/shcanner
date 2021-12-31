# shcanner
sh...scanner

edit scope.txt file to fit IP needs

run: sh shcanner.sh


-----------------------------------------

python3 shcanner.py -h

usage: shcanner.py [-h] [-n NETWORK] [-f FILE] [-o OUTPUT]

Network segmentation automation validation tool.

optional arguments:
  -h, --help            show this help message and exit
  -n NETWORK, --network NETWORK
                        enter an ip or network to initialize scanning.
  -f FILE, --file FILE  option to use file containing multiple networks, or ip address
  -o OUTPUT, --output OUTPUT
                        optional ouput name to prepend to scan outputs.
                    
-----------------------------------------------------------------------------------------------

to run the docker image.

[docker build -t shcanner/sudosec .]


-------------------------------------------------------------------------------------------------
python3 table_maker.py ./py-results/<livewebhosts.csv> or whichever file you'd like in table form



import sys
from bs4 import BeautifulSoup
import argparse
from numpy import dtype, inner
import pandas as pd
from pandas import json_normalize
from pandas.core.frame import DataFrame
from pandas.io.parsers import read_csv

parser = argparse.ArgumentParser(description='convert nmap json files to table')
parser.add_argument('input_file', type=argparse.FileType('r'))
args = parser.parse_args()


with args.input_file as f:
    data = pd.read_csv(f, delimiter=';', usecols=['host', 'port', 'state', 'reason', 'cpe'])
df = pd.DataFrame(data).fillna("Not found")
print(df.loc[df['state'] != 'closed'])

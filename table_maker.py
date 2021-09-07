import sys
import argparse
from tabulate import tabulate
import pandas as pd


parser = argparse.ArgumentParser(description='convert nmap csv files to table')
parser.add_argument('input_file', type=argparse.FileType('r'))
args = parser.parse_args()


with args.input_file as f:
    data = pd.read_csv(f, delimiter=';', usecols=['host', 'port', 'state', 'reason', 'cpe'])
df = pd.DataFrame(data).fillna("Not found")
df = df.loc[df['state'] != 'closed']
print(tabulate(df, headers = 'keys', tablefmt = 'psq1'))

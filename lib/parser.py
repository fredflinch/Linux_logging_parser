from  datetime import datetime  
import re 
from tqdm import tqdm
import pandas as pd

def read_file(path):
        with open(path, 'r') as f:
            values = f.readlines()
        return values

def df_final(arr, save, ofile):
    df_webaccess = pd.DataFrame(arr[1:], columns=arr[0])
    if save: df_webaccess.to_csv(ofile)
    return df_webaccess

class parser:
    def __init__(self, inFile, outFile, save=False, options=[]):
        self.parsed = None
        self.inFile = inFile
        self.outFile = outFile
        self.save = save
        self.options = options
    
    def webaccess(self):
        waRex = r'(?P<ip>[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}) - - \[(?P<dt>[0-9][0-9]\/[A-Za-z]{3}\/[0-9]{4}\:[0-9][0-9]\:[0-9][0-9]\:[0-9][0-9] \+[0-9]{4})\] \"(?P<method>[A-Za-z]{1,}) (?P<uri>[\S]{1,}) [\S]{1,} (?P<status>[0-9]{3}) (?P<bytes>[0-9]{1,}) [\S]{1,} \"(?P<useragent>[^"]{1,})\"'              
        webAccesses = read_file(self.inFile)
        cols = [['time', 'ip', 'uri', 'method', 'status', 'useragent', 'bytes']]
        for wa in webAccesses:
            s = re.search(waRex, wa)
            if s is not None:
                cols.append([s.group('dt'), s.group('ip'), s.group('uri'), s.group('method'), s.group('status'), s.group('useragent'), s.group('bytes')])
        self.parsed = df_final(cols, self.save, self.outFile)
    
    ## options -- 'level', 'procs' ##
    def messages(self):
        if "level" in self.options:
            cols = [['time', 'host', 'classification', 'alertlevel', 'content']]
            colsRex = r'(?P<dt>[0-9]{4}-[0-9]{2}-[0-9]{2}T[\S]{1,}) (?P<host>[\S]{1,}) 20[0-9]{2}\.[0-9]{2}\.[0-9]{2,3} [0-9]{2}:[0-9]{2}:[0-9]{0,3} (?P<class>\[[^\]]{1,}\]) (?P<level>[A-Z]{1,}): (?P<content>.{1,})'
        else:
            cols = [['time', 'host', 'process', 'content']]    
            colsRex = r'(?P<dt>[0-9]{4}-[0-9]{2}-[0-9]{2}T[\S]{1,}) (?P<host>[\S]{1,}) (?P<proc>[^\[^:]{1,})(\[[0-9]{1,}\]){0,}: (?P<content>.{1,})'    

        messages = read_file(self.inFile)
        for msg in tqdm(messages):
            oValues = re.search(colsRex, msg)
            if oValues is not None:
                if "level" in self.options:
                    cols.append([oValues.group('dt'), oValues.group('host'), oValues.group('class'), oValues.group('level'), oValues.group('content')])
                else:
                    cols.append([oValues.group('dt'),oValues.group('host'),oValues.group('proc'),oValues.group('content')])
            else:
                print(msg)

        self.parsed =df_final(cols, self.save, self.outFile) 
        return

    def parse_bash_history(self):
        r = [['time','command']]
        bhist = read_file(self.inFile)
        for i,h in enumerate(bhist):
            if h[0]=="#": 
                date_time = (datetime.fromtimestamp(int(h[1:]))).strftime("%d/%m/%Y %H:%M:%S")
                r.append([date_time, bhist[i+1][:-1]])
        self.parsed = df_final(r, self.save, self.outFile)
        return

    def get_logins(self):
        pRex = r'(?P<dt>[0-9]{4}-[0-9]{2}-[0-9]{2}T[\S]{1,}) (?P<host>[\S]{1,}) 20[0-9]{2}\.[0-9]{2}\.[0-9]{2,3} [0-9]{2}:[0-9]{2}:[0-9]{0,3} (?P<class>\[[^\]]{1,}\]) (?P<level>[A-Z]{1,}): (?P<content>.{1,})'
        r = [['Time', 'User', 'IP']] 
        messages = read_file(self.inFile)        
        
        for msg in tqdm(messages):
            level = re.search(pRex, msg)
            if (level is not None):
                cont = str(level.group('content'))
                if "federationbroker.FederationBrokerService" in cont:
                    v = (level.group('content')).split(" ")
                    user = v[-2]
                    ip = v[1].split(":")[-1][:-1]
                    ipData = "" 
                    r.append([level.group('dt'), user, ip])
        self.parsed = df_final(r, self.save, self.outFile)



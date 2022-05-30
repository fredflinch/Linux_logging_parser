#!/bin/python3
from  datetime import datetime  
import csv
import argparse
import re 
from tqdm import tqdm
import pandas as pd
from ipwhois import IPWhois

def out_csv(opath, data, colNames):
    with open(opath,'w', newline='') as out:
        csv_out=csv.writer(out)
        csv_out.writerow(colNames)
        for row in data:
            csv_out.writerow(row)

def parse_bash_history(path, opath):
    r = []
    with open(path, 'r') as f:
        bhist= f.readlines()
    for i,h in enumerate(bhist):
        if h[0]=="#": 
            date_time = (datetime.fromtimestamp(int(h[1:]))).strftime("%d/%m/%Y %H:%M:%S")
            r.append((date_time, bhist[i+1][:-1]))
    out_csv(opath, r, ['time','command'])
    return r


def parse_warn(path, opath):
    r = []
    ips = []
    ip_reg = r'(?P<dt>[0-9]{4}-[0-9]{2}-[0-9]{2}T[\S]{1,}) [\S]{1,} [\S]{1,} [\S]{1,} [\S]{1,} (?P<ip>[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})'
    with open(path, 'r') as f:
        warnL= f.readlines()
    for warning in warnL:
        l = re.search(ip_reg, warning)
        if l is not None:
            r.append((l.group('dt'), l.group('ip')))
            ips.append(l.group('ip'))
    out_csv(opath, r, ['time','ip'])
    
    print("Unique IPs in warn")
    for ip in list(dict.fromkeys(ips)):
        print(ip)
    return 

def parse_messages(path, opath, save):
    lvl = [['time', 'host', 'classification', 'alertlevel', 'content']]
    prc = [['time', 'host', 'process', 'content']]
    levelRex = r'(?P<dt>[0-9]{4}-[0-9]{2}-[0-9]{2}T[\S]{1,}) (?P<host>[\S]{1,}) 20[0-9]{2}\.[0-9]{2}\.[0-9]{2,3} [0-9]{2}:[0-9]{2}:[0-9]{0,3} (?P<class>\[[^\]]{1,}\]) (?P<level>[A-Z]{1,}): (?P<content>.{1,})'
    procRex = r'(?P<dt>[0-9]{4}-[0-9]{2}-[0-9]{2}T[\S]{1,}) (?P<host>[\S]{1,}) (?P<proc>[^\[^:]{1,})(\[[0-9]{1,}\]){0,}: (?P<content>.{1,})'    
    print("Reading in file: " + path + "...")
    with open(path, 'r') as f:
        messages = f.readlines()
    print("Completed read, Begining processing...")
    for msg in tqdm(messages):
        level = re.search(levelRex, msg)
        proc = re.search(procRex, msg)
        if (level is not None) and (proc is None):
            lvl.append([level.group('dt'), level.group('host'), level.group('class'), level.group('level'), level.group('content')])
        elif proc is not None:
            prc.append([proc.group('dt'),proc.group('host'),proc.group('proc'),proc.group('content')])
        else:
            print(msg)

    df_lvl = pd.DataFrame(lvl[1:], columns=lvl[0])
    df_proc = pd.DataFrame(prc[1:], columns=prc[0])


    if save:
        df_lvl.to_csv(opath.split(",")[0])
        df_proc.to_csv(opath.split(",")[1])
        print("Done!\n")   
    
    return

def get_logins(path, opath, op=False):
    pRex = r'(?P<dt>[0-9]{4}-[0-9]{2}-[0-9]{2}T[\S]{1,}) (?P<host>[\S]{1,}) 20[0-9]{2}\.[0-9]{2}\.[0-9]{2,3} [0-9]{2}:[0-9]{2}:[0-9]{0,3} (?P<class>\[[^\]]{1,}\]) (?P<level>[A-Z]{1,}): (?P<content>.{1,})'
    r = []
    ips_e = []
    with open(path, 'r') as f:
        messages = f.readlines()
    for msg in tqdm(messages):

        level = re.search(pRex, msg)
        if (level is not None):
            cont = str(level.group('content'))
            if "federationbroker.FederationBrokerService" in cont:
                v = (level.group('content')).split(" ")
                user = v[-2]
                ip = v[1].split(":")[-1][:-1]
                ipData = ""
                if op:
                    for x in ips_e:
                        if x[0] == ip:
                            ipData = x
                            break
                    else:
                        iD = enrich_ip(ip)
                        ipData = iD
                        ips_e.append(iD)
                    
                    r.append((level.group('dt'), user, ipData[0], ipData[1], ipData[2], ipData[3], ipData[4]))
                else: 
                    r.append((level.group('dt'), user, ip))
    if op:
        out_csv(opath, r, ['Time', 'User', 'IP', 'Country', 'Name', 'Description', 'CIDR'])
    else:
        out_csv(opath, r, ['Time', 'User', 'IP'])
    return



def validate_cron(infile):
    r = []
    procRex = r'(?P<dt>[0-9]{4}-[0-9]{2}-[0-9]{2}T[\S]{1,}) (?P<host>[\S]{1,}) (?P<proc>[^\[^:]{1,})(\[[0-9]{1,}\]){0,}: (?P<content>.{1,})'    
    with open(infile, 'r') as f:
        cron = f.readlines()
    for c in cron:
        cR = re.search(procRex, c)
        if cR is not None:
            r.append((cR.group('proc'), cR.group('content')))
    print(list(dict.fromkeys(r)))
    return

def parse_query(qu):
    MACROS = ["SEARCH"]
    q = qu.split(" ")
    if q[0] == "SEARCH":
        if len(q) < 6:
            print("Too few arguments\ne.g. SEARCH col1,col2 IN col WHERE \'string to search\'")
            return -1 
        cols = q[1].split(",")
        colV = ""
        for x in cols:
            colV += "'"+x+"',"
        colV = colV[1:-2]
        sCol = q[3]
        s = ""
        for x in q[5:]:
            x = x.replace("\'", "")
            s+=x
            s+=" "
        s = s[:-1]
        qu = "FRAME[FRAME[\'" + sCol + "\'].str.contains(\"" + s + "\")][[\'" + colV + "\']]"
    return qu
    
def enrich_ip(ip):
    try:
        lookup = IPWhois(ip).lookup_whois()
        return (ip, lookup['nets'][0]['country'], lookup['nets'][0]['name'], lookup['nets'][0]['description'], lookup['nets'][0]['cidr'])
    except:
        return (ip, '', '', '', '')


# will allow code execution so probs dont deploy as root... #
def analyse_dataframe(infile, query, op=False, oFile=""):
    pd.set_option('display.max_colwidth', None)
    pd.set_option('display.max_rows', None)
    
    df_in = pd.read_csv(infile, index_col=0)
    query = parse_query(query)
    if query == -1: return
    query = query.replace("FRAME", "df_in")
    outQ = eval(query)
    if op: outQ.to_csv(oFile)
    else: print(outQ)
    return
            

if __name__=="__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-m", "--mode", help="select mode from list:    bashhistory, warn, messages, query, cron, logins")
    parser.add_argument("-i", "--input", help="input artifact")
    parser.add_argument("-o", "--output", help="output artifact -- for multiparse add outputs as comma seperated e.g. out1, out2 ...")
    parser.add_argument("-op", "--options", help="aditional options for parsers")
    parser.add_argument("-q", "--query", help="query dataframe, when refering to the dataframe use FRAME")

    args = parser.parse_args()
    if (args.mode == "bashhistory"):
        parse_bash_history(args.input, args.output)
    elif (args.mode == "warn"):
        parse_warn(args.input, args.output)
    elif (args.mode == "messages"):
        if args.options == "True":
            if len((args.output).split(",")) >= 2: 
                parse_messages(args.input, (args.output).replace(' ', ''), True)
            else:
                print("Needs to be run with 2 files as output...\nLevel logging output then proc logging output")
        else:
            parse_messages(args.input, (args.output), False)
    elif args.mode=="cron" and args.input is not None:
        validate_cron(args.input)
    elif args.mode=="logins": 
        if (args.input is not None) and (args.output is not None):
            if args.options is not None:
                get_logins(args.input, args.output, args.options)
            else:
                get_logins(args.input, args.output)
            quit()
        else: print("specify input and output file")
    elif (args.mode == "query"):
        if (args.input is not None) and (args.query is not None):
            if args.output is not None and args.options == "True":
                analyse_dataframe(args.input, args.query, args.options, args.output)
            else:
                analyse_dataframe(args.input, args.query)
        else:
            print("Query mode requires input file and query\n example parse.py -i in/file -q \"query\"")              
    else:
        print("Specify a mode with -m from list")
        quit()




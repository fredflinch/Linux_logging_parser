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

def parse_execve(p):
    prog = ''
    cmdline = ''
    if 'argc=' in p:
        arg_count = p[p.index('argc=')+len('argc='):].split(' ')[0]
        prog = p[p.index('a0=')+len('a0='):].split(' ')[0].replace("\"", "")
        if int(arg_count) > 0:
            for x in range(1, int(arg_count)):
                p = p.replace('a'+str(x)+'=', '')
            cmdline = ' '.join(p[p.index('a0=')+len('a0='):].split(' ')[1:]).replace("\"", '')
    return [prog, cmdline]            

# types to parse 
# ['DAEMON_START', 'SYSCALL', 'SOCKADDR', 'PROCTITLE', 'CWD', 'PATH', 'EXECVE', 'CONFIG_CHANGE', 'SERVICE_START', 'USER_END', 'CRED_DISP', 'USER_ACCT', 
# 'USER_CMD', 'CRED_REFR', 'USER_START', 'USER_ERR', 'USER_AUTH', 'USER_LOGIN', 'CRED_ACQ', 'LOGIN', 'UNKNOWN[1334]', 'SERVICE_STOP', 'TTY', 'DAEMON_END']
def parse_audit(path, opath, type2save=None):
    bRex = r'type=(?P<type>[^\s]{1,}) msg=audit\((?P<dt>[0-9]{1,}\.[0-9]{1,})\:(?P<id>[0-9]{1,})\): (?P<body>.{1,})'
    types = []
    outV = [['time', 'type', 'content']]

    with open(path, 'r') as f:
        audits = f.readlines()
    for a in audits:
        auditLine = re.search(bRex, a)
        if auditLine is not None:
            dt = (datetime.fromtimestamp(float(auditLine.group('dt')))).strftime("%d/%m/%Y %H:%M:%S")
            line = [dt, auditLine.group('type')]
            # parse execve
            if (auditLine.group('type') == "EXECVE"):
                execve_ret = parse_execve(auditLine.group('body'))  
                line.append(execve_ret)
            # parse cwd
            if (auditLine.group('type') == "CWD"):
                cwd_r = re.search(r'cwd=[\"]{0,1}(?P<dir>[^\"]{1,})', auditLine.group('body'))
                if cwd_r is not None:
                    line.append(cwd_r.group('dir'))
            outV.append(line)
    df_audit = pd.DataFrame(outV[1:], columns=outV[0])
    if type2save!=None:
        df_audit.loc[df_audit['type'] == type2save].to_csv(opath)
    else: 
        df_audit.to_csv(opath)
    
def parse_webaccess(path, opath):
    waRex = r'(?P<ip>[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}) - - \[(?P<dt>[0-9][0-9]\/[A-Za-z]{3}\/[0-9]{4}\:[0-9][0-9]\:[0-9][0-9]\:[0-9][0-9] \+[0-9]{4})\] \"(?P<method>[A-Za-z]{1,}) (?P<uri>[\S]{1,}) [\S]{1,} (?P<status>[0-9]{3}) (?P<bytes>[0-9]{1,}) [\S]{1,} \"(?P<useragent>[^"]{1,})\"'              
    with open(path, 'r') as f:
        webAccesses = f.readlines()
    cols = [['time', 'ip', 'uri', 'method', 'status', 'useragent', 'bytes']]
    for wa in webAccesses:
        s = re.search(waRex, wa)
        if s is not None:
            cols.append([s.group('dt'), s.group('ip'), s.group('uri'), s.group('method'), s.group('status'), s.group('useragent'), s.group('bytes')])
    df_webaccess = pd.DataFrame(cols[1:], columns=cols[0])
    df_webaccess.to_csv(opath)

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
    parser.add_argument("-m", "--mode", help="select mode from list:    bashhistory, warn, messages, audit, query, cron, logins")
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
    elif args.mode == "audit":
        if (args.input is not None) and (args.output is not None) and (args.options is None):
            parse_audit(args.input, args.output)
        elif (args.input is not None) and (args.output is not None) and (args.options is not None):
            parse_audit(args.input, args.output, args.options)
        else:
            print("Parse audit requires input and output files with optional save option")
            quit()
    elif args.mode == "webaccess":
        if (args.input is not None) and (args.output is not None):
            parse_webaccess(args.input, args.output)
    else:
        print("Specify a mode with -m from list")
        quit()




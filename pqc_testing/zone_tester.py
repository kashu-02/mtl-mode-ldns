#!/usr/bin/python3

'''
DNS query metrics collection tool

Args:
    None

Output:
    Comma separated data table with query results
'''

import dns.resolver
import os
import time
import io
from copy import deepcopy
import statistics

algos = ['rsa','ecdsa','fl-dsa', 'ml-dsa', 'slh-dsa-sha','slh-dsa-shake','slh-dsa-mtl-sha','slh-dsa-mtl-shake']
query_list = [('@','SOA'),('@','NS'),('@','DNSKEY'),('www','CNAME')]
resolver_ip = "54.237.115.110"
resolver_port = 53
protocol = ['UDP','TCP']

rdtypes = {6: 'SOA', 46: 'RRSIG', 2: 'NS', 1: 'A', 48: 'DNSKEY', 43: 'DS', 28: 'AAAA', 50: 'NSEC3', 47: 'NSEC', 51: 'NSEC3PARAMS', 5: 'CNAME'}
empty_set = {'SOA':0,'RRSIG':0,'NS':0,'A':0,'DNSKEY':0,'DS':0,'AAAA':0,'NSEC3':0,'NSEC':0,'NSEC3PARAMS':0, 'CNAME':0}

print_response = False
query_average_num = 10

def get_name(label, algo, zone_name):
    '''
    Get the appropriate FQDN for this zone 
    '''
    qname = ""

    if label != "@":
        qname += f"{label}."
    qname += f"{algo}.{zone_name}"
    return qname

def print_headings():
    '''
    Initalize the output table data
    '''    

    os.system('cls' if os.name == 'nt' else 'clear')

    print(f"Protocol, Algorithm, Name, Label, Record, Query Size, EDNS(0) MTL, Response Size, Truncated, EDNS(0) Request Payload Size, EDNS(0) Response Payload Size, Query Time ({query_average_num} average), Query Median, Query Stdev, DNSKEY Size (average)",end="")
    for r in empty_set:
        print(f",{r} Count (in response)",end="")
    print("")

def print_results(proto, algo, qname, label, qtype, query_size, full_sig, response_size, result, time_sample, tcout, dnskey_size):
    '''
    Print out a results line
    '''   

    print(f"{proto},{algo},{qname},{label},{qtype},{query_size},{full_sig},{response_size},{(result.flags & dns.flags.TC) != 0},{result.request_payload},{result.payload},{statistics.mean(time_sample)},{statistics.median(time_sample)},{statistics.stdev(time_sample)}",end="")
    for r in tcout:
        print(f",{tcout[r]}",end="")
    if(len(dnskey_size) == 0):
        print(f",0",end="")
    else:
        print(f",{statistics.mean(dnskey_size)}",end="")
    print("")

def count_response_records(section, tcout, dnskey_sizes):
    '''
    Tally the response records
    ''' 

    for r in section:        
        if(r.to_rdataset().rdtype == 48):
            buffer = io.BytesIO()
            r.to_wire(buffer)
            dnskey = buffer.getvalue()   
            dnskey_sizes.append(len(dnskey))                             
        rdtype = rdtypes[r.to_rdataset().rdtype]
        tcout[rdtype] += 1   


def get_query_metrics(zone_name, proto, algo, label, qtype, display_results, display_query):
    '''
    Get the query metrics for a zone, protocol, algorithm, etc...
    ''' 

    # By default just query for the signature
    opt_set = [False]
    if 'mtl' in algo:
        # If it is MTL query for the signature with and without the EDNS option
        opt_set = [False, True]

    for full_sig in opt_set:
        qname = get_name(label, algo, zone_name)
        opt = None
        # If this is a MTL full sig, add the EDNS option
        if full_sig:
            opt = [dns.edns.GenericOption(65050, b'')]
        query = dns.message.make_query(qname,qtype,want_dnssec=True, options=opt)

        start = 0
        end = 0
        time_sample = []   

        count = query_average_num
        # If this is a warmup or output is supressed just do one iteration
        if not display_results:
            count = 1                             
        
        # Issue the query over UDP or TCP
        if proto.lower() == 'udp':
            for t in range(0,count):
                start = time.time()
                result = dns.query.udp(query, resolver_ip,port=resolver_port)
                end = time.time()        
                time_sample.append(end-start)
        else:
            for t in range(0,count):
                start = time.time()
                result = dns.query.tcp(query, resolver_ip,port=resolver_port)
                end = time.time()                        
                time_sample.append(end-start)

        # Deep copy the result set so the numbers are fresh each time
        tcout = deepcopy(empty_set)
        dnskey_size = []

        # Count the resulting record type and sizes
        count_response_records(result.answer, tcout, dnskey_size)
        count_response_records(result.authority, tcout, dnskey_size)
        count_response_records(result.additional, tcout, dnskey_size)

        # Generate the resulting metrics and output if appropriate
        query_size = len(query.to_wire())
        response_size = len(result.to_wire())
        if display_results:
            print_results(proto, algo, qname, label, qtype, query_size, full_sig, response_size, result, time_sample, tcout, dnskey_size)
        if display_query:
            print(f"{result}\n\n")


def main():
    print_headings()

    # Do one run through to make sure resovler is up and serving.
    # Sometimes it takes a few queries before the times settle out.
    for print_results in [False,True]: 
        for proto in protocol:
            for algo in algos:
                for label, qtype in query_list:
                    get_query_metrics("example.com", proto, algo, label, qtype, print_results, False)


if __name__ == "__main__":
    main()

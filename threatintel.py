"""
Author: Swati krishnan

Date:04/03/2016

Basic Indicators of Compromise (IOCs) information provider.


"""

import json
import sys
from pprint import pprint
from datetime import datetime
import pytz
import re
import urllib
import urllib2
import ast
from urllib2 import urlopen
# -*- coding: utf-8 -*-
#data = []
parsed_data=[];

def byteify(input):
    """
    Converts UTF encoded dictionary entries to normal byte string, improving readibilty for user.
        
    """
    if isinstance(input, dict):
        return {byteify(key): byteify(value)
            for key, value in input.iteritems()}
    elif isinstance(input, list):
        return [byteify(element) for element in input]
    elif isinstance(input, unicode):
        return input.encode('utf-8')
    else:
        return input

def main():
    """
    Parsing the given input and storing it in ip_list for further use
    """
    ip_list = sys.argv[1].split(",")
    print "The given indicators of compromise are:",
    print ip_list
    parsed_data=parse_honeypot()
    honeypot_search(ip_list,parsed_data)
    #virustotal_search(ip_list)
    isc_search(ip_list)
    virustotal_search(ip_list)

def parse_honeypot():
    """
    Parsing the honeypot data. First read json from file
    line by line, convert each entry to dict and append it
    to list 'data'. Most of our data is in the string
    associated with the payload entry. So, we extract that
    from the string accordingly using string find function and then
    modify the data before adding it to temp dictionary 'parsed'. We
    then append 'parsed' (with all the extracated data that we
    consider important to a list 'parsed_data'.
    
    """
    print "Parsing honeypot data.."
    data = []
    for line in open('honeypot.json', 'r'):
        data.append(json.loads(line))
    parsed={};
    global parsed_data

    for j in range(len(data)):
        str1=data[j]["payload"]
        stu=str1[str1.find("time"):str1.find("filename")-1].strip("time")
        stuf=re.sub('"', '', stu)
        srcu=str1[str1.find("source"):str1.find("request_raw")-1].strip("source")
        srcuf=re.sub('"|,|:', '', srcu)
        atpo=str1[str1.find("attackerPort"):str1.find("victimPort")-1].strip("attackerPort")
        atpo1 = re.sub('"|,|:', '', atpo)
        atpo2=atpo1.encode('UTF-8')
        atpof=atpo2.strip()
        vpo=str1[str1.find("victimPort"):str1.find("victimIP")-1].strip("victimPort")
        vpo1 = re.sub('"|,|:', '', vpo)
        vpo2=vpo1.encode('UTF-8')
        vpof=vpo2.strip()

        req_raw=str1[str1.find("request_raw"):str1.find("request_url")-1].strip("request_raw")
        req_raw1=req_raw.strip("\"")

        req_url=str1[str1.find("request_url"):str1.find("}")-1].strip("request_url")
        req_url1=re.sub('"|:', '', req_url)
        req_url2=req_url1.encode('UTF-8')
        req_url3=req_url2.strip()
        strv=str1[str1.find("victimIP"):str1.find("attackerIP")-1].strip("victimIP")
        victim1 = re.sub('"|,|:', '', strv)
        victim2=victim1.encode('UTF-8')
        victim=victim2.strip()
        stra=str1[str1.find("attackerIP"):str1.find("connectionType")-1].strip("attackerIP")
        attacker = re.sub('"|,|:', '', stra)
        con=str1[str1.find("connectionType"):str1.find("connectionType")+26].strip("connectionType")
        con1=re.sub('"|:', '', con)
        jdate=data[j]["timestamp"]["$date"]
        ts=jdate[0:jdate.find("T")]
        parsed={'victimIP':victim, 'attackerIP':attacker, 'ConType':con1, 'time_Ip':ts, 'time_url':stuf, 'source_url':srcuf, 'raw_request_URL':req_raw1, 'request URL':req_url3, 'att_port':atpof, 'vic_port':vpof,'source':"Honeypot"}
        
        parsed_data.append(parsed)

    return parsed_data

def honeypot_search(ip_list,parsed_data):
    """
    Search for IOCs in our local honeypot.json file
    by using dict values.
        
    """
    prompt='>'
    print "Searching local honeypot for data......"
    for i in range(len(ip_list)):
        for j in range(len(parsed_data)):
            if ip_list[i]==parsed_data[j]["victimIP"]:
                print "Information for victim IP",ip_list[i]
                print "Attacker IP:",parsed_data[j]["attackerIP"]
                print "Connection Type:",parsed_data[j]["ConType"]
                print "Source:",parsed_data[j]["source"]
                print "Time Stamp:",parsed_data[j]["time_Ip"]
                print
            #raw_input("Press Enter to continue...")
            elif ip_list[i]==parsed_data[j]["vic_port"] or ip_list[i]==parsed_data[j]["att_port"]:
                print "Information for Port",ip_list[i]
                print "Victim IP:",parsed_data[j]["victimIP"]
                print "Victim port:",parsed_data[j]["vic_port"]
                print "Attacker IP:",parsed_data[j]["attackerIP"]
                print "Attacker port:",parsed_data[j]["att_port"]
                print "Connection Type:",parsed_data[j]["ConType"]
                print "Source:",parsed_data[j]["source"]
                print "Time Stamp:",parsed_data[j]["time_Ip"]
                print
            elif ip_list[i] in parsed_data[j]["request URL"] and re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', str(ip_list[i])):
                print "Information for URL:",ip_list[i]
                print "Raw Request",parsed_data[j]["raw_request_URL"]
                print "Request URL:",parsed_data[j]["request URL"]
                print "Timestamp",parsed_data[j]["time_url"]
                print "Source IP and Port:",parsed_data[j]["source_url"]
                print
            #raw_input("Press Enter to continue...")
            elif ip_list[i] in parsed_data[j]["raw_request_URL"] and re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', str(ip_list[i])):
                print "Information for:",ip_list[i]
                print "Raw Request",parsed_data[j]["raw_request_URL"]
                print "Timestamp",parsed_data[j]["time_url"]
                print "Source IP and Port:",parsed_data[j]["source_url"]
                print "Request URL:",parsed_data[j]["request URL"]
                print
    #raw_input("Press Enter to continue...")
    print "Do you need more information? (C'mon, just THIS can't be all for your anti-phishing needs!)->yes/no"
    ans = raw_input(prompt)
    if ans=='yes':
        print "Now querying other sources for threat data....."
    else:
        print "Aw, you could've used more resources!"
        sys.exit()

def virustotal_search(ip_list):
    
    """
    Query for IOCs in the Virus Total database.
    Use regular expressions for hashes, URLs,
    domains and IPs so that correct requests
    (with different URLs) are made to the API.
    
    """
    prompt='>'
    
    for i in range(len(ip_list)):
        if re.findall(r'([a-fA-F\d]{32})',str(ip_list[i])):
            print "********************************************************************************"
            print "Searching for hash "+ip_list[i]+" in VirusTotal......."
            url = "https://www.virustotal.com/vtapi/v2/file/report"
            parameters = {"resource": ip_list[i],"apikey": "1d43c23fa6731ad6adbc48e5136edcecba4c9ba46faefee5356b9268c51b1d1d"}
            data = urllib.urlencode(parameters)
            req = urllib2.Request(url, data)
            response = urllib2.urlopen(req)
            json1 = response.read()
            hdict=json.loads(json1)
            if hdict['response_code']==1:
                print "Scan timestamp:",hdict["scan_date"]
                print "Link to analysis:",hdict["permalink"]
                print "Total scans:",hdict["total"]
                print "Postive scans:",hdict["positives"]
                print
                print "Do you need more information? -> yes/no"
                ans = raw_input(prompt)
                if ans=='yes':
                    hdictf=byteify(hdict)
                    pprint(hdictf, width=1)
                    raw_input("Press Enter to continue...")
                else:
                    raw_input("Press Enter to continue...")
            else:
                    print "NOT FOUND IN VIRUSTOTAL"
                    raw_input("Press Enter to continue...")
        #print json1
        elif re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', str(ip_list[i])):
            print "********************************************************************************"
            print "Searching for URL "+ip_list[i]+" in VirusTotal......."
            url = 'https://www.virustotal.com/vtapi/v2/url/report'
            parameters = {'resource': ip_list[i], 'apikey': '1d43c23fa6731ad6adbc48e5136edcecba4c9ba46faefee5356b9268c51b1d1d'}
            response = urllib.urlopen('%s?%s' % (url, urllib.urlencode(parameters))).read()
            url_dict = json.loads(response)
            if url_dict['response_code']==1:
                print "Resource:",url_dict["resource"]
                print "Scan timestamp:",url_dict["scan_date"]
                print "Total scans:",url_dict["total"]
                print "Postive scans:",url_dict["positives"]
                print "Link to analysis:",url_dict["permalink"]
                print
                print "Do you need more information? ->yes/no"
                ans = raw_input(prompt)
                if ans=='yes':
                    url_dictf=byteify(url_dict)
                    pprint(url_dictf, width=1)
                    raw_input("Press Enter to continue...")
                else:
                    raw_input("Press Enter to continue...")
            else:
                    print "NOT FOUND IN VIRUSTOTAL"
                    raw_input("Press Enter to continue...")
    
        elif re.findall(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', str(ip_list[i])):
            print "********************************************************************************"
            print "Searching for IP "+ip_list[i]+" in VirusTotal......."
            url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
            parameters = {'ip': ip_list[i], 'apikey': '1d43c23fa6731ad6adbc48e5136edcecba4c9ba46faefee5356b9268c51b1d1d'}
            response = urllib.urlopen('%s?%s' % (url, urllib.urlencode(parameters)))
#            response_dict = json.loads(response)
#            print response_dict
            jsonip = response.read()
            ip_dict=json.loads(jsonip)
            if ip_dict['response_code']==1:
                #print "Country:",ip_dict["country"]
                #print "Autonomous System Owner:",ip_dict["as_owner"]
                #print "Autonomous System Number:",ip_dict["asn"]
                print "Total Number of detected urls:",len(ip_dict["detected_urls"])
                print "Total Number of resolutions:",len(ip_dict["resolutions"])
                print "Do you need more information? ->yes/no"
                ans = raw_input(prompt)
                if ans=='yes':
                    ip_dictf=byteify(ip_dict)
                    pprint(ip_dictf, width=1)
                    raw_input("Press Enter to continue...")
                else:
                    raw_input("Press Enter to continue...")
            else:
                print "NOT FOUND IN VIRUSTOTAL"
                raw_input("Press Enter to continue...")
                    
        elif re.findall(r'^[a-zA-Z\d-]{,63}(\.[a-zA-Z\d-]{,63}).$',str(ip_list[i])):
            print "********************************************************************************"
            print "Searching for domain "+ip_list[i]+" in VirusTotal......."
            url = 'https://www.virustotal.com/vtapi/v2/domain/report'
            parameters = {'domain': ip_list[i], 'apikey': '1d43c23fa6731ad6adbc48e5136edcecba4c9ba46faefee5356b9268c51b1d1d'}
            response = urllib.urlopen('%s?%s' % (url, urllib.urlencode(parameters))).read()
            dom_dict = json.loads(response)
            if dom_dict['response_code']==1:
                print "Number of resolutions:",len(dom_dict["resolutions"])
                print "Number of domain siblings",len(dom_dict["domain_siblings"])
                #print "WHOIS information:",dom_dict["whois"]
                print "Please type 'yes'for threat information about domain:"+ip_list[i]+" else no."
                ans = raw_input(prompt)
                if ans=='yes':
                    dom_dictf=byteify(dom_dict)
                    pprint(dom_dictf, width=1)
                    raw_input("Press Enter to continue...")
                else:
                    raw_input("Press Enter to continue...")
            else:
                    print "NOT FOUND IN VIRUSTOTAL"
                    raw_input("Press Enter to continue...")
    print "Thank you for testing this out! Here's to a safer, kinder internet and better malware detection!!:)"


def isc_search(ip_list):
    """
    Query for IOCs in the ISC database. Only for IPs and ports.
    """
    print "searching in ISC..."
    for i in range(len(ip_list)):
        if re.findall(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', str(ip_list[i])):
            print "Information for IP:"+ip_list[i]+" in Internet Storm Centre (ISC).."
            print
            url = 'https://isc.sans.edu/api/ip/'+ip_list[i]+'?json'
            res=urlopen(url)
            jsonip=res.read()
            ip_dict=json.loads(jsonip)
            ip_dictf=byteify(ip_dict)
            pprint(ip_dictf, width=1)

            raw_input("Press Enter to continue...")
        elif re.findall(r'^0*(?:6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{1,3}|[0-9])$', str(ip_list[i])):
            print "Information for Port:"+ip_list[i]+" in Internet Storm Centre (ISC).."
            print
            url = 'https://isc.sans.edu/api/port/'+ip_list[i]+'?json'
            res=urlopen(url)
            jsonp=res.read()
            p_dict=json.loads(jsonp)
            p_dictf=byteify(p_dict)
            pprint(p_dictf, width=1)
            raw_input("Press Enter to continue...")

if __name__ == "__main__":
    main()

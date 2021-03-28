import os
import re
import json
import socket
import ctypes
import traceback
import tldextract
from sys import platform
from sty import ef, fg, rs
from datetime import datetime
from dnsdumpster.DNSDumpsterAPI import DNSDumpsterAPI


# Main function
def urlAnalyse(full_url):
    t1 = datetime.now()
    
    Hostname = getHostName(full_url)
    IP = getIPByHostname(Hostname)
    print(rs.bold_dim + "[+] " + ef.underl + "Hostname:" + rs.u + ef.bold + " " + Hostname + rs.bold_dim)
    print("[+] " + ef.underl + "IP:" + rs.u + ef.bold + " " + IP + rs.bold_dim)
    hr()
    getAllOpenPort(Hostname)
    hr()
    getDNSDumpster(Hostname)
    
    t2 = datetime.now()
    total =  t2 - t1
    hr()
    print(ef.italic + 'Scanning Completed in: ' + str(total) + rs.italic)
    hr()


def getDNSDumpster(Hostname):
    results = DNSDumpsterAPI().search(Hostname)
    subs = results['dns_records']['host']
    x = len(subs)
    print("[+] Sub-domains Found: " + str(x))
    num = 0

    out_result = ""
    for e in subs:
        out_result += ("[" + str(num + 1) + "]" + " Returned Domain\n")
        out_result += ("\t[+] Domain: " + results['dns_records']['host'][num]['domain'] + "\n")
        out_result += ("\t[+] IP Address: " + results['dns_records']['host'][num]['ip'] + "\n")
        out_result += ("\t[+] Header: " +  results['dns_records']['host'][num]['header'] + "\n")
        out_result += ("\t[+] Country: " +  results['dns_records']['host'][num]['country'] + "\n")
        out_result += ("\t[+] Provider: " +  results['dns_records']['host'][num]['provider'] + "\n")
        out_result += ("\t[+] AS: " +  results['dns_records']['host'][num]['as'] + "\n")
        out_result += ("\t[+] Reverse DNS: " +  results['dns_records']['host'][num]['reverse_dns'] + "\n")
        if num + 1 != x:
            out_result += ("\n")
        num += 1

    print(out_result)
    
    
# Function to get URL
def getURL():
    url = input(ef.underl + 'Enter the url to analyse:' + rs.u + " " + ef.bold)
    if(isValidURL(url) == True):
        hr()
        urlAnalyse(url)
    else:
        print(fg.red + "The link seems invalid" + rs.fg + rs.bold_dim)


# Function to get Hostname
def getHostName(full_url):
    tldextract_return = tldextract.extract(full_url) # Initialization of tldextract
    domain_name = tldextract_return.domain + '.' + tldextract_return.suffix
    return domain_name #return Hostname

# Function to get open port
def getAllOpenPort(hostname):
    try:
        between_start = int(input(ef.underl + 'Enter the first port to be scanned (1 minimum):' + rs.u + " " + ef.bold))
        between_end = int(input(rs.bold_dim + ef.underl + 'Enter the last port to be scanned (65535 maximum):' + rs.u + " " + ef.bold))
        
        # will scan ports between 1 to 65,535
        for port in range(between_start, between_end + 1):
        
            if platform == "linux" or platform == "linux2" or platform == "darwin":
                system("title " + "Port currently scanned: " + str(port))
            elif platform == "win32":
                ctypes.windll.kernel32.SetConsoleTitleW("Port currently scanned: " + str(port))
                
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(0.1)
              
            # returns an error indicator
            result = s.connect_ex((hostname,port))
            if result == 0:
                print("Port {} is open".format(port))
            s.close()
    except:
        traceback.print_exc()

# Function to get IP with Hostname
def getIPByHostname(hostname):
    return socket.gethostbyname(hostname)
    
def hr():
    print("-" * 60)
    
def isValidURL(str):
 
    # Regex to check valid URL
    regex = ("((http|https)://)(www.)?" +
             "[a-zA-Z0-9@:%._\\+~#?&//=]" +
             "{2,256}\\.[a-z]" +
             "{2,6}\\b([-a-zA-Z0-9@:%" +
             "._\\+~#?&//=]*)")
     
    # Compile the ReGex
    p = re.compile(regex)
 
    # If the string is empty
    # return false
    if (str == None):
        return False
 
    # Return if the string
    # matched the ReGex
    if(re.search(p, str)):
        return True
    else:
        return False

if __name__ == '__main__':
    # clear console in all plateforme
    if platform == "linux" or platform == "linux2" or platform == "darwin":
        os.system('clear')
    elif platform == "win32":
        os.system('cls')

    getURL()


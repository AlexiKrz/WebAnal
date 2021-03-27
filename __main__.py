import os
import re
import socket
import tldextract
from sys import platform
from sty import ef, fg, rs
from datetime import datetime


# Main function
def urlAnalyse(full_url):
    t1 = datetime.now()
    
    Hostname = getHostName(full_url)
    IP = getIPByHostname(Hostname)
    print(rs.bold_dim + ef.underl + "Hostname:" + rs.u + ef.bold + " " + Hostname + rs.bold_dim)
    print(ef.underl + "IP:" + rs.u + ef.bold + " " + IP + rs.bold_dim)
    hr()
    getAllOpenPort(Hostname)
    
    t2 = datetime.now()
    total =  t2 - t1
    hr()
    print(ef.italic + 'Scanning Completed in: ' + str(total) + rs.italic)
    hr()
    
    
# Function to get URL
def getURL():
    url = input(ef.underl + 'Enter the url to analyse:' + rs.u + " " + ef.bold)
    if(isValidURL(url) == True):
        hr()
        urlAnalyse(url)
    else:
        print(fg.red + "The link seems invalid" + rs.fg + rs.bold_dim)


def getHostName(full_url):
    tldextract_return = tldextract.extract(full_url) # Initialization of tldextract
    domain_name = tldextract_return.domain + '.' + tldextract_return.suffix
    return domain_name #return Hostname


def getAllOpenPort(hostname):
    try:
        # will scan ports between 1 to 65,535
        for port in range(1,65535):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(0.1)
              
            # returns an error indicator
            result = s.connect_ex((hostname,port))
            if result == 0:
                print("Port {} is open".format(port))
            s.close()
    except Exception:
        console = False


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


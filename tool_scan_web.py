import requests
import urllib
import argparse
import re
import validators
import concurrent.futures
import sys
from bs4 import BeautifulSoup
import nmap
from colorama import Fore, init

init(autoreset=True)
print(Fore.BLUE+r'''
                    ________  ____________   _____   ________
                   / ____/ / / /__  /__  /  /  _/ | / / ____/
                  / /_  / / / /  / /  / /   / //  |/ / / __  
                 / __/ / /_/ /  / /__/ /___/ // /|  / /_/ /  
                /_/    \____/  /____/____/___/_/ |_/\____/   
                                                                Version 1.0 / Team 3 
''')


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--url', dest='url', help='Url of target scan.')
    parser.add_argument('-p', '--port', dest='port', help='Port of target scan.')
    parser.add_argument('-r', '--path', dest='path', help='Path file brute force.')
    parser.add_argument('-m', '--mod', dest='mod', help='SQLI, XSS')
    parser.add_argument('-P', '--processes', dest='processes', help='Processes (Default: 4).')
    parser.add_argument('-q', '--query', dest='query', help='Query search google_dork.')
    if len(sys.argv)==1:
        parser.print_help(sys.stderr)
        sys.exit(1)
    options = parser.parse_args()
    return options

def search_cve(vendor):
    print('[*] CVE new for server :')
    query = re.findall('[a-z0-9.\-]+', vendor)
    url = "https://cve.report/search.php?search={}".format(query[0])

    r = requests.get(url)
    soup = BeautifulSoup(r.text, 'html.parser')

    cve = soup.find_all('a')
    for i in cve:
        c = i.get('title')
        if c != None and 'CVE-2022' in c:
            print(c)
    print("-"*86)

def get_banner(url):

    print('_'*86)

    header = {'User-Agent': 'Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36'}
    r = requests.get(url, headers=header)

    h = []
    with open('db/header.txt') as f:
        for x in f:
            h.append(x[:-1])
    for i in r.headers:
        if i in h:
            print('[+] {} : {}'.format(i, r.headers[i]))

    if 'Server' in r.headers:
        print("-"*86)
        search_cve(r.headers['server'])

    lst = ['robots.txt', '.htaccess']
    for i in lst:
        r2 = requests.get(url + "/" + i )
        if r2.status_code == 200:
            print('Found file {} !'.format(i))
            print(r2.text)
            print("-"*86)

    soup = BeautifulSoup(r.text, 'html.parser')
    print("[+] Find all input :")
    input_data = soup.find_all('input')
    print(input_data)
    print("-"*86)
    print("[+] Find all tag meta :")
    meta_data = soup.find_all('meta')
    print(meta_data)
    print("-"*86)

    links = re.findall('(?:href=")(.*?)"', r.text)
    regex_url = r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’]))"
    print("[+] Find all link in web {}\n".format(url))
    for l in set(links):
        valid = re.findall(regex_url, l)
        if valid:
            print(l)

def load_file(url, path):
    lst = []
    with open(path) as f:
        for i in f:
            lst.append(url + i[:-1])
    return lst


def requestx(url_list):

    USER_AGENT = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:65.0) Gecko/20100101 Firefox/65.0'
    header = {'User-agent': USER_AGENT}
    r = requests.get(url_list, headers=header)
    return r


def check_sqli(res, payload):
    payload = re.findall('=.*\w', payload)
    payload = payload[0][1:]
    if "mysql" in res.lower(): 
        print("Injectable MySQL detected,attack string: "+payload)
    elif "native client" in res.lower():
        print("Injectable MSSQL detected,attack string: "+payload)
    elif "syntax error" in res.lower():
        print("Injectable PostGRES detected,attack string: "+payload)
    elif "ORA" in res.lower():
        print("Injectable Oracle database detected,attack string: "+payload)

def check_xss(res, payload):
    payload = re.findall('=.*\w', payload)
    payload = payload[0][1:]
    if str(payload).strip() in res.text:
        print("Payload - "+ payload +" - returned in the response")

def brute_force_page(url, path, processes, mod):

    URLS = load_file(url, path)
    with concurrent.futures.ThreadPoolExecutor(max_workers=processes) as executor:
        future_to_url = {executor.submit(requestx, url_list): url_list for url_list in URLS}
        
        for future in concurrent.futures.as_completed(future_to_url):
            urlx = future_to_url[future]
            try:
                data = future.result()
            except Exception as exc:
                print('%r generated an exception: %s' % (urlx, exc))
            else:
                if mod == None:
                    if data.status_code == 200:
                        print(Fore.GREEN+'[+] %r ------> %d' % (urlx, data.status_code))
                    elif data.status_code == 304:
                        print(Fore.RED+'[+] %r ------> %d' % (urlx, data.status_code))
                if mod == 'sqli':
                    check_sqli(data.text, urlx)
                if mod == 'xss':
                    check_xss(data.text, urlx)

def google_dork(query):

    print('_'*70)
    print(Fore.BLUE+"[*] Find google dork {}\n".format(url))
    query = urllib.parse.quote(query)
    URL = f"https://google.com/search?q={query}"
    USER_AGENT = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:65.0) Gecko/20100101 Firefox/65.0'
    header = {'User-agent': USER_AGENT}
    resp = requests.get(URL, headers=header)
    if resp.status_code == 200:
        soup = BeautifulSoup(resp.text, "html.parser")

    links  = soup.findAll('cite')
    for link in links:
        print('[+] ' + link.text)


def nmap_scan_host(host_scan, portlist):

    print(Fore.BLUE+'\n[*] Scanning nmap : {} \n'.format(host_scan))
    portScanner = nmap.PortScanner()
    h = s = re.findall('\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}', host_scan)
    portScanner.scan(hosts=h[0], arguments='-A -Pn vuln -p'+portlist)

    hosts_list = [(x, portScanner[x]['status']['state']) for x in portScanner.all_hosts()]

    for host, status in hosts_list:
        print(host, status)

        for protocol in portScanner[host].all_protocols():

            print(34*'-'+"Port Description"+34*'-')
            print('Protocol : %s' % protocol)
            lport = portScanner[host][protocol].keys()
            for port in lport:
                state = portScanner[host][protocol][port]['state']
                name = portScanner[host][protocol][port]['name']
                print ('port : {}\tname : {}\tstate : {}'.format(port, name, state))

        print('-'*35 + 'OS Description' +'-'*35)
        print("Details about the scanned host are: \t", portScanner[host]['osmatch'][0]['osclass'][0]['cpe'])
        print("Operating system family is: \t\t", portScanner[host]['osmatch'][0]['osclass'][0]['osfamily'])
        print("Type of OS is: \t\t\t\t", portScanner[host]['osmatch'][0]['osclass'][0]['type']) 
        print("Generation of Operating System :\t", portScanner[host]['osmatch'][0]['osclass'][0]['osgen'])
        print("Operating System Vendor is:\t\t", portScanner[host]['osmatch'][0]['osclass'][0]['vendor'])
        print("Accuracy of detection is:\t\t", portScanner[host]['osmatch'][0]['osclass'][0]['accuracy'])
      

def main():

    try:
        options = get_arguments()
        url = options.url 
        if options.mod == None:

            print(Fore.BLUE+'\n[*] Scanning url : {} \n'.format(url))
            get_banner(url)

            if options.query != None:
                google_dork(options.query)

            if options.path != None:
                print('_'*86)
                print(Fore.BLUE+'\n[*] Find hidden page : {} \n'.format(url))
                if options.processes != None:
                    pro = int(options.processes)
                else :
                    pro = 4
                brute_force_page(options.url, options.path, pro, None)
                            
            if options.port != None:
                nmap_scan_host(url, options.port)
        else:
            if options.path != None:
                print('_'*86)
                print(Fore.BLUE+'\n[*] Fuzzing {} : {} \n'.format(options.mod, url))
                if options.processes != None:
                    pro = int(options.processes)
                else :
                    pro = 4
                brute_force_page(options.url, options.path, pro, options.mod)

    except KeyboardInterrupt:
        print(Fore.RED + "[*] User interrupted the program.")
        raise SystemExit(0)

if __name__ == "__main__": 
    main()


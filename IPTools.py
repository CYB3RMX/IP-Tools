#!/usr/bin/env python
#-*- encoding: utf-8 -*-
import os,socket,telnetlib,time
from telnetlib import Telnet
os.system('clear')
print("[!] FIRST YOU NEED TO DOWNLOAD NMAP AND HYDRA...")
print("[!] IF YOU ALREADY HAVE PRESS 0 TO CONTINUE...")
down = int(input("DO YOU WANT TO DOWNLOAD [1/0] ?: "))
if down == 1:
  print("[*] DOWNLOAD STARTS...")
  os.system('pkg install nmap')
  os.system('pkg install hydra')
  print("[*] DOWNLOAD COMPLETED...")
elif down == 0:
  os.system('clear')
else:
  print("\u001b[31m[!] WRONG OPTION..")
print("\u001b[32m")
print("            ___ __   ______ ____ ____ __  ____  __")
print("           / __|\ \ / /| _ )|__ (| _ \| \/ |\ \/ /")
print("           | (__ \ V / | _ \ |_ \| / ||\/| | >  <")
print("           \___|  |_|  |___/|___/|_|_\|_||_|/_/\_\___")
print("\u001b[33m")
print('         《"""""""""""""""""""""""""""""""""""""""""""》')
print("         《    CYB3RMX_ PROGRAMMING & CYBERSECURITY   》")
print("         《       ~~~~~MX Security Corporation~~~~~   》")
print("         《                  IP TOOLS                 》")
print('         《___________________________________________》')
print("\u001b[37m///////////////////////////////////////")
print("[1]---------{ PING }")
print("[2]---------{ NETSTAT }")
print("[3]---------{ WHOIS }")
print("[4]---------{ NSLookup }")
print("[5]---------{ ARP }")
print("[6]---------{ DOMAIN TO IP ADDRESS }")
print("[7]---------{ TRACEROUTE }")
print("[8]---------{ NMAP }")
print("[9]---------{ TELNET CONNECTION }")
print("[10]--------{ HYDRA PASSWORD CRACKER }")
print("[154]--------{ UPDATE IP-TOOLS }")
print("///////////////////////////////////////")
ipx = socket.gethostbyname(socket.gethostname())
time = time.asctime()
print("\u001b[36m")
print(ipx)
print(time)
print("\u001b[0m")
print("////////////////////////")
select = int(input("\u001b[33mCHOOSE: "))
ping = '''
888888  88 888    88 88888888
8     8 88 88 8   88 88
888888  88 88  8  88 88 88888
8       88 88   8 88 88     8
8       88 88    888 88888888
'''
netstat = '''
888    88 8888888 88888888 8888888 88888888 8888888 88888888
88 8   88 88         88    88         88    8     8    88
88  8  88 88888      88    888888     88    8_____8    88
88   8 88 88         88        88     88    8"""""8    88
88    888 8888888    88    888888     88    8     8    88
'''
whoisx = '''
88      88 88    88 8888888 88 888888
88  88  88 88    88 8     8 88 88
88  88  88 88888888 8     8 88 888888
88  88  88 88    88 8     8 88     88
8888888888 88    88 8888888 88 888888
'''
nsl = '''
888    88   888888   88
88 8   88   88       88
88  8  88   888888   88
88   8 88       88   88
88    888 0 888888 0 8888888 0
'''
arp = '''
8888888 8888888  888888
8     8 8      8 8     8
8_____8 8888888  888888
8"""""8 8   8    8
8     8 8    8   8
'''
d2i = '''
888888   888888 88
8     8 8     8 88
8     8    88   88
8     8   8     88
888888   888888 88
'''
trace = '''
88888888 8888888  8888888 8888888 8888888
   88    8      8 8     8 88      88
   88    8888888  8_____8 88      88888
   88    8   8    8"""""8 88      88
   88    8    8   8     8 8888888 8888888
'''
nmapx = '''
888    88 888       888 8888888 888888
88 8   88 88 8     8 88 8     8 8     8
88  8  88 88  8   8  88 8_____8 888888
88   8 88 88   8 8   88 8"""""8 8
88    888 88    8    88 8     8 8
'''
telnet = '''
88888888 8888888 88      888    88 8888888 88888888
   88    88      88      88 8   88 88         88
   88    88888   88      88  8  88 88888      88
   88    88      88      88   8 88 88         88
   88    8888888 8888888 88    888 8888888    88
'''
hydra = '''
8     8 88    88 888888  8888888  8888888
8     8  88  88  8     8 8      8 8     8
8ooooo8    88    8     8 8888888  8_____8
8     8    88    8     8 8   8    8"""""8
8     8    88    888888  8    8   8     8
'''
update = '''
88    88 888888  888888  8888888 88888888 8888888
88    88 8     8 8     8 8     8    88    88
88    88 888888  8     8 8_____8    88    88888
88    88 8       8     8 8"""""8    88    88
88888888 8       888888  8     8    88    8888888
'''
if select == 1:
    os.system('clear')
    print("\u001b[36m")
    print(ping)
    print("/////////////////")
    print("[1] PING IP ADDRESS")
    print("[2] PING DOMAIN")
    print("[0] RETURN BACK TO MAIN MENU")
    print("/////////////////")
    pings = int(input("CHOOSE: "))
    if pings == 1:
        print("=================")
        pingip = str(input("WRITE TARGET IP: "))
        os.system('ping '+pingip)
        print("=================")
        ret = int(input("RETURN BACK TO MAIN MENU [1/0]?: "))
        if ret == 1:
            os.system('clear')
            os.system('python IPTools.py')
        else:
            print("OK.")
    elif pings == 2:
        print("=================")
        pingdo = str(input("WRITE TARGET DOMAIN: "))
        os.system('ping '+pingdo)
        print("=================")
        ret1 = int(input("RETURN BACK TO MAIN MENU [1/0]?: "))
        if ret1 == 1:
            os.system('clear')
            os.system('python IPTools.py')
        else:
            print("OK.")
    elif pings == 0:
        os.system('clear')
        os.system('python IPTools.py')
    else:
        print("YOU SELECTED WRONG OPTION!!")
elif select == 2:
    os.system('clear')
    print(netstat)
    print("\u001b[32m=========")
    os.system('netstat -an')
    print("=========")
    ret2 = int(input("RETURN BACK TO MAIN MENU [1/0]?: "))
    if ret2 == 1:
        os.system('clear')
        os.system('python IPTools.py')
    else:
        print("OK.")
elif select == 3:
    os.system('clear')
    print("\u001b[34m")
    print(whoisx)
    print("$$$$$$$$$$$$$$$$$$$$$$")
    whois = str(input("WRITE TARGET DOMAIN: "))
    os.system('whois '+whois)
    print("$$$$$$$$$$$$$$$$$$$$$$")
    ret3 = int(input("RETURN BACK TO MAIN MENU [1/0]?: "))
    if ret3 == 1:
        os.system('clear')
        os.system('python IPTools.py')
    else:
        print("OK.")
elif select == 4:
    os.system('clear')
    print(nsl)
    print("¥¥¥¥¥¥¥¥¥¥¥¥¥¥¥¥¥¥")
    nslookup = str(input("WRITE TARGET IP/DOMAIN: "))
    os.system('nslookup '+nslookup)
    print("¥¥¥¥¥¥¥¥¥¥¥¥¥¥¥¥¥¥")
    ret4 = int(input("RETURN BACK TO MAIN MENU [1/0]?: "))
    if ret4 == 1:
        os.system('clear')
        os.system('python IPTools.py')
    else:
        print("OK.")
elif select == 5:
    os.system('clear')
    print("\u001b[35m")
    print(arp)
    print("@@@@@@@@@@@@@@@@@@@@@@")
    os.system('arp')
    print("@@@@@@@@@@@@@@@@@@@@@@")
    ret5 = int(input("RETURN BACK TO MAIN MENU [1/0]?: "))
    if ret5 == 1:
        os.system('clear')
        os.system('python IPTools.py')
    else:
        print("OK.")
elif select == 6:
    os.system('clear')
    print("\u001b[36m")
    print(d2i)
    print("××××××××××××××××××××××××××××××")
    print("[1] NORMAL INFORMATION")
    print("[2] DETAILED INFORMATION")
    print("[0] RETURN BACK TO MAIN MENU")
    d2isel = int(input("CHOOSE: "))
    if d2isel == 1:
       domain = str(input("WRITE TARGET DOMAIN: "))
       print(socket.gethostbyname(domain))
       print("××××××××××××××××××××××××××××××")
       ret6 = int(input("RETURN BACK TO MAIN MENU [1/0]?: "))
       if ret6 == 1:
          os.system('clear')
          os.system('python IPTools.py')
    elif d2isel == 2:
       d2ihost = str(input("WRITE HOST ADDRESS: "))
       d2iport = int(input("WRITE HOSTS PORT: "))
       print(socket.gethostbyaddr(d2ihost))
       print(socket.getaddrinfo(d2ihost,d2iport))
       print("××××××××××××××××××××××××××××××")
       ret6 = int(input("RETURN BACK TO MAIN MENU [1/0]?: "))
       if ret6 == 1:
          os.system('clear')
          os.system('python IPTools.py')
    elif d2isel == 0:
        os.system('clear')
        os.system('python IPTools.py')
elif select == 7:
    os.system('clear')
    print("\u001b[35m")
    print(trace)
    print("€€€€€€€€€€€€€€€€€€€€")
    trace = str(input("WRITE TARGET DOMAIN: "))
    os.system('traceroute '+trace)
    print("€€€€€€€€€€€€€€€€€€€€")
    ret7 = int(input("RETURN BACK TO MAIN MENU [1/0]?: "))
    if ret7 == 1:
        os.system('clear')
        os.system('python IPTools.py')
elif select ==8:
    os.system('clear')
    print("\u001b[32m")
    print(nmapx)
    print("oooooooooooooooooooooooooooo")
    print("[1] ALIVE HOST SCAN")
    print("[2] SIMPLE SCAN")
    print("[3] DETAILED SCAN")
    print("[0] RETURN BACK TO MAIN MENU")
    print("oooooooooooooooooooooooooooo")
    nmapsel = int(input("CHOOSE: "))
    if nmapsel == 1:
        print("ooooooooooooooooooooooooooooooo")
        print("[1] 192.168.0.0/24")
        print("[2] 192.168.1.0/24")
        print("[3] 192.168.2.0/24")
        print("[4] 192.168.43.0/24 (For mobile networks)")
        print("ooooooooooooooooooooooooooooooo")
        network = int(input("SELECT YOUR NETWORK: "))
        if network == 1:
          os.system('nmap 192.168.0.0/24')
          nret = int(input("RETURN BACK TO MAIN MENU [1/0]?: "))
          if nret == 1:
            os.system('clear')
            os.system('python IPTools.py')
          else:
            print("\u001b[31m[!] WRONG OPTION..")
        elif network == 2:
            os.system('nmap 192.168.1.0/24')
            nret1 = int(input("RETURN BACK TO MAIN MENU [1/0]?: "))
            if nret1 == 1:
              os.system('clear')
              os.system('python IPTools.py')
            else:
              print("\u001b[31m[!] WRONG OPTION..")
        elif network == 3:
            os.system('nmap 192.168.2.0/24')
            nret2 = int(input("RETURN BACK TO MAIN MENU [1/0]?: "))
            if nret2 == 1:
              os.system('clear')
              os.system('python IPTools.py')
            else:
              print("\u001b[31m[!] WRONG OPTION..")
        elif network == 4:
            os.system('nmap 192.168.43.0/24')
            nret3 = int(input("RETURN BACK TO MAIN MENU [1/0]?: "))
            if nret3 == 1:
              os.system('clear')
              os.system('python IPTools.py')
            else:
              print("\u001b[31m[!] WRONG OPTION..")
        ret8 = int(input("RETURN BACK TO MAIN MENU [1/0]?: "))
        if ret8 == 1:
            os.system('clear')
            os.system('python IPTools.py')
    elif nmapsel == 2:
        scan = str(input("WRITE TARGET: "))
        os.system('nmap '+scan)
        ret9 = int(input("RETURN BACK TO MAIN MENU [1/0]?: "))
        if ret9 == 1:
            os.system('clear')
            os.system('python IPTools.py')
    elif nmapsel == 3:
        Nmaptarget = str(input("WRITE TARGET: "))
        os.system("nmap ' ' -sV -vv "+Nmaptarget)
        ret10 = int(input("RETURN BACK TO MAIN MENU [1/0]?: "))
        if ret10 == 1:
            os.system('clear')
            os.system('python IPTools.py')
    else:
        os.system('clear')
        os.system('python IPTools.py')
elif select == 9:
    os.system('clear')
    print("\u001b[36m")
    print(telnet)
    print("v^v^v^v^v^v^v^v^v^v^v^v")
    telhost = str(input("WRITE HOST TO CONNECT: "))
    telport = int(input("WRITE HOSTS PORT: "))
    with Telnet(telhost,telport) as tn:
        tn.interact()
    ret11 = int(input("RETURN BACK TO MAIN MENU [1/0]?: "))
    if ret11 == 1:
        os.system('clear')
        os.system('python IPTools.py')
elif select == 10:
    os.system('clear')
    print("\u001b[0m")
    print(hydra)
    print("+++++++++++++++++++++++")
    hydra_target = str(input("ENTER THE TARGET: "))
    os.system("hydra -l admin -P passx.txt ''"+hydra_target)
    ret12 = int(input("RETURN BACK TO MAIN MENU [1/0]?: "))
    if ret12 == 1:
        os.system('clear')
        os.system('python IPTools.py')
elif select == 154:
    print(update)
    print("\u001b[32m[*] UPDATING IP-Tools...")
    os.system('git clone https://github.com/CYB3RMX/IP_TOOLS_FOR_TERMUX')
    print("[*] UPDATE COMPLETE.")
    os.system('python IPTools.py')
else:
    print("\u001b[31mYOU SELECTED WRONG OPTION!!!")
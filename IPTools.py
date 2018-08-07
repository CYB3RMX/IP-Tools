#!/usr/bin/env python
#-*- coding: utf-8 -*-
import os,socket
print("\u001b[33m") 
print("           ) ( * )") 
print("       ( ( /( ( ) )\ ) ( ` ( /(") 
print("    )\ )\()) ( )\ ( /( (()/( )\))( )\())") 
print("  (((_) ((_)\ )((_) )\()) /(_))((_)()\ ((_)\ ") 
print(" )\__ __ ((_)((_)_ ((_)\ (_)) (_()((_)__((_)") 
print("/ __|\ \ / /| _ )|__ (_| _ \ | \/ |\ \/ /") 
print("| (__ \ V / | _ \ |_ \ | / | |\/| | >  <") 
print("\___|  |_|  |___/|___/ |_|_\ |_||_|/_/\_\_____") 
print("                                        |_____|")
print("《                                       》")
print("《  CYB3RMX_ PROGRAMMING & CYBERSECURITY 》")
print("《                IP-Tools               》")
print("\u001b[37m///////////////////")
print("[1] PING")
print("[2] NETSTAT")
print("[3] WHOIS")
print("[4] NSLookup")
print("[5] ARP")
print("[6] DOMAIN TO IP ADDRESS")
print("[7] TRACEROUTE")
print("[8] NMAP")
print("[99] UPDATE IP-Tools")
print("///////////////////")
select = int(input("\u001b[33mCHOOSE: "))
if select == 1:
    os.system('clear')
    print("\u001b[36mPING EVERYTHING!")
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
    print("NETSTAT!!")
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
    print("\u001b[34mWHOIS LOOKUP")
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
    print("Name Server Lookup")
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
    print("\u001b[35mADDRESS RESOLUTION PROTOCOL")
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
    print("\u001b[36mDOMAIN TO IP ADDRESS")
    print("××××××××××××××××××××××××××××××")
    domain = str(input("WRITE TARGET DOMAIN: "))
    print(socket.gethostbyname(domain))
    print("××××××××××××××××××××××××××××××")
    ret6 = int(input("RETURN BACK TO MAIN MENU [1/0]?: "))
    if ret6 == 1:
        os.system('clear')
        os.system('python IPTools.py')
elif select == 7:
    os.system('clear')
    print("\u001b[35mTRACEROUTE")
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
    print("\u001b[32mNMAP NETWORK ANALYSIS")
    print("oooooooooooooooooooooooooooo")
    print("[1] ALIVE HOST SCAN")
    print("[2] SIMPLE SCAN")
    print("[3] DETAILED SCAN")
    print("[0] RETURN BACK TO MAIN MENU")
    print("oooooooooooooooooooooooooooo")
    nmapsel = int(input("CHOOSE: "))
    if nmapsel == 1:
        os.system('nmap 192.168.1.0/24')
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
        os.system('nmap 192.168.1.0/24 -sV -vv')
        ret10 = int(input("RETURN BACK TO MAIN MENU [1/0]?: "))
        if ret10 == 1:
            os.system('clear')
            os.system('python IPTools.py')
    else:
        os.system('clear')
        os.system('python IPTools.py')
elif select == 99:
    print("\u001b[32m[*] UPDATING IP-Tools...")
    os.system('git clone https://github.com/CYB3RMX/IP-Tools')
    print("[*] UPDATE COMPLETE.")
else:
    print("\u001b[31mYOU SELECTED WRONG OPTION!!!")
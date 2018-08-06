#!/usr/bin/env python
#-*- coding: utf-8 -*-
import os
print("\u001b[33mIPTools by CYB3RMX_")
print("\u001b[37m///////////////////")
print("[1] PING")
print("[2] NETSTAT")
print("[3] WHOIS")
print("[4] NSLookup")
print("[5] ARP")
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
else:
    print("\u001b[31mYOU SELECTED WRONG OPTION!!!")
#!/bin/python3

def show_title(ver):
    print("")
    print("\033[1;31m _       __                __", end="")
    print("\033[1;96m                __            ")
    print("\033[1;31m| |     / /___  ____  ____/ /", end="")
    print("\033[1;96m___  ___  _____/ /_____  _____")
    print("\033[1;31m| | /| / / __ \/ __ \/ __  /", end="")
    print("\033[1;96m __ \/ _ \/ ___/ //_/ _ \/ ___/")
    print("\033[1;31m| |/ |/ / /_/ / /_/ / /_/ /", end="")
    print("\033[1;96m /_/ /  __/ /__/ ,< /  __/ /    ")
    print("\033[1;31m|__/|__/\____/\____/\__,_/", end="")
    print("\033[1;96m .___/\___/\___/_/|_|\___/_/     ")
    print("\033[1;96m                        /_/                           \033[0;0m")
    print("\033[1;31mNetwork Vulnerability \033[1;96mTester       Version:", ver, "\033[0;0m")
    print("\033[1;31m---------------------\033[1;96m--------------------------------------\033[0;0m")
    print("Written by: Lothar TheQuiet")
    print("lotharthequiet@gmail.com")
    print("")
    print("")

def progressbar(progress, total, barcolor):
    endcolor = "\033[0;0m"
    if barcolor == "none":
        startcolor = endcolor
    if barcolor == "green":
        startcolor = "\033[1;32m"
    if barcolor == "red":
        startcolor = "\033[1;31m"
    if barcolor == "blue":
        startcolor = "\033[1;96m"
    percent = 100 * (progress / float(total))
    bar = f"{startcolor}={endcolor}" * int(percent) + "-" * (100 - int(percent))
    if percent == 100:
        print(f"\r{startcolor}|{endcolor}{bar}{startcolor}|{endcolor} {percent:.2f}%\n\n", end="")
    else:
        print(f"\r{startcolor}|{endcolor}{bar}{startcolor}|{endcolor} {percent:.2f}%", end="\r")

def drawdiv(divcolor):
    endcolor = "\033[0;0m"
    if divcolor == "none":
        startcolor = endcolor
    if divcolor == "green":
        startcolor = "\033[1;32m"
    if divcolor == "red":
        startcolor = "\033[1;31m"
    if divcolor == "blue":
        startcolor = "\033[1;96m"
    print(f"{startcolor}+----------------------------------------------------------------------------------------------------+{endcolor}")
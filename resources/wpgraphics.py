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

def progressbar(progress, total):
    percent = 100 * (progress / float(total))
    bar = "\033[32m=\033[0m" * int(percent) + "-" * (100 - int(percent))
    if percent == 100:
        print(f"\r\033[32m|\033[0m{bar}\033[32m|\033[0m {percent:.2f}%\n\n", end="")
    else:
        print(f"\r\033[32m|\033[0m{bar}\033[32m|\033[0m {percent:.2f}%", end="\r")

def drawdiv():
    print("------------------------------------------------------------------------------------------------------")

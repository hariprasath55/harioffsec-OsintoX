import os
import random
import shutil
import socket
import string
import subprocess
import threading
import time
import BetterPrinting as bp
import re
import sqlite3
from requests.structures import CaseInsensitiveDict
import requests
import colorama
import logging
from logging import NullHandler
from paramiko import SSHClient, AutoAddPolicy, AuthenticationException, ssh_exception
import sys
import csv
import ipaddress
from .port_data import check_ports
from .gui_pytheas import string_port


class PortScanner:
    ip_subnett = []
    waiting = False
    well_known_ports = [20, 21, 22, 23, 25, 53, 80, 110, 119, 123, 135, 139, 143, 161, 194, 389, 443, 445, 515, 520,
                        636, 3389, 5060, 5061, 5357, 8001, 8002, 8080, 9080, 9999, 62078]
    is_web = False
    all_colors = ["red", "blue", "green", "cyan", "yellow", "magenta"]
    random_color = random.choice(all_colors)
    ssh_port = []
    every_ip_with_name = []
    my_ip_address = None
    check_open_port = []
    hostnames = {}
    hostname = None
    open_ports = []
    nice_printing = []
    all_intern_ip = None
    scan_all = False
    pps = False
    ipv6 = False
    public_ip = False

    def __init__(self):
        self.headers = None
        self.country_name = None
        self.addresses = None
        self.gui = string_port

    def print_gui(self):
        bp.color(self.gui, PortScanner.random_color)

    def cool_text(self):
        thread_wait = threading.Thread(target=PortScanner.wait)
        thread_wait.start()
        time.sleep(5)
        PortScanner.waiting = True
        time.sleep(1)
        PortScanner.waiting = False

    def get_lst(self, port_range="20-80", known_ports=False):
        error = "ERROR (EXAMPLE: 20-80)"
        if known_ports is True:
            return PortScanner.well_known_ports

        try:
            if "-" in port_range:
                try:
                    return range(int(port_range.split("-")[0]), int(port_range.split("-")[1]) + 1)
                except ValueError:
                    return error
            else:
                print(error)
                quit()
        except TypeError:
            return error

    @staticmethod
    def check_char(wort, idx, zeichen):
        wort = [*wort]
        wort[idx] = zeichen
        wort = "".join(wort)
        return wort

    @staticmethod
    def print_text(word):
        color = bp.color(f"\r{word}", PortScanner.random_color, False)
        print(color, end="")

    @staticmethod
    def wait():
        wort = "Welcome to PYTHEAS22".upper()
        print()
        while True:
            for idx, letter in enumerate(wort):
                try:
                    if letter.upper() == letter:
                        new = letter.lower()
                    else:
                        new = letter.upper()

                    wort = PortScanner.check_char(wort, idx, new)

                    if "2" == letter:
                        wort = PortScanner.check_char(wort, idx, "?")

                    elif "?" == letter:
                        wort = PortScanner.check_char(wort, idx, "2")
                    PortScanner.print_text(wort)
                    time.sleep(0.1)
                    wort = PortScanner.check_char(wort, idx, letter)
                    PortScanner.print_text(wort)

                    if PortScanner.waiting:
                        print()
                        sys.exit()
                except KeyboardInterrupt:
                    quit()

    @staticmethod
    def add_to_db(country_names, ip_address, open_ports, name=""):
        if name != "":
            port_name = f"{country_names[name]}_Ports.db"
        else:
            port_name = f"Ports.db"
        con = sqlite3.connect(port_name)

        cur = con.cursor()
        cur.execute('''CREATE TABLE IF NOT EXISTS Ports
                        (IPAddress, Open Ports)''')

        cur.execute("INSERT OR IGNORE INTO Ports VALUES (?,?)",
                    (ip_address, open_ports))
        con.commit()

    @staticmethod
    def add_to_db_intern(ip_address, open_ports):
        con = sqlite3.connect('Internal_Network.db')

        cur = con.cursor()
        cur.execute('''CREATE TABLE IF NOT EXISTS Ports
                                (IPAddress, Open Ports, Time)''')

        cur.execute("INSERT OR IGNORE INTO Ports VALUES (?,?,?)",
                    (ip_address, open_ports, time.strftime("%d.%m.%y - %H:%M")))
        con.commit()

    @classmethod
    def get_ip(cls):
        open_ports = subprocess.run(["ip", "a"], capture_output=True)
        everything = str(open_ports).split()
        ipaddress = [everything[ip + 1] for ip, inet in enumerate(everything) if inet == "inet"]

        for each_ip in ipaddress:
            real_ip = each_ip.split("/")
            if real_ip[0] != "127.0.0.1":
                cls.ip_subnett.append((real_ip[0], real_ip[1]))

        host = cls.ip_subnett[0][0].split(".")
        host[-1] = "0"
        host_ip = ".".join(host)
        return host_ip, cls.ip_subnett

    def counter(self, country):
        res = requests.get(
            f"http://www.insecam.org/en/bycountry/{country}", headers=self.headers
        )
        last_page = re.findall(r'pagenavigator\("\?page=", (\d+)', res.text)[0]
        all_ips = []
        for page in range(int(last_page)):
            res = requests.get(
                f"http://www.insecam.org/en/bycountry/{country}/?page={page}",
                headers=self.headers
            )
            find_ip = re.findall(r"http://\d+.\d+.\d+.\d+:\d+", res.text)

            all_ips.extend(find_ip)
            amount = bp.color(f"\rScanning {page + 1} of {int(last_page)}".upper(), PortScanner.random_color, False)
            print(amount, end="")
        directory = f"{self.country_name[country]}_hacked_IP_Cameras"
        if os.path.exists(directory):
            shutil.rmtree(directory)

        os.mkdir(directory)
        os.chdir(directory)
        with open(f"{self.country_name[country]}_IP-Cameras.txt", "a+") as file:
            for each_ip in all_ips:
                file.write(f"{each_ip}\n")

        return all_ips

    def ask_range(self):
        lst_everything = []
        str_quest = bp.color("Do you want to parse through wellknown ports? y/n: ", PortScanner.random_color, False)
        question = input(str_quest)

        if question == "y":
            lst_everything.extend(PortScanner.well_known_ports)
        else:
            bp.color(
                "To specify the range you simply write 'number1-number2'. "
                "Number 1 should be smaller than number 2\nIf you only want "
                "to scan one port. Just type one number".upper(),
                PortScanner.random_color)
            str_range = bp.color("What is your range: ", PortScanner.random_color, False)
            while True:
                str_port_range = input(str_range)
                if "-" in str_port_range:
                    try:
                        first_number, second_number = int(str_port_range.split("-")[0]), int(
                            str_port_range.split("-")[1])
                        if first_number > second_number:
                            print("SECOND NUMBER IS GREATER THAN THE FIRST NUMBER. (min-max)")
                            continue

                        get_range = PortScanner()
                        real_range = get_range.get_lst(port_range=str_port_range)
                        lst_everything.ext

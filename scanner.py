"""
Network Scanning Script

This script performs an Nmap scan on a given network CIDR range, 
validates input, and saves the results in a user-specified format.
It uses the Nmap Python library and displays progress with tqdm.

Modules used:
- os
- time
- subprocess
- ipaddress
- datetime
- nmap
- tqdm
"""

import os
import time
import subprocess
import ipaddress
from datetime import datetime

import nmap
from tqdm import tqdm

def getHelp():
    """
    Display help information about the script.
    """
    help_text = """
    Network Scanning Script
    -----------------------
    This script performs an Nmap scan on a given network CIDR range, validates input, 
    and saves the results in a user-specified format.

    Usage:
        python script.py
    
    Features:
    - CIDR validation
    - Nmap scanning with custom options
    - Progress tracking with tqdm
    - Results saved in XML, JSON, grepable, or normal format

    Options:
    - You will be prompted to enter a CIDR range (e.g., 192.168.1.0/24)
    - You can choose an output format: xml, json, grepable, or normal
    - The scan uses default options: '-sS -sV -O -A -p 1-1000'

    Example:
        Please enter the CIDR range: 192.168.1.0/24
        Enter output format (xml/json/grepable/normal): xml

    Dependencies:
    - Python modules: os, time, subprocess, ipaddress, datetime, nmap, tqdm
    - Ensure Nmap is installed on your system.

    To exit, use Ctrl+C.
    """
    print(help_text)

    

def validate_cidr(cidr):
    """
    Validate if the CIDR is in a correct format.

    :param cidr: CIDR range string (e.g., "192.168.1.0/24")
    :return: True if valid, False otherwise
    """
    try:
        ipaddress.IPv4Network(cidr)
        return True
    except ValueError:
        print("Invalid CIDR format. Please use the correct format like 192.168.1.0/24.")
        return False


def get_user_input():
    """
    Get a valid CIDR input from the user.

    :return: Valid CIDR range string
    """
    while True:
        cidr_input = input("Please enter the CIDR range (e.g., 192.168.1.0/24): ").strip()
        if validate_cidr(cidr_input):
            return cidr_input


def generate_unique_filename(output_format, target_cidr):
    """
    Generate a unique filename based on the scan target and output format.

    :param output_format: Output file format (xml, json, grepable, normal)
    :param target_cidr: Target CIDR range
    :return: Unique filename string
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = target_cidr.replace("/", "_").replace(".", "_")
    return f"nmap_scan_{safe_target}_{timestamp}.{output_format}"


def scan_network(target, options, output_format):
    """
    Perform an Nmap scan on the target network.

    :param target: Target CIDR range
    :param options: Nmap scan options
    :param output_format: Output format for Nmap results
    """
    scanner = nmap.PortScanner()
    scanner.scan(target, arguments=options)

    for host in scanner.all_hosts():
        print(f"Host: {host}")
        print(f"State: {scanner[host].state()}")

        for proto in scanner[host].all_protocols():
            print(f"Protocol: {proto}")
            ports = scanner[host][proto].keys()
            for port in ports:
                print(
                    f"Port: {port}, "
                    f"State: {scanner[host][proto][port]['state']}"
                )

    valid_formats = ["xml", "json", "grepable", "normal"]
    if output_format not in valid_formats:
        print("Invalid output format specified. Using default 'xml'.")
        output_format = "xml"

    output_filename = generate_unique_filename(output_format, target)

    if os.path.exists(output_filename):
        print(f"Output file {output_filename} already exists, overwriting.")

    output_flags = {
        "xml": "-oX",
        "json": "-oJ",
        "grepable": "-oG",
        "normal": "-oN"
    }
    output_flag = output_flags[output_format]

    total_ports = 1000
    with tqdm(
        total=total_ports,
        desc="Scanning Ports",
        unit="port",
        dynamic_ncols=True,
        colour="green"
    ) as pbar:

        command = (
            f"nmap {output_flag} {output_filename} {options} {target}"
        )

        process = subprocess.Popen(
            command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )

        for line in process.stdout:
            line = line.decode("utf-8")
            if "Ports scanned" in line:
                pbar.update(10)
            time.sleep(0.1)

        process.communicate()

    print(f"Scan complete. Results saved to {output_filename}")


def main():
    """
    Main function to execute the network scanning process.
    """
    if input("Need help? (yes/no): ").strip().lower() == "yes":
        getHelp()
        return

    target_cidr = get_user_input()
    options = "-sS -sV -O -A -p 1-1000"
    output_format = input("Enter output format (xml/json/grepable/normal): ").strip().lower()
    scan_network(target_cidr, options, output_format)

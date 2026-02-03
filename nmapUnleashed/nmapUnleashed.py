# This software is free for personal and small-company use (<50 employees).
# Commercial use requires a license. See https://license.nmap-unleashed.com or contact sharkeonix@pm.me.

###CLI-Frontend
#import signal

import typer
from typing import Optional
from typing_extensions import Annotated
from rich import print as rich_print
import pickle
import shlex
###Backend/Dashboard###
import re
import ipaddress
import os
import sys
import threading
import time
import queue
import datetime
import subprocess
from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.layout import Layout
from rich.progress import Progress, BarColumn, TextColumn, TimeElapsedColumn
#from rich.markup import escape
import psutil
import copy
#import readchar
#from pynput.keyboard import Key, Listener
import termios, tty
from prompt_toolkit import Application
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout import Layout as prompt_toolkitLayout
from prompt_toolkit.widgets import TextArea as prompt_toolkitTextArea
import glob
import json5 as json
import shutil
import xml.etree.ElementTree as ET

CONFIG_FILE_CONTENT = '''
// nmapUnleashed Config
{

//// Default Parameter sets
//--------------------------------------------------
"parameterSets":    {
        "basic": "-d -p- -A",
        "basic-offline": "-d -p- -A -Pn",
        "safe": "-th 2 -kt 120 -d -p - -sV --exclude-ports 9100 --exclude localhost",
        "default": "-th 4 -kt 120 --exclude localhost -nwr 5000 -nwt 5000 -d -p- -A"
    },
//--------------------------------------------------

//// CLI Configuration
//--------------------------------------------------
"cliConfiguration": {
    "DEFAULT_NumberOfThreads": 4
},
//--------------------------------------------------


//// Dashboard and Backend Configuration
//--------------------------------------------------
"configuration": {
    "NETWORK_WARNING_RECEIVE": 0, //default: 0, At what KBps to warn about receiving to much network traffic. 0 means disabled.
    "NETWORK_WARNING_TRANSMIT": 0, //default: 0, At what KBps to warn about transmitting to much network traffic. 0 means disabled.
    "OUTPUT_PATTERN": "{target}", //default: "{target}", parameter is also available i.e. "{target}_{parameter}". "{target}" is mandatory!
    "REMOVE_FILES": "", //default: "", which scan files to remove after completion i.e. "xml" or "xml;gnmap"
    "NO_FOLDER_PER_SCAN": false, //default: false, if a folder should be created for each scan
    "KEEP_OFFLINE_FILES": false, //default false, if scan files where host was offline should not be removed
    "NO_DASHBOARD_FILE": false, //default false, if the dashboard.txt file should be created or not
    "REFRESH_RATE": 0.2,  //default: 0.2 seconds, refreshrate of dashboard
    "REFRESH_RATE_FOR_WORKER": 0.05, //default: 0.05 seconds, wait x seconds for next check if workers finished
    "REFRESH_RATE_FOR_FINAL_THREAT_WAIT": 0.05, //default: 0.05 seconds, wait x seconds for next check if all threads have finished
    "REFRESH_NMAP_STATS": 1, //default: 1 seconds, passed to nmap via "--stats-every" to controll how often stats are outputted
    "DATETIME_STR_FORMAT": "%Y-%m-%d | %H:%M:%S", //default: "%Y-%m-%d | %H:%M:%S", datetime format for dashboard, i.e. start and stop time
    "DASHBOARD_MAX_SIZE_THREADS": 10, //default: 10, how many rows max for active threads
    "DASHBOARD_MAX_SIZE_DONE": 4, //default: 4, how many rows max for finished scans
    "DASHBOARD_MAX_SIZE": 14, //DASHBOARD_MAX_SIZE_THREADS + DASHBOARD_MAX_SIZE_DONE #max size of dashboard regarding scans, before it switches to scroll mode
    "NETWORK_MAX_SIZE": 4, //default: 4, max size of network dashboard section, before it switches to scroll mode
    "DASHBOARD_SCROLL_SPEED_MODIFIER": 1, //default: 1, factor (REFRESH_RATE * DASHBOARD_MAX_SIZE * DASHBOAD_SCROLL_SPEED_MODIFIER)
    "DYNAMIC_DASHBOARD_SIZE": true, //default: false, Regulates weather to adjust the dashboard size dynamically.
    "SCAN_KILL_PENDING_WAIT": 3, //default: 3, seconds, how long a kill of scan is pending for confirmation before reset
    "SCAN_KILL_PENDING_REFRESH": 1, //default: 1, seconds, how long to wait for next check if a kill is pending
    "FEATURE_LOADER_PARALLEL_REFRESHRATE": 0.2, //default: 0.2, seconds, how long to wait before parallel features are executed again
    "RECOVERY_FILE": ".nmapUnleashed.recover", //default: ".nmapUnleashed.recover", File tracking passed args, options and targets to help recovery
    "TRACK_STATE_FILE": ".nmapUnleashed.stateTrack", //default: ".nmapUnleashed.stateTrack", File tracking scan state to help recovery
    "TRACK_TARGET_STATE_REFRESHRATE": 1, //default: 1, seconds, how often the target states are saved to disk
    "MERGED_SCAN_FILE": "scans", // default: "scans", filename for merged scans as xml and html
    "NO_SCANS_FILE": false, // default: false, if scans.xml and scans.html should not be created
    "ONLY_SCANS_FILE": false, // default: false, if only scans.xml and scans.html should be created and no individual scan files
    "ORIGINAL_COLORS": false // default: false, if nmap's original color scheme should be used for scans.html or not
}
//--------------------------------------------------

}
'''

###CONFIG FILE LOCATION
CONFIG_FILE_LOCATION = os.path.expanduser("~/.config/nmapUnleashed/nmapUnleashed.conf")
#CONFIG_FILE_LOCATION = "../nmapUnleashed.conf"
# Ensure config file exists
if not os.path.exists("".join([var+"/" for var in CONFIG_FILE_LOCATION.split("/")[:-1]])):
    os.makedirs("".join([var+"/" for var in CONFIG_FILE_LOCATION.split("/")[:-1]]))
if not os.path.isfile(CONFIG_FILE_LOCATION):
    with open(CONFIG_FILE_LOCATION, "w") as file:
        file.write(CONFIG_FILE_CONTENT)
# Try to load config file
CONFIG = None
try:
    with open(CONFIG_FILE_LOCATION, "r") as file:
        CONFIG = json.load(file)
except Exception as e:
    raise Exception(f'Config file could not be loaded: {CONFIG_FILE_LOCATION}')


###CLI-Frontend
########################################################################################################################
########################################################################################################################
########################################################################################################################
##########COLORS##########
#All colors extracted from transparent default kali terminal
COLORS = {
    #Colors Transparent Terminal: cyan -> #069aeb
    "cyan": "#069aeb",
    #Colors Transparent Terminal: cyan2 -> #02f4ce
    "cyan2": "#02f4ce",
    #Colors Transparent Terminal: sky_blue1 -> #8cd8fe
    "skyBlue": "#8cd8fe",
    #"white on dark_orange3"  #ce5c02
    "woDarkOrange": "white on #ce5c02",
    #"white on dark_sea_green4"  #5ca85c
    "woDarkGreen": "white on #5ca85c",
    #"white on grey37"  #5c5c5c
    "woGrey37": "white on #5c5c5c",
    #"white on red"  #ca1a1a
    "woRed": "white on #ca1a1a",
    #"cyan1"  #01f3f3
    "cyan1": "#01f3f3",
    #"red"  #ca1a1a
    "red": "#ca1a1a",
    #"dark_sea_green4"  #5ca85c
    "darkGreen": "#5ca85c",
    #"dark_orange3"  #ce5c02
    "darkOrange": "#ce5c02",
    #"grey69"  #a8a8a8
    "grey69": "#a8a8a8",
    #"white"  #f4f4f4
    "white": "#f4f4f4",
    #"green3"  #01ce02
    "green3": "#01ce02",
    #"white on grey19"  #2f3030
    "woGrey19": "white on #2f3030",
    #turquoise2 #01cef4
    "lightCyan": "#01cef4"

}
##########META##########
AUTHOR = "Sharkeonix"
WEBSITE = "https://nmap-unleashed.com"
DOCS = "https://docs.nmap-unleashed.com"
LICENSE = "https://license.nmap-unleashed.com"
VERSION = "v1.1.0"
LASTUPDATEDATE= "2026-02-03"
LOGO = f'''
[{COLORS["cyan"]} bold].__   __. .___  ___.      ___      .______      [/{COLORS["cyan"]} bold][{COLORS["cyan2"]} bold] __    __  .__   __.  __       _______     ___           _______. __    __   _______  _______   [/{COLORS["cyan2"]} bold]
[{COLORS["cyan"]} bold]|  \\ |  | |   \\/   |     /   \\     |   _  \\ [/{COLORS["cyan"]} bold][{COLORS["cyan2"]} bold]    |  |  |  | |  \\ |  | |  |     |   ____|   /   \\         /       ||  |  |  | |   ____||       \\  [/{COLORS["cyan2"]} bold]
[{COLORS["cyan"]} bold]|   \\|  | |  \\  /  |    /  ^  \\    |  |_)  | [/{COLORS["cyan"]} bold][{COLORS["cyan2"]} bold]   |  |  |  | |   \\|  | |  |     |  |__     /  ^  \\       |   (----`|  |__|  | |  |__   |  .--.  | [/{COLORS["cyan2"]} bold]
[{COLORS["cyan"]} bold]|  . `  | |  |\\/|  |   /  /_\\  \\   |   ___/  [/{COLORS["cyan"]} bold][{COLORS["cyan2"]} bold]   |  |  |  | |  . `  | |  |     |   __|   /  /_\\  \\       \\   \\    |   __   | |   __|  |  |  |  | [/{COLORS["cyan2"]} bold]
[{COLORS["cyan"]} bold]|  |\\   | |  |  |  |  /  _____  \\  |  |       [/{COLORS["cyan"]} bold][{COLORS["cyan2"]} bold]  |  `--'  | |  |\\   | |  `----.|  |____ /  _____  \\  .----)   |   |  |  |  | |  |____ |  '--'  | [/{COLORS["cyan2"]} bold]
[{COLORS["cyan"]} bold]|__| \\__| |__|  |__| /__/     \\__\\ | _|      [/{COLORS["cyan"]} bold][{COLORS["cyan2"]} bold]    \\______/  |__| \\__| |_______||_______/__/     \\__\\ |_______/    |__|  |__| |_______||_______/ [/{COLORS["cyan2"]} bold]'''
INFO = f'Version: {VERSION} | Author: {AUTHOR} | Website: {WEBSITE} | License: {LICENSE}'
BANNER = f'{LOGO}\n\n[{COLORS["skyBlue"]}]{INFO}[/{COLORS["skyBlue"]}]'
META = {
    "AUTHOR": AUTHOR,
    "WEBSITE": WEBSITE,
    "VERSION": VERSION,
    "LASTUPDATE": LASTUPDATEDATE,
    "LOGO": LOGO,
    "INFO": INFO,
    "BANNER": BANNER,
}
########################
##########EXAMPLES##############
EXAMPLES =f'''
[bold]Examples[/bold]
--------------------
[{COLORS["skyBlue"]}]# Classic Nmap scan of all ports with version detection.[/{COLORS["skyBlue"]}]
  nu -d -p- -A scanme.nmap.org
[{COLORS["skyBlue"]}]# Scan multiple targets specified as IPs, CIDRs, or files in 8 parallel scans and only create merged scan results (scans.xml, scans.html).[/{COLORS["skyBlue"]}]
  nu -th 8 -p- -A scanme.nmap.org 192.168.178.0/24 targets.txt -os
[{COLORS["skyBlue"]}]# Use a predefined parameter set (see [italic]{CONFIG_FILE_LOCATION}[/italic] for custom sets).[/{COLORS["skyBlue"]}]
  nu -ps basic scanme.nmap.org
[{COLORS["skyBlue"]}]# 8 threads, auto-abort after 120 min, warn if network >1000 KBps, keep files for non-online targets.[/{COLORS["skyBlue"]}]
  nu -th 8 -kt 120 -nwr 1000 -nwt 1000 -ko -p- -sV scanme.nmap.org
[{COLORS["skyBlue"]}]# Keep scan files for non-online targets, store all scans in the current folder, remove specified file types after scan.[/{COLORS["skyBlue"]}]
  nu -ko -nf -rf "xml;html;gnamp" -p- -A fd12:3456:789a::/28
[{COLORS["skyBlue"]}]# Specify Nmap parameters and targets, set custom parameters for a target network, and exclude one target of the specified network.[/{COLORS["skyBlue"]}]
  nu -p- -A 10.10.2.1 10.10.2.2 "10.10.1.0/24=--top-ports 100 -A" -ex 10.10.1.5
--------------------
For more information please visit the nmapUnleashed docs at {DOCS}.

[{COLORS["grey69"]}]This software is free for personal and small-company use (<50 employees).
Commercial use requires a license. See {LICENSE} or contact sharkeonix@pm.me.[/{COLORS["grey69"]}]
'''
################################

##########Default Values########
DEFAULT_NumberOfThreads = 4
########################
#Trying to load config from file
try:
    if CONFIG:
        DEFAULT_NumberOfThreads = CONFIG["cliConfiguration"]["DEFAULT_NumberOfThreads"]
except:
    pass


def main(
        ctx: typer.Context,
        targets: Annotated[Optional[list[str]], typer.Argument(help="Targets as: IP, CIDR, DNS or file with target per line; Optionally use \"<target>=<nmapParameter>\" for individual parameters per target.", rich_help_panel=f'[{COLORS["lightCyan"]} bold]nmapUnleashed Arguments[/{COLORS["lightCyan"]} bold]')] = None,
        # Scan options
        threads: Annotated[int, typer.Option('-th', "--threads", help="Number of threads (max parallel scans).", rich_help_panel=f'[{COLORS["lightCyan"]} bold]nmapUnleashed Scan Options[/{COLORS["lightCyan"]} bold]', metavar="<number>")] = DEFAULT_NumberOfThreads,
        parameterSet: Annotated[str, typer.Option('-ps', "--parameter-set", help=f'Apply a predefined parameter set (nmap and unleashed parameter) from {CONFIG_FILE_LOCATION}, merged with parameters given at runtime.: {str({key:value for key, value in CONFIG["parameterSets"].items()})}', rich_help_panel=f'[{COLORS["lightCyan"]} bold]nmapUnleashed Scan Options[/{COLORS["lightCyan"]} bold]', metavar="<id>")] = None,
        killThreshold: Annotated[int, typer.Option('-kt', "--kill-threshold", help="Automatically abort a scan if it reaches the specified runtime.", rich_help_panel=f'[{COLORS["lightCyan"]} bold]nmapUnleashed Scan Options[/{COLORS["lightCyan"]} bold]', metavar="<minutes>")] = None,
        exclude: Annotated[list[str], typer.Option('-ex', "--exclude", help="Exclude passed target(s) (IP, CIDR, DNS, File) from target list.", rich_help_panel=f'[{COLORS["lightCyan"]} bold]nmapUnleashed Scan Options[/{COLORS["lightCyan"]} bold]', metavar="<target>")] = None,

        # Dashboard options
        networkWarningReceive: Annotated[int, typer.Option('-nwr', "--network-warning-receive", help="Warn if incoming network traffic reaches defined KBps (0 to disable).", rich_help_panel=f'[{COLORS["lightCyan"]} bold]nmapUnleashed Dashboard Options[/{COLORS["lightCyan"]} bold]', metavar="<integerInKBps>")] = CONFIG["configuration"]["NETWORK_WARNING_RECEIVE"],
        networkWarningTransmit: Annotated[int, typer.Option('-nwt', "--network-warning-transmit", help=" Warn if outgoing network traffic reaches defined KBps (0 to disable).", rich_help_panel=f'[{COLORS["lightCyan"]} bold]nmapUnleashed Dashboard Options[/{COLORS["lightCyan"]} bold]', metavar="<integerInKBps>")] = CONFIG["configuration"]["NETWORK_WARNING_TRANSMIT"],
        fixedDashboardSize: Annotated[bool, typer.Option('-fs', "--fixed-size", help=f'Keep the dashboard size fixed.', rich_help_panel=f'[{COLORS["lightCyan"]} bold]nmapUnleashed Dashboard Options[/{COLORS["lightCyan"]} bold]')] = False,

        # Output options
        keepOfflineFiles: Annotated[bool, typer.Option('-ko', "--keep-offline", help="Preserve scan files for non-online targets; they are always listed in dashboard.txt.", rich_help_panel=f'[{COLORS["lightCyan"]} bold]nmapUnleashed Output Options[/{COLORS["lightCyan"]} bold]')] = CONFIG["configuration"]["KEEP_OFFLINE_FILES"],
        removeFiles: Annotated[str, typer.Option('-rf', "--remove-files", help="Delete specified scan files after completion (e.g., \"xml\" or \"xml;gnmap\").", rich_help_panel=f'[{COLORS["lightCyan"]} bold]nmapUnleashed Output Options[/{COLORS["lightCyan"]} bold]', metavar="<listOfFileTypes>")] = CONFIG["configuration"]["REMOVE_FILES"] if CONFIG["configuration"]["REMOVE_FILES"] != "" else None,
        noFolderPerScan: Annotated[bool, typer.Option('-nf', "--no-folder", help="Store all scan files in the current directory instead of creating a subfolder per scan.", rich_help_panel=f'[{COLORS["lightCyan"]} bold]nmapUnleashed Output Options[/{COLORS["lightCyan"]} bold]')] = CONFIG["configuration"]["NO_FOLDER_PER_SCAN"],
        outputPattern: Annotated[str, typer.Option('-op', "--output-pattern", help="Set the naming pattern for scan files and folders (e.g., {target}_{parameter});{target} is mandatory.", rich_help_panel=f'[{COLORS["lightCyan"]} bold]nmapUnleashed Output Options[/{COLORS["lightCyan"]} bold]', metavar="<outputPattern>")] = CONFIG["configuration"]["OUTPUT_PATTERN"],
        noDashboardFile: Annotated[bool, typer.Option('-nd', "--no-dashboard", help="Do not create the dashboard.txt file (holding an overview over performed scans and their states).", rich_help_panel=f'[{COLORS["lightCyan"]} bold]nmapUnleashed Output Options[/{COLORS["lightCyan"]} bold]')] = CONFIG["configuration"]["NO_DASHBOARD_FILE"],
        noScansFile: Annotated[bool, typer.Option('-ns', "--no-scans", help="Do not create the scans.xml and scans.html file (holding the merged scan results).", rich_help_panel=f'[{COLORS["lightCyan"]} bold]nmapUnleashed Output Options[/{COLORS["lightCyan"]} bold]')] = CONFIG["configuration"]["NO_SCANS_FILE"],
        onlyScansFile: Annotated[bool, typer.Option('-os', "--only-scans", help="Only create the scans.xml and scans.html file (holding the merged scan results) and no files for each individual scan.", rich_help_panel=f'[{COLORS["lightCyan"]} bold]nmapUnleashed Output Options[/{COLORS["lightCyan"]} bold]')] = CONFIG["configuration"]["ONLY_SCANS_FILE"],
        originalColors: Annotated[bool, typer.Option('-oc', "--original-colors", help="Do not tamper the scans.html and keep nmap's original color scheme.", rich_help_panel=f'[{COLORS["lightCyan"]} bold]nmapUnleashed Output Options[/{COLORS["lightCyan"]} bold]')] = CONFIG["configuration"]["ORIGINAL_COLORS"],

        # Misc options
        config: Annotated[list[str], typer.Option('-cf', "--config", help=f'Temporarily adjust configuration settings for this run (see {CONFIG_FILE_LOCATION} for permanent changes).', rich_help_panel=f'[{COLORS["lightCyan"]} bold]nmapUnleashed Misc Options[/{COLORS["lightCyan"]} bold]', metavar="\"<configKey>:<value>;...\"")] = None,
        quiet: Annotated[bool, typer.Option('-qm', "--quiet-mode", help="Enable quiet mode (no banner or version info).", rich_help_panel=f'[{COLORS["lightCyan"]} bold]nmapUnleashed Misc Options[/{COLORS["lightCyan"]} bold]')] = False,
        silence: Annotated[bool, typer.Option('-sm', "--silence-mode", help="Enable silent mode (suppress all terminal output).", rich_help_panel=f'[{COLORS["lightCyan"]} bold]nmapUnleashed Misc Options[/{COLORS["lightCyan"]} bold]')] = False,
        version: Annotated[bool, typer.Option('-v', "--version", help="Display nmapUnleashed version.", rich_help_panel=f'[{COLORS["lightCyan"]} bold]nmapUnleashed Misc Options[/{COLORS["lightCyan"]} bold]')] = None,
        help: Annotated[bool, typer.Option('-h', "--help", help="Display this help message.", rich_help_panel=f'[{COLORS["lightCyan"]} bold]nmapUnleashed Misc Options[/{COLORS["lightCyan"]} bold]')] = None,


        #####NMAP Inheritance#####
        #Targets and files are processed by nmapUnleashed
        ##HOST DISCOVERY
        nmap_sL: Annotated[bool, typer.Option('-sL', help="List Scan - simply list targets to scan", rich_help_panel=f'[bold]Host Discovery[/bold] inherited from NMAP')] = None,
        nmap_sn: Annotated[bool, typer.Option('-sn', help="Ping Scan - disable port scan", rich_help_panel=f'[bold]Host Discovery[/bold] inherited from NMAP')] = None,
        nmap_Pn: Annotated[bool, typer.Option('-Pn', help="Treat all hosts as online -- skip host discovery", rich_help_panel=f'[bold]Host Discovery[/bold] inherited from NMAP')] = None,
        nmap_PS: Annotated[str, typer.Option('-PS', help="TCP SYN discovery to given ports", rich_help_panel=f'[bold]Host Discovery[/bold] inherited from NMAP', metavar="<portlist>")] = None,
        nmap_PA: Annotated[str, typer.Option('-PA', help="TCP ACK discovery to given ports", rich_help_panel=f'[bold]Host Discovery[/bold] inherited from NMAP', metavar="<portlist>")] = None,
        nmap_PU: Annotated[str, typer.Option('-PU', help="TCP UDP discovery to given ports", rich_help_panel=f'[bold]Host Discovery[/bold] inherited from NMAP', metavar="<portlist>")] = None,
        nmap_PY: Annotated[str, typer.Option('-PY', help="TCP SCTP discovery to given ports", rich_help_panel=f'[bold]Host Discovery[/bold] inherited from NMAP', metavar="<portlist>")] = None,
        nmap_PE: Annotated[bool, typer.Option('-PE', help="ICMP echo discovery probes", rich_help_panel=f'[bold]Host Discovery[/bold] inherited from NMAP')] = None,
        nmap_PP: Annotated[bool, typer.Option('-PP', help="Timestamp discovery probes", rich_help_panel=f'[bold]Host Discovery[/bold] inherited from NMAP')] = None,
        nmap_PM: Annotated[bool, typer.Option('-PM', help="Netmask request discovery probes", rich_help_panel=f'[bold]Host Discovery[/bold] inherited from NMAP')] = None,
        nmap_PO: Annotated[str, typer.Option('-PO', help="IP Protocol Ping", rich_help_panel=f'[bold]Host Discovery[/bold] inherited from NMAP', metavar="<protocol list>")] = None,
        nmap_n: Annotated[bool, typer.Option('-n', help="Never do DNS resolution; default: sometimes", rich_help_panel=f'[bold]Host Discovery[/bold] inherited from NMAP')] = None,
        nmap_R: Annotated[bool, typer.Option('-R', help="Always resolve; default: sometimes", rich_help_panel=f'[bold]Host Discovery[/bold] inherited from NMAP')] = None,
        nmap__dns_servers: Annotated[str, typer.Option('--dns-servers', help="Specify custom DNS servers", rich_help_panel=f'[bold]Host Discovery[/bold] inherited from NMAP', metavar="<serv1[,serv2],...>")] = None,
        nmap__system_dns: Annotated[bool, typer.Option('--system-dns', help="Use OS's DNS resolver", rich_help_panel=f'[bold]Host Discovery[/bold] inherited from NMAP')] = None,
        nmap__traceroute: Annotated[bool, typer.Option('--traceroute', help="Trace hop path to each host", rich_help_panel=f'[bold]Host Discovery[/bold] inherited from NMAP')] = None,
        ##SCAN TECHNIQUES
        nmap_sS: Annotated[bool, typer.Option('-sS', help="TCP SYN scans", rich_help_panel=f'[bold]Scan Techniques[/bold] inherited from NMAP')] = None,
        nmap_sT: Annotated[bool, typer.Option('-sT', help="TCP Connect() scans", rich_help_panel=f'[bold]Scan Techniques[/bold] inherited from NMAP')] = None,
        nmap_sA: Annotated[bool, typer.Option('-sA', help="TCP ACK scans", rich_help_panel=f'[bold]Scan Techniques[/bold] inherited from NMAP')] = None,
        nmap_sW: Annotated[bool, typer.Option('-sW', help="TCP Window scans", rich_help_panel=f'[bold]Scan Techniques[/bold] inherited from NMAP')] = None,
        nmap_sM: Annotated[bool, typer.Option('-sM', help="TCP Maimon scans", rich_help_panel=f'[bold]Scan Techniques[/bold] inherited from NMAP')] = None,
        nmap_sU: Annotated[bool, typer.Option('-sU', help="UDP scan", rich_help_panel=f'[bold]Scan Techniques[/bold] inherited from NMAP')] = None,
        nmap_sN: Annotated[bool, typer.Option('-sN', help="TCP Null scans", rich_help_panel=f'[bold]Scan Techniques[/bold] inherited from NMAP')] = None,
        nmap_sF: Annotated[bool, typer.Option('-sF', help="TCP FIN scans", rich_help_panel=f'[bold]Scan Techniques[/bold] inherited from NMAP')] = None,
        nmap_sX: Annotated[bool, typer.Option('-sX', help="TCP Xmas scans #\"lighting the packet up like a Christmas tree\" LOL", rich_help_panel=f'[bold]Scan Techniques[/bold] inherited from NMAP')] = None,
        nmap__scanflags: Annotated[str, typer.Option('--scanflags', help="Customize TCP scan flags", rich_help_panel=f'[bold]Scan Techniques[/bold] inherited from NMAP', metavar="<flags>")] = None,
        nmap_sI: Annotated[str, typer.Option('-sI', help="Idle scan", rich_help_panel=f'[bold]Scan Techniques[/bold] inherited from NMAP', metavar="<zombie host[:probeport]>")] = None,
        nmap_sY: Annotated[bool, typer.Option('-sY', help="SCTP INIT scans", rich_help_panel=f'[bold]Scan Techniques[/bold] inherited from NMAP')] = None,
        nmap_sZ: Annotated[bool, typer.Option('-sZ', help="SCTP COOKIE-ECHO scans", rich_help_panel=f'[bold]Scan Techniques[/bold] inherited from NMAP')] = None,
        nmap_sO: Annotated[bool, typer.Option('-sO', help="IP protocol scan", rich_help_panel=f'[bold]Scan Techniques[/bold] inherited from NMAP')] = None,
        nmap_b: Annotated[str, typer.Option('-b', help="FTP bounce scan", rich_help_panel=f'[bold]Scan Techniques[/bold] inherited from NMAP', metavar="<FTP relay host>")] = None,
        ##PORT SPECIFICATION AND SCAN ORDER
        nmap_p: Annotated[str, typer.Option('-p', help="Only scan specified ports. Ex: -p22; -p1-65535; -p U:53,111,137,T:21-25,80,139,8080,S:9", rich_help_panel=f'[bold]Port Specification and Scan Order[/bold] inherited from NMAP', metavar="<port ranges>")] = None,
        nmap__exclude_ports: Annotated[str, typer.Option('--exclude-ports', help="Exclude the specified ports from scanning", rich_help_panel=f'[bold]Port Specification and Scan Order[/bold] inherited from NMAP', metavar="<port ranges>")] = None,
        nmap_F: Annotated[bool, typer.Option('-F', help="Fast mode - Scan fewer ports than the default scan", rich_help_panel=f'[bold]Port Specification and Scan Order[/bold] inherited from NMAP')] = None,
        nmap_r: Annotated[bool, typer.Option('-r', help="Scan ports sequentially - don't randomize", rich_help_panel=f'[bold]Port Specification and Scan Order[/bold] inherited from NMAP')] = None,
        nmap__top_ports: Annotated[str, typer.Option('--top-ports', help="Scan <number> most common ports", rich_help_panel=f'[bold]Port Specification and Scan Order[/bold] inherited from NMAP', metavar="<number>")] = None,
        nmap__port_ratio: Annotated[str, typer.Option('--port-ratio', help="Scan ports more common than <ratio>", rich_help_panel=f'[bold]Port Specification and Scan Order[/bold] inherited from NMAP', metavar="<ratio>")] = None,
        ##SERVICE/VERSION DETECTION
        nmap_sV: Annotated[bool, typer.Option('-sV', help="Probe open ports to determine service/version info", rich_help_panel=f'[bold]Service/Version Detection[/bold] inherited from NMAP')] = None,
        nmap__version_intensity: Annotated[int, typer.Option('--version-intensity', help="Set from 0 (light) to 9 (try all probes)", rich_help_panel=f'[bold]Service/Version Detection[/bold] inherited from NMAP', metavar="<level>")] = None,
        nmap__version_light: Annotated[bool, typer.Option('--version-light', help="Limit to most likely probes (intensity 2)", rich_help_panel=f'[bold]Service/Version Detection[/bold] inherited from NMAP')] = None,
        nmap__version_all: Annotated[bool, typer.Option('--version-all', help="Try every single probe (intensity 9)", rich_help_panel=f'[bold]Service/Version Detection[/bold] inherited from NMAP')] = None,
        nmap__version_trace: Annotated[bool, typer.Option('--version-trace', help="Show detailed version scan activity (for debugging)", rich_help_panel=f'[bold]Service/Version Detection[/bold] inherited from NMAP')] = None,
        ##SCRIPT SCAN
        nmap_sC: Annotated[bool, typer.Option('-sC', help="equivalent to --script=default", rich_help_panel=f'[bold]Script Scan[/bold] inherited from NMAP')] = None,
        nmap__script: Annotated[str, typer.Option('--script', help="<Lua scripts> is a comma separated list of directories, script-files or script-categories", rich_help_panel=f'[bold]Script Scan[/bold] inherited from NMAP', metavar="<Lua scripts>")] = None,
        nmap__script_args: Annotated[str, typer.Option('--script-args', help="provide arguments to scripts", rich_help_panel=f'[bold]Script Scan[/bold] inherited from NMAP', metavar="<n1=v1,[n2=v2,...]>")] = None,
        nmap__script_args_file: Annotated[str, typer.Option('--script-args-file', help="provide NSE script args in a file", rich_help_panel=f'[bold]Script Scan[/bold] inherited from NMAP', metavar="<filename>")] = None,
        nmap__script_trace: Annotated[bool, typer.Option('--script-trace', help="Show all data sent and received", rich_help_panel=f'[bold]Script Scan[/bold] inherited from NMAP')] = None,
        nmap__script_updatedb: Annotated[bool, typer.Option('--script-updatedb', help="Update the script database.", rich_help_panel=f'[bold]Script Scan[/bold] inherited from NMAP')] = None,
        nmap__script_help: Annotated[str, typer.Option('--script-help', help="Show help about scripts. <Lua scripts> is a comma-separated list of script-files or script-categories.", rich_help_panel=f'[bold]Script Scan[/bold] inherited from NMAP', metavar="<Lua scripts>")] = None,
        ##OS DETECTION
        nmap_O: Annotated[bool, typer.Option('-O', help="Enable OS detection", rich_help_panel=f'[bold]OS Detection[/bold] inherited from NMAP')] = None,
        nmap__osscan_limit: Annotated[bool, typer.Option('--osscan-limit', help="Limit OS detection to promising targets", rich_help_panel=f'[bold]OS Detection[/bold] inherited from NMAP')] = None,
        nmap__osscan_guess: Annotated[bool, typer.Option('--osscan-guess', help="Guess OS more aggressively", rich_help_panel=f'[bold]OS Detection[/bold] inherited from NMAP')] = None,
        ##TIMING AND PERFORMANCE (<time> is in seconds, you can also add ms/s/m/h to specify units)
        nmap_T: Annotated[int, typer.Option('-T', help="Set timing template (higher is faster)", rich_help_panel=f'[bold]Timing and performance[/bold] inherited from NMAP (<time> is in seconds; ms/s/m/h to specify units)', metavar="<0-5>")] = None,
        nmap__min_hostgroup: Annotated[int, typer.Option('--min-hostgroup', help="Parallel host scan group sizes", rich_help_panel=f'[bold]Timing and performance[/bold] inherited from NMAP (<time> is in seconds; ms/s/m/h to specify units)', metavar="<size>")] = None,
        nmap__max_hostgroup: Annotated[int, typer.Option('--max-hostgroup', help="Parallel host scan group sizes", rich_help_panel=f'[bold]Timing and performance[/bold] inherited from NMAP (<time> is in seconds; ms/s/m/h to specify units)', metavar="<size>")] = None,
        nmap__min_parallelism: Annotated[int, typer.Option('--min-parallelism', help="Probe parallelization", rich_help_panel=f'[bold]Timing and performance[/bold] inherited from NMAP (<time> is in seconds; ms/s/m/h to specify units)', metavar="<numprobes>")] = None,
        nmap_max_parallelism: Annotated[int, typer.Option('--max-parallelism', help="Probe parallelization", rich_help_panel=f'[bold]Timing and performance[/bold] inherited from NMAP (<time> is in seconds; ms/s/m/h to specify units)', metavar="<numprobes>")] = None,
        nmap__min_rtt_timeout: Annotated[str, typer.Option('--min-rtt-timeout', help="Specifies probe round trip time.", rich_help_panel=f'[bold]Timing and performance[/bold] inherited from NMAP (<time> is in seconds; ms/s/m/h to specify units)', metavar="<time>")] = None,
        nmap__max_rtt_timeout: Annotated[str, typer.Option('--max-rtt-timeout', help="Specifies probe round trip time.", rich_help_panel=f'[bold]Timing and performance[/bold] inherited from NMAP (<time> is in seconds; ms/s/m/h to specify units)', metavar="<time>")] = None,
        nmap__initial_rtt_timeout: Annotated[str, typer.Option('--initial-rtt-timeout', help="Specifies probe round trip time.", rich_help_panel=f'[bold]Timing and performance[/bold] inherited from NMAP (<time> is in seconds; ms/s/m/h to specify units)', metavar="<time>")] = None,
        nmap__max_retries: Annotated[int, typer.Option('--max-retries', help="Caps number of port scan probe retransmissions.", rich_help_panel=f'[bold]Timing and performance[/bold] inherited from NMAP (<time> is in seconds; ms/s/m/h to specify units)', metavar="<tries>")] = None,
        nmap__host_timeout: Annotated[str, typer.Option('--host-timeout', help="Give up on target after this long", rich_help_panel=f'[bold]Timing and performance[/bold] inherited from NMAP (<time> is in seconds; ms/s/m/h to specify units)', metavar="<time>")] = None,
        nmap__scan_delay: Annotated[str, typer.Option('--scan-delay', help="Adjust delay between probes", rich_help_panel=f'[bold]Timing and performance[/bold] inherited from NMAP (<time> is in seconds; ms/s/m/h to specify units)', metavar="<time>")] = None,
        nmap__max_scan_delay: Annotated[str, typer.Option('--max-scan-delay', help="Adjust delay between probes", rich_help_panel=f'[bold]Timing and performance[/bold] inherited from NMAP (<time> is in seconds; ms/s/m/h to specify units)', metavar="<time>")] = None,
        nmap__min_rate: Annotated[int, typer.Option('--min-rate', help="Send packets no slower than <number> per second", rich_help_panel=f'[bold]Timing and performance[/bold] inherited from NMAP (<time> is in seconds; ms/s/m/h to specify units)', metavar="<number>")] = None,
        nmap__max_rate: Annotated[int, typer.Option('--max-rate', help="Send packets no slower than <number> per second", rich_help_panel=f'[bold]Timing and performance[/bold] inherited from NMAP (<time> is in seconds; ms/s/m/h to specify units)', metavar="<number>")] = None,
        ##FIREWALL/IDS EVASION AND SPOOFING
        nmap_f: Annotated[bool, typer.Option('-f', help="fragment packets (optionally w/given MTU)", rich_help_panel=f'[bold]Firewall/IDS Evasion and Spoofing[/bold] inherited from NMAP')] = None,
        nmap__mtu: Annotated[str, typer.Option('--mtu', help="optional setting for -f to set MTU", rich_help_panel=f'[bold]Firewall/IDS Evasion and Spoofing[/bold] inherited from NMAP', metavar="<val>")] = None,
        nmap_D: Annotated[str, typer.Option('-D', help="Cloak a scan with decoys", rich_help_panel=f'[bold]Firewall/IDS Evasion and Spoofing[/bold] inherited from NMAP', metavar="<decoy1,decoy2[,ME],...>")] = None,
        nmap_S: Annotated[str, typer.Option('-S', help="Spoof source address", rich_help_panel=f'[bold]Firewall/IDS Evasion and Spoofing[/bold] inherited from NMAP', metavar="<IP_Address>")] = None,
        nmap_e: Annotated[str, typer.Option('-e', help="Use specified interface", rich_help_panel=f'[bold]Firewall/IDS Evasion and Spoofing[/bold] inherited from NMAP', metavar="<iface>")] = None,
        nmap_g: Annotated[int, typer.Option('-g', help="Use given port number", rich_help_panel=f'[bold]Firewall/IDS Evasion and Spoofing[/bold] inherited from NMAP', metavar="<portnum>")] = None,
        nmap__source_port: Annotated[int, typer.Option('--source-port', help="Use given port number", rich_help_panel=f'[bold]Firewall/IDS Evasion and Spoofing[/bold] inherited from NMAP', metavar="<portnum>")] = None,
        nmap__proxies: Annotated[str, typer.Option('--proxies', help="Relay connections through HTTP/SOCKS4 proxies", rich_help_panel=f'[bold]Firewall/IDS Evasion and Spoofing[/bold] inherited from NMAP', metavar="<url1,[url2],...>")] = None,
        nmap__data: Annotated[str, typer.Option('--data', help="Append a custom payload to sent packets", rich_help_panel=f'[bold]Firewall/IDS Evasion and Spoofing[/bold] inherited from NMAP', metavar="<hex string>")] = None,
        nmap__data_string: Annotated[str, typer.Option('--data-string', help="Append a custom ASCII string to sent packets", rich_help_panel=f'[bold]Firewall/IDS Evasion and Spoofing[/bold] inherited from NMAP', metavar="<string>")] = None,
        nmap__data_length: Annotated[int, typer.Option('--data-length', help="Append random data to sent packets", rich_help_panel=f'[bold]Firewall/IDS Evasion and Spoofing[/bold] inherited from NMAP', metavar="<num>")] = None,
        nmap__ip_options: Annotated[str, typer.Option('--ip-options', help="Send packets with specified ip options", rich_help_panel=f'[bold]Firewall/IDS Evasion and Spoofing[/bold] inherited from NMAP', metavar="<options>")] = None,
        nmap__ttl: Annotated[str, typer.Option('--ttl', help="Set IP time-to-live field", rich_help_panel=f'[bold]Firewall/IDS Evasion and Spoofing[/bold] inherited from NMAP', metavar="<val>")] = None,
        nmap__spoof_mac: Annotated[str, typer.Option('--spoof-mac', help="Spoof your MAC address", rich_help_panel=f'[bold]Firewall/IDS Evasion and Spoofing[/bold] inherited from NMAP', metavar="<mac address/prefix/vendor name>")] = None,
        nmap__badsum: Annotated[bool, typer.Option('--badsum', help="Send packets with a bogus TCP/UDP/SCTP checksum", rich_help_panel=f'[bold]Firewall/IDS Evasion and Spoofing[/bold] inherited from NMAP')] = None,
        ##OUTPUT
        #output file types and name are managed by nmapUnleashed
        #-v is set by default to allow live data regarding open ports
        #nmap_v: Annotated[bool, typer.Option('-v', help="Increase verbosity level (use -vv or more for greater effect)", rich_help_panel=f'[bold]Output[/bold] inherited from NMAP')] = None,
        nmap_d: Annotated[bool, typer.Option('-d', help="Increase debugging level (use -dd or more for greater effect)", rich_help_panel=f'[bold]Output[/bold] inherited from NMAP')] = None,
        nmap__reason: Annotated[bool, typer.Option('--reason', help="Display the reason a port is in a particular state", rich_help_panel=f'[bold]Output[/bold] inherited from NMAP')] = None,
        nmap__open: Annotated[bool, typer.Option('--open', help="Only show open (or possibly open) ports", rich_help_panel=f'[bold]Output[/bold] inherited from NMAP')] = None,
        nmap__packet_trace: Annotated[bool, typer.Option('--packet-trace', help="Show all packets sent and received", rich_help_panel=f'[bold]Output[/bold] inherited from NMAP')] = None,
        nmap__iflist: Annotated[bool, typer.Option('--iflist', help="Print host interfaces and routes (for debugging)", rich_help_panel=f'[bold]Output[/bold] inherited from NMAP')] = None,
        nmap__append_output: Annotated[bool, typer.Option('--append-output', help="Append to rather than clobber specified output files", rich_help_panel=f'[bold]Output[/bold] inherited from NMAP')] = None,
        nmap__resume: Annotated[str, typer.Option('--resume', help="Resume an aborted scan", rich_help_panel=f'[bold]Output[/bold] inherited from NMAP', metavar="<filename>")] = None,
        nmap__noninteractive: Annotated[bool, typer.Option('--noninteractive', help="Disable runtime interactions via keyboard", rich_help_panel=f'[bold]Output[/bold] inherited from NMAP')] = None,
        nmap__stylesheet: Annotated[str, typer.Option('--stylesheet', help="XSL stylesheet to transform XML output to HTML", rich_help_panel=f'[bold]Output[/bold] inherited from NMAP', metavar="<path/URL>")] = None,
        nmap__webxml: Annotated[bool, typer.Option('--webxml', help="Reference stylesheet from Nmap.Org for more portable XML", rich_help_panel=f'[bold]Output[/bold] inherited from NMAP')] = None,
        nmap__no_stylesheet: Annotated[bool, typer.Option('--no-stylesheet', help="Prevent associating of XSL stylesheet w/XML output", rich_help_panel=f'[bold]Output[/bold] inherited from NMAP')] = None,
        ##MISC
        nmap_6: Annotated[bool, typer.Option('-6', help="Enable IPv6 scanning", rich_help_panel=f'[bold]Misc[/bold] inherited from NMAP')] = None,
        nmap_A: Annotated[bool, typer.Option('-A', help="Enable OS detection, version detection, script scanning, and traceroute", rich_help_panel=f'[bold]Misc[/bold] inherited from NMAP')] = None,
        nmap__datadir: Annotated[str, typer.Option('--datadir', help="Specify custom Nmap data file location", rich_help_panel=f'[bold]Misc[/bold] inherited from NMAP', metavar="<dirname>")] = None,
        nmap__send_eth: Annotated[bool, typer.Option('--send-eth', help="Send using raw ethernet frames", rich_help_panel=f'[bold]Misc[/bold] inherited from NMAP')] = None,
        nmap__send_ip: Annotated[bool, typer.Option('--send-ip', help="Send using raw IP packets", rich_help_panel=f'[bold]Misc[/bold] inherited from NMAP')] = None,
        nmap__privileged: Annotated[bool, typer.Option('--privileged', help="Assume that the user is fully privileged", rich_help_panel=f'[bold]Misc[/bold] inherited from NMAP')] = None,
        nmap__unprivileged: Annotated[bool, typer.Option('--unprivileged', help="Assume the user lacks raw socket privileges", rich_help_panel=f'[bold]Misc[/bold] inherited from NMAP')] = None,
        nmap_V: Annotated[bool, typer.Option('-V', help="Print version number", rich_help_panel=f'[bold]Misc[/bold] inherited from NMAP')] = None,

):

    # Kinda weird but necessary because of recovery mode
    _COLORS = COLORS
    _META = META

    #Print Help Message if called or no args and options are set
    if help or (not ctx.args and all(ctx.get_parameter_source(parameter).name == "DEFAULT" for parameter, value in ctx.params.items() if parameter != "targets") and not ctx.params["targets"]):
        rich_print(_META["BANNER"], "\n")
        ctx.get_help()
        rich_print(EXAMPLES)
        raise typer.Exit(code=0)

    #Print version and last update date
    if version:
        rich_print(_META["BANNER"], "\n")
        typer.echo(f'Version {_META["VERSION"]} - {_META["LASTUPDATE"]}')
        raise typer.Exit(code=0)

    # Adjust output pattern
    CONFIG["configuration"]["OUTPUT_PATTERN"] = outputPattern
    # Adjust no folder per scan config
    CONFIG["configuration"]["NO_FOLDER_PER_SCAN"] = noFolderPerScan
    # Adjust config for scan file removal after completion
    if removeFiles:
        CONFIG["configuration"]["REMOVE_FILES"] = removeFiles
    # Adjust config for if offline scan files should be kept or not
    CONFIG["configuration"]["KEEP_OFFLINE_FILES"] = keepOfflineFiles
    # Adjust config if dashboard.txt should be created or not
    CONFIG["configuration"]["NO_DASHBOARD_FILE"] = noDashboardFile
    # Adjust config if scans.xml and scans.html should be created or not
    CONFIG["configuration"]["NO_SCANS_FILE"] = noScansFile
    # Adjust config if only scans.xml and scans.html should be created and no individual scan files
    CONFIG["configuration"]["ONLY_SCANS_FILE"] = onlyScansFile
    # Adjust config if nmap's original color scheme should be used for the scans.html
    CONFIG["configuration"]["ORIGINAL_COLORS"] = originalColors
    # Adjust config for static dashboard size
    if fixedDashboardSize:
        CONFIG["configuration"]["DYNAMIC_DASHBOARD_SIZE"] = False
    # Set network warning configurations if options were set
    if networkWarningReceive > 0:
        CONFIG["configuration"]["NETWORK_WARNING_RECEIVE"] = networkWarningReceive
    if networkWarningTransmit > 0:
        CONFIG["configuration"]["NETWORK_WARNING_TRANSMIT"] = networkWarningTransmit

    # Process parameter set. Merge with current parameter
    # If parameter from set does not exist in curren it is just added
    # If both exist and if it is a single value option, current overrides set. Except current comes from default value, then set is taken
    # if both exists and if it is a multi value option, they are merged. Except current comes from default value, then only set is taken
    #
    if parameterSet != None:
        # Split args and use temporary app of cli to leverage parser and get the proper options
        args = shlex.split(CONFIG["parameterSets"][parameterSet])
        appTmp = typer.Typer()
        appTmp.command()(main)
        cmdTmp = typer.main.get_command(appTmp)
        ctxTmp = cmdTmp.make_context("main", args)
        parameterSet = ctxTmp.params
        # Merge parameters / options
        parameter = ctx.params
        #Add parameter from cli to merged
        mergedParams = copy.deepcopy(parameter)
        #Iter over parameter from option
        for key, value in parameterSet.items():
            #If parameter from option was not set, skip it
            if not value:
                continue
            #If parameter from option not in cli, then just add it
            if not mergedParams[key]:
                mergedParams[key] = value
            #If the parameter from option already exists in cli
            if mergedParams[key]:
                # If multiple option merge the parameter of option and cli
                if type(value) == tuple or type(mergedParams[key]) == tuple:
                    # If the cli parameter is a default value and was not excplicitly set, override it
                    default = True if str(ctx.get_parameter_source(key)) == "ParameterSource.DEFAULT" else False
                    # Override
                    if default:
                        mergedParams[key] = tuple(value)
                    #Merge
                    else:
                        #Merges the two independed, if any ore both or so are str or list. Results in list
                        mergedParams[key] = list(mergedParams[key]) + list(value)
                        #Make it unique list
                        mergedParams[key] = list(set(mergedParams[key]))
                        #Convert back to tuple
                        mergedParams[key] = tuple(mergedParams[key])
                # If single option it gets overridden by cli option, meaning it is skipped
                else:
                    #If the cli parameter is a default value and was not excplicitly set, override it
                    default = True if str(ctx.get_parameter_source(key)) == "ParameterSource.DEFAULT" else False
                    if default:
                        mergedParams[key] = value
                    else:
                        continue
        # Override current ctx.params with merged
        ctx.params = mergedParams

    #Process inherited NMAP options
    nmapParameter = ""
    for key, value in ctx.params.items():
        #onky process the one with prefix "nmap"
        if not key.startswith("nmap"): continue
        #Only process if option is set
        if value:
            #If bool option only set key, if option with value than add option and its value, also restore key name (replace _ with -)
            nmapParameter += (" " if nmapParameter != "" else "")+(key.split("nmap")[1].replace("_","-") if value == True else f'{key.split("nmap")[1].replace("_","-")} {value}')

    #Prepare and load targets
    if not targets:
        raise typer.BadParameter("No targets specified")
    #REMOVED RECOVER FEATURE: if not recover:
    try:
        targets, parameterOfTargets = prepareTargets(targets=targets)
    except Exception as e:
        raise typer.BadParameter("targets")
    #If option was set, exclude defined targets
    if exclude:
        try:
            targetsExcluded, parameterOfTargetsExclude = prepareTargets(targets=exclude)
            for target in targetsExcluded:
                if target in targets: targets.remove(target)
        except Exception as e:
            raise typer.BadParameter("--exclude")

    # Adjust config if option was used
    if config and CONFIG:
        # Expand config
        expanded = []
        for entry in config:
            expanded += entry.split(";")
        config = expanded
        ctx.params["config"] = expanded
        # Load config
        for conf in config:
            key = conf.split("=")[0]
            value = conf.split("=")[1]
            # Check if class variable exist
            if key not in [classVarKey for classVarKey, classVarValue in vars(Scheduler).items() if
                           not classVarKey.startswith("__") and not callable(classVarValue)]:
                raise typer.BadParameter(f'--config: Unknown configuration key "{key}"')
            else:
                CONFIG["configuration"][key] = autoCast(value)
        # Not sure if necessary, just in case
        ctx.params["config"] = config



    #Run scheduler aka start scanning
    try:
        #If targets is smaller than threads reduce it, makes the dashboard prettier
        #if len(targets) < threads: threads = len(targets) ##why did i comment this out? Seems fine commented out
        # Suppress printing of pressed keys to term while preserving "ctrl+c" functionality
        rawMode = RawMode()
        rawMode.__enter__()
        try:
            #Initialize scheduler
            scheduler = Scheduler(rawMode=rawMode, meta=_META, colors=_COLORS, config=CONFIG, targets=targets, parameterOfTargets=parameterOfTargets, threads=threads, parameter=nmapParameter, options=ctx.params)
            #Run scheduler aka start the scans and threads
            scheduler.execute()
        except Exception as e:
            rawMode.__exit__()
            raise e
        rawMode.__exit__()

    except Exception as e:
        raise Exception(f'An error occured:\n{e}')


#Suppress printing of pressed keys to term while preserving "ctrl+c" functionality
class RawMode:
    def __enter__(self):
        self.fd = sys.stdin.fileno()
        self.old = termios.tcgetattr(self.fd)
        tty.setcbreak(self.fd)  # or tty.setraw(self.fd) if you want full raw mode
        return self

    def __exit__(self, *args):
        termios.tcsetattr(self.fd, termios.TCSADRAIN, self.old)

# Try to autocast var
def autoCast(value):
    if value.lower() in ["false", "true"]:
        return bool(value)
    try:
        return int(value)
    except:
        pass
    try:
        return float(value)
    except:
        pass
    return str(value)





###Backend/Dashboard
########################################################################################################################
########################################################################################################################
########################################################################################################################





#Prepare passed targets.
##This function processes passed targets to extract single IPs (ipv4 and ipv6), networks in CIDR notation, hostnames / domains and files with targets.
##It than creates one single list with all IPs and DNS names that result from the passed targets.
##First IPs and Networks are extracted. The rest is checked if a file with this name exists, if not it is assumed that it is a dns name (domain, hostname etc).
def prepareTargets(targets: list):
    ###Pattern###
    pattern_ipv4 = r'^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.' \
                   r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.' \
                   r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.' \
                   r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    pattern_ipv6 = r'^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|' \
                   r'^(?:[0-9a-fA-F]{1,4}:){1,7}:|' \
                   r'^(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|' \
                   r'^(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|' \
                   r'^(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|' \
                   r'^(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|' \
                   r'^(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|' \
                   r'^[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}|' \
                   r'^:((:[0-9a-fA-F]{1,4}){1,7}|:)|' \
                   r'^(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}$'
    pattern_ipv4_cidr = r'^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.' \
                        r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.' \
                        r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.' \
                        r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/([0-9]|[1-2][0-9]|3[0-2])$'
    pattern_ipv6_cidr = r'^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\/([0-9]|[1-1][0-9]|12[0-8])|' \
                        r'^(?:[0-9a-fA-F]{1,4}:){1,7}:\/([0-9]|[1-1][0-9]|12[0-8])|' \
                        r'^(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\/([0-9]|[1-1][0-9]|12[0-8])|' \
                        r'^(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}\/([0-9]|[1-1][0-9]|12[0-8])|' \
                        r'^(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}\/([0-9]|[1-1][0-9]|12[0-8])|' \
                        r'^(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}\/([0-9]|[1-1][0-9]|12[0-8])|' \
                        r'^(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}\/([0-9]|[1-1][0-9]|12[0-8])|' \
                        r'^[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}\/([0-9]|[1-1][0-9]|12[0-8])|' \
                        r'^:((:[0-9a-fA-F]{1,4}){1,7}|:)(\/([0-9]|[1-1][0-9]|12[0-8]))|' \
                        r'^(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\/([0-9]|[1-1][0-9]|12[0-8])$'
    #############
    parsedTargets = []
    targetsIPv4CIDR = []
    targetsIPv6CIDR = []
    targetsDNS = []
    targetsFiles = []
    targetsDnsFilesJunk = []
    parameterOfTargets = {}
    #Sort targets by IP, Network and File
    for target in targets:
        #Check if individual parameter was passed
        parameter = None
        if "=" in target:
            parameterOfTargets[target.split("=", 1)[0]] = target.split("=", 1)[1]
            target = target.split("=", 1)[0]
        #The order of the ifs matters!
        # IPv4 networks are sorted out for further processing
        if re.match(pattern_ipv4_cidr, target) is not None: targetsIPv4CIDR.append(target)
        # IPv6 networks are sorted out for further processing
        elif re.match(pattern_ipv6_cidr, target) is not None: targetsIPv6CIDR.append(target)
        #IPv4 and IPv6 addresses can go directly into parsedTargets
        elif re.match(pattern_ipv4, target) is not None or re.match(pattern_ipv6, target) is not None: parsedTargets.append(target)
        #The rest must be DNS names, files or junk
        else: targetsDnsFilesJunk.append(target)
    #Load the IPs and Networks from the targetsFiles
    for target in targetsDnsFilesJunk:
        #If target is not a file it is assumed its a DNS name
        if not os.path.isfile(target):
            targetsDNS.append(target)
            continue
        #if target was file make sure no individual parameter exists, even tho this should not happen
        if target in parameterOfTargets.keys(): parameterOfTargets.pop(target)
        #Load targets from file, one per line
        targetsFromFile = []
        with open(target, 'r') as targetFile:
            #Remove line breaks and empty lines
            targetsFromFile = [t.replace('\n','') for t in targetFile.readlines() if t != '' and t != '\n']
        # Sort targetsFromFile by IP and Network, aswell as DNS names
        for t in targetsFromFile:
            # Check if individual parameter was passed
            parameter = None
            if "=" in t:
                parameterOfTargets[t.split("=", 1)[0]] = t.split("=", 1)[1]
                t = t.split("=", 1)[0]
            # The order of the ifs matters!
            # IPv4 networks are sorted out for further processing
            if re.match(pattern_ipv4_cidr, t) is not None: targetsIPv4CIDR.append(t)
            # IPv6 networks are sorted out for further processing
            elif re.match(pattern_ipv6_cidr, t) is not None: targetsIPv6CIDR.append(t)
            # IPv4 and IPv6 addresses can go directly into parsedTargets
            elif re.match(pattern_ipv4, t) is not None or re.match(pattern_ipv6, t) is not None: parsedTargets.append(t)
            # The rest must be DNS names
            else: targetsDNS.append(t)
    # Add the DNS names to parsedTargets
    parsedTargets += targetsDNS
    #Resolve each IPv4 network to all relating IPv4 IPs
    for target in targetsIPv4CIDR:
        #This resolves the network to its IPs and exludes the broadcast and network IP (.0 and .255)
        ##The list converts the IP generator object / iterator to a list of strings
        ips = [str(ip) for ip in ipaddress.ip_network(target, strict=False).hosts()]
        #Add the resolved IPs to parsedTargets
        parsedTargets += ips
        #If for the net an individual parameter was set, set for all ips of net
        if target in parameterOfTargets.keys():
            #Remove net
            parameter = parameterOfTargets.pop(target)
            #Set parameter for ips of net
            for ip in ips:
                parameterOfTargets[ip] = parameter
    #Resolve each IPv6 network to all relating IPv6 IPs
    for target in targetsIPv6CIDR:
        #This resolves the network to its usable IPs
        ##The list converts the IP generator object / iterator to a list of strings
        ips = [str(ip) for ip in ipaddress.IPv6Network(target, strict=False).hosts()]
        #Add the resolved IPs to parsedTargets
        parsedTargets += ips
        # If for the net an individual parameter was set, set for all ips of net
        if target in parameterOfTargets.keys():
            # Remove net
            parameter = parameterOfTargets.pop(target)
            # Set parameter for ips of net
            for ip in ips:
                parameterOfTargets[ip] = parameter
    #remove dupes
    parsedTargets = list(set(parsedTargets))
    #sort
    parsedTargets.sort()
    return parsedTargets, parameterOfTargets


class Scheduler():

    ##########CONFIG##########
    NETWORK_WARNING_RECEIVE = 0 #default: 0, At what KBps to warn about receiving to much network traffic. 0 means disabled.
    NETWORK_WARNING_TRANSMIT = 0 #default: 0, At what KBps to warn about transmitting to much network traffic. 0 means disabled.
    OUTPUT_PATTERN = "{target}" #default: "{target}", parameter is also available i.e. "{target}_{parameter}". {target} is mandatory
    REMOVE_FILES = "" #default: "", which scan files to remove after completion i.e. "xml" or "xml;gnmap"
    NO_FOLDER_PER_SCAN = False #default: True, if a folder should be created for each scan
    KEEP_OFFLINE_FILES = False #default False, if scan files where host was offline should not be removed
    NO_DASHBOARD_FILE = False #default false, if the dashboard.txt file should be created or not
    REFRESH_RATE = 0.2  # default: 0.2 seconds, refreshrate of dashboard
    REFRESH_RATE_FOR_WORKER = 0.05 # default: 0.05 seconds, wait x seconds for next check if workers finished
    REFRESH_RATE_FOR_FINAL_THREAT_WAIT = 0.05 # default: 0.05 seconds, wait x seconds for next check if all threads have finished
    REFRESH_NMAP_STATS = 1 # default: 1 seconds, passed to nmap via "--stats-every" to controll how often stats are outputted
    DATETIME_STR_FORMAT = "%Y-%m-%d | %H:%M:%S" # default: "%Y-%m-%d | %H:%M:%S", datetime format for dashboard, i.e. start and stop time
    DASHBOARD_MAX_SIZE_THREADS = 10 # default: 10, how many rows max for active threads
    DASHBOARD_MAX_SIZE_DONE = 4 # default: 4, how many rows max for finished scans
    DASHBOARD_MAX_SIZE = DASHBOARD_MAX_SIZE_THREADS + DASHBOARD_MAX_SIZE_DONE #max size of dashboard regarding scans, before it switches to scroll mode
    NETWORK_MAX_SIZE = 4 # default: 4, max size of network dashboard section, before it switches to scroll mode
    DASHBOARD_SCROLL_SPEED_MODIFIER = 1 # default: 1, factor (REFRESH_RATE * DASHBOARD_MAX_SIZE * DASHBOAD_SCROLL_SPEED_MODIFIER)
    DYNAMIC_DASHBOARD_SIZE = True # default: false, Regulates weather to adjust the dashboard size dynamically.
    SCAN_KILL_PENDING_WAIT = 3 # default: 3, seconds, how long a kill of scan is pending for confirmation before reset
    SCAN_KILL_PENDING_REFRESH = 1 # default: 1, seconds, how long to wait for next check if a kill is pending
    FEATURE_LOADER_PARALLEL_REFRESHRATE = 0.2 # default: 0.2, seconds, how long to wait before parallel features are executed again
    RECOVERY_FILE = ".nmapUnleashed.recover" # default: ".nmapUnleashed.recover", File tracking passed args, options and targets to help recovery
    TRACK_STATE_FILE = ".nmapUnleashed.stateTrack" # default: ".nmapUnleashed.stateTrack", File tracking scan state to help recovery
    TRACK_TARGET_STATE_REFRESHRATE = 1 # default: 1, seconds, how often the target states are saved to disk
    MERGED_SCAN_FILE = "scans" # default: "scans", filename for merged scans as xml and html
    NO_SCANS_FILE = False # default: false, if scans.xml and scans.html should not be created
    ONLY_SCANS_FILE = False # default: false, if only scans.xml and scans.html should be created and no individual scan files
    ORIGINAL_COLORS = False # default: false, if nmap's original color scheme should be used for scans.html or not
    ##########################

    def __init__(self, rawMode, meta: dict, colors: dict, config, targets: list, parameterOfTargets: dict, threads: int, parameter: str, options):
        # Var for parameterSets loaded from config, if config was loaded it gets filled
        self.parameterSets = None
        # Load config
        self.loadConfig(config)
        ##Initialize Instanz Vars
        self.targets = targets
        self.parameterOfTargets = parameterOfTargets
        self.threads = threads
        self.parameter = parameter
        self.options = options
        self.threadListInfo = None
        self.targetsTotal = len(self.targets)
        self.targetsCompleted = 0
        self.TARGETS = copy.deepcopy(self.targets) #list of targets that remains constant, now pop action or similar
        #Create thread-safe queue for data sharing
        self.data_queue = queue.Queue()
        #Track when display was last refreshed
        self.last_refresh = 0
        #Track when dashboard was last scrolled
        self.last_scroll_main_threads = 0
        self.last_scroll_main_done = 0
        self.last_scroll_network = 0
        self.last_scroll_detailed_view = 0
        #Track if dashboard was initalized
        self.dashboardInitialized = False
        #Track start time
        self.timeStart = None
        #Track active threads
        self.threadsActive = 0
        #Track bandwith usage
        self.networkStartData = psutil.net_io_counters(pernic=True)
        self.networkStartTime = time.time()
        self.networkLastData = self.networkStartData
        self.networkLastTime = self.networkStartTime
        self.networkMaxRX = {interface: 0 for interface in self.networkStartData}
        self.networkMaxTX = {interface: 0 for interface in self.networkStartData}
        #Track window of targets and network interfaces if to many to display
        self.windowMainThreads = 0
        self.windowMainThreadsBuffer = 0
        self.windowMainDone = 0
        self.windowMainDoneBuffer = 0
        self.windowNetworks = 0
        self.windowDetailedView = 0
        self.windowDetailedViewBuffer = 0
        #Store target stats. Current evaluated thread data and finished ones. (For now also the thread data) and not started ones
        self.targetsStats = [{"targetID": i, "target": self.targets[i], "done": False, "status": "inactive", "filename": self.createFilename(self.targets[i])} for i in range(len(self.targets))]
        #Dashboard live changes
        self.dashboardLive = None
        ##CONSTANTS
        self.DASHBOARD = True
        self.META = meta #This is defined in the frontend section
        self.COLORS = colors #This is defined in the frontend section
        self.rawMode = rawMode
        ##Initialize rich Console for Dashboard
        self.console = Console()
        #State of interactive dashboard
        self.dashboardInteractionState = {"selectedTarget": 0,
                                          "enter": False,
                                          "quit": False,
                                          "view": 0,
                                          "killPending": False,
                                          "killExecute": False}
        #Holds the processes of the nmap scans
        self.scanProcesses = {}
        #Track last target state tracking refresh
        self.lastTargetStateTrack = 0


    #Schedules scans, manages threads and distributes targets to threads
    def execute(self):
        #Set start time
        self.timeStart = datetime.datetime.now()
        #The list of threads to be run
        threadList = [None for _ in range(self.threads)]
        #Holds information which thread has which target
        self.threadListInfo = [None for _ in range(self.threads)]
        #Track which thread is currently looked at
        currentThread = -1
        #Create target ID to identify scan
        targetID = 0
        # Pre Feature loader
        self.featureLoaderPre()
        #Start keystroke listener
        keystrokeListener = threading.Thread(target=self.keyboardListener, daemon=True)
        keystrokeListener.start()
        #Start pending kill reseter
        pendingReseter = threading.Thread(target=self.pendingReseter, daemon=True)
        pendingReseter.start()
        # Start parallel feature loader, executes integrated features regulary parallel to main thread
        featureLoaderParallel = threading.Thread(target=self.featureLoaderParallel, daemon=True)
        featureLoaderParallel.start()
        while self.targets:
            #Go to next thread, if max number is reached, start at the beginning
            currentThread = (currentThread + 1) % self.threads
            # If thread is done join, not sure if necessary here
            if threadList[currentThread] is not None and not threadList[currentThread].is_alive(): threadList[currentThread].join()
            #Check if thread finished (or is not started), so needs new work
            if threadList[currentThread] is None or not threadList[currentThread].is_alive():
                target = self.targets.pop(0)
                #Load filename for scan
                fileName = self.targetsStats[targetID]["filename"]
                #Prepare new thread
                threadList[currentThread] = threading.Thread(target=self.scan, args=(target, self.parameter if not target in self.parameterOfTargets else self.parameterOfTargets[target], currentThread, targetID, fileName), name=currentThread, daemon=True)
                # Start new thread
                threadList[currentThread].start()
                #Update target stats
                self.threadListInfo[currentThread] = targetID
                self.targetsStats[targetID]["threadInfo"] = {
                                                    "threadID": currentThread,
                                                    "pid": threadList[currentThread].native_id,
                                                    "timeStart": datetime.datetime.now(),
                                                    "timeStop": None,
                                                    "parameter": self.parameter if not target in self.parameterOfTargets else self.parameterOfTargets[target],
                                                    "fileName": fileName}
                self.targetsStats[targetID]["data"] = ""
                self.targetsStats[targetID]["status"] = "active"
                #Increment targetID
                targetID += 1
                #Increment active threads
                self.threadsActive += 1
            #Update realtime data of threads
            self.updateThreadInfoWithRealtimeDataFromThreads()
            #Display and update dashboard
            self.displayAndUpdateDashboard()
#####

        '''#Wait for all threads to finish
        while any(t is None or t.is_alive() for t in threadList):
            # Update realtime data of threads
            self.updateThreadInfoWithRealtimeDataFromThreads()
            # Display and update dashboard
            self.displayAndUpdateDashboard()'''
        # Proper way to wait for all threads to finish
        for t in threadList:
            if t is not None:
                while t.is_alive():
                    # Update realtime data of threads
                    self.updateThreadInfoWithRealtimeDataFromThreads()
                    # Display and update dashboard
                    self.displayAndUpdateDashboard()
                    time.sleep(Scheduler.REFRESH_RATE_FOR_FINAL_THREAT_WAIT)
                t.join()

#####
        #Empty queue. This makes sure all latest data is shown, even though all threads already finished
        while not self.data_queue.empty():
            self.updateThreadInfoWithRealtimeDataFromThreads()

        #Wait for at least the refresh rate, so all latest data is shown, otherwise it might not be displayed as the last refresh is to close by
        time.sleep(Scheduler.REFRESH_RATE)
        #Refresh dashboard for the last time
        self.displayAndUpdateDashboard(last=True)

        # Moved this into self.displayAndUpdateDashboard(last=True)
        '''#If dashboard is enabled close it
        if self.DASHBOARD:
            self.dashboardLive.refresh()
            self.dashboardLive.stop()'''
        #execute post features
        self.featureLoaderPost()
        #Cleanup
        self.cleanup()

    #Update thread info with realtime data from threads
    def updateThreadInfoWithRealtimeDataFromThreads(self):
        # Receive thread data to update thread status and information
        if not self.data_queue.empty():
            # Receive data from any thread
            dataFromThread = self.data_queue.get(timeout=0.1)
            # Update realtime data of relating thread
            self.targetsStats[dataFromThread["targetID"]]["data"] += dataFromThread["data"]
            #if "nmap done:" in dataFromThread["data"].lower(): self.threadListInfo[dataFromThread["threadID"]]["status"] = "completed"

    #Here the dashboard is displayed
    def displayAndUpdateDashboard(self, last=False):
        #If dashboard is disabled skip this function
        if not self.DASHBOARD: return
        #Check if dashboard is initalized, if not do so
        if not self.dashboardInitialized and not self.options["silence"]:
            self.dashboardInitialized = True
            #Initialize lidisplayve view for dashboard
            self.dashboardLive = Live("", refresh_per_second=1/Scheduler.REFRESH_RATE) #why was here Scheduler.REFRESH_RATE/2 wrong?
            self.dashboardLive.start()
        #Get current time
        currentTime = time.time()
        #Check if dashboard should be refreshed based on refresh rate
        if currentTime - self.last_refresh >= Scheduler.REFRESH_RATE:
            #Track last refresh
            self.last_refresh = currentTime
            #Create / update dashboard
            dashboardScrolled, dashboardComplete = self.buildAndUpdateDashboard(last=last)
            #Update dashboard
            #if self.dashboardInteractionState["view"] == 0:
            #    #Default dashboard view
            if not self.options["silence"]:
                self.dashboardLive.update(dashboardScrolled)
            #elif self.dashboardInteractionState["view"] == 1:
            #    #Detailed view of selected scan
            #    self.dashboardLive.update(self.buildDetailedViewOfScan())
            #Save dashboard to file
            if not Scheduler.NO_DASHBOARD_FILE:
                with open("dashboard.txt", "w") as dashboardFile:
                    console = Console(file=dashboardFile, force_terminal=True, height=25+(self.targetsTotal+len(self.networkStartData)))
                    console.print(dashboardComplete)
            # If last output whole dashboard
            if last and not self.options["silence"]:
                self.dashboardLive.update("", refresh=True) # refresh forces last refresh independent of refresh cycle
                # Kill dashboard here, then final print
                self.dashboardLive.stop()
                Console(force_terminal=True, height=25+(self.targetsTotal+len(self.networkStartData))).print(dashboardComplete)

    #Build and update dashboard
    def buildAndUpdateDashboard(self, scroll=True, last=False):
        #Create layout from rich to put multiple tables (dashboards) into one
        dashboardComplete = Layout()
        dashboardScrolled = Layout()
        #Try to load portCount for view=1 if dynamic is on
        portCount = 0
        try:

            if not self.targetsStats[self.dashboardInteractionState["selectedTarget"]]["done"]:
                portCount = len(self.getOpenPortsLive(self.dashboardInteractionState["selectedTarget"]))
            else:
                portCount = len(self.getPortsAndServices(self.dashboardInteractionState["selectedTarget"]))
        except:
            pass
        #Add dashboards layout, adjust size dynamically
        if not last:
            dashboardComplete.split_column(Layout(name="banner",size=(10  if not self.options["quiet"] else 1)),Layout(name="command", size=2),Layout(name="navigator", size=2) ,Layout(name="dashboardMain", size=self.targetsTotal + 5), Layout(name="dashboardNetwork", size=len(self.networkStartData) + 6), Layout(name="stats", size=2), Layout(name="progressbar"))
            dashboardScrolled.split_column(Layout(name="banner",size=(10  if not self.options["quiet"] else 1)),Layout(name="command", size=2),Layout(name="navigator", size=2) , Layout(name="dashboardMain", size=(self.targetsTotal if (self.targetsTotal < Scheduler.DASHBOARD_MAX_SIZE and not self.dashboardInteractionState["view"] == 1) and Scheduler.DYNAMIC_DASHBOARD_SIZE else portCount if self.dashboardInteractionState["view"] == 1 and portCount < Scheduler.DASHBOARD_MAX_SIZE and Scheduler.DYNAMIC_DASHBOARD_SIZE else Scheduler.DASHBOARD_MAX_SIZE) + 5 + (1 if self.targetsTotal > Scheduler.DASHBOARD_MAX_SIZE_THREADS else 0)), Layout(name="dashboardNetwork", size=(len(self.networkStartData) if len(self.networkStartData) < Scheduler.NETWORK_MAX_SIZE and Scheduler.DYNAMIC_DASHBOARD_SIZE else Scheduler.NETWORK_MAX_SIZE)+6), Layout(name="stats", size=2), Layout(name="progressbar"))
        else:
            dashboardComplete.split_column(Layout(name="banner",size=(10  if not self.options["quiet"] else 1)),Layout(name="command", size=2), Layout(name="dashboardMain", size=self.targetsTotal + 5), Layout(name="dashboardNetwork", size=len(self.networkStartData) + 6), Layout(name="stats", size=2), Layout(name="progressbar"))
            dashboardScrolled.split_column(Layout(name="banner",size=(10  if not self.options["quiet"] else 1)),Layout(name="command", size=2), Layout(name="dashboardMain", size=(self.targetsTotal if (self.targetsTotal < Scheduler.DASHBOARD_MAX_SIZE and not self.dashboardInteractionState["view"] == 1) and Scheduler.DYNAMIC_DASHBOARD_SIZE else portCount if self.dashboardInteractionState["view"] == 1 and portCount < Scheduler.DASHBOARD_MAX_SIZE and Scheduler.DYNAMIC_DASHBOARD_SIZE else Scheduler.DASHBOARD_MAX_SIZE) + 5 + (1 if self.targetsTotal > Scheduler.DASHBOARD_MAX_SIZE_THREADS else 0)), Layout(name="dashboardNetwork", size=(len(self.networkStartData) if len(self.networkStartData) < Scheduler.NETWORK_MAX_SIZE and Scheduler.DYNAMIC_DASHBOARD_SIZE else Scheduler.NETWORK_MAX_SIZE)+6), Layout(name="stats", size=2), Layout(name="progressbar"))

        #dashboard.split_column(Layout(Panel("banner",title="banner"),size=9),Layout(Panel("dashboardMain"), size=self.threads+5), Layout(Panel("dashboardNetwork")))
        #Create layout of main dashboard for scans
        dashboardMainTable = Table()
        dashboardMainTable.add_column("TargetID")
        #dashboardMainTable.add_column("ThreadID")
        #dashboardMainTable.add_column("Pid")
        dashboardMainTable.add_column("Target")
        dashboardMainTable.add_column("TargetState")
        dashboardMainTable.add_column("Status")
        dashboardMainTable.add_column("Progress")
        dashboardMainTable.add_column("Runtime")
        dashboardMainTable.add_column("ETE")
        dashboardMainTable.add_column("Start")
        dashboardMainTable.add_column("Stop")
        dashboardMainTable.add_column("Open Ports")
        if self.parameterOfTargets: dashboardMainTable.add_column("Parameter")
        #Create layout of dashboard for network / bandwith usage
        dashboardNetworkTable = Table()
        dashboardNetworkTable.add_column("Interface\n", justify="center")
        dashboardNetworkTable.add_column("RX\n[KBps]", justify="center")
        dashboardNetworkTable.add_column("TX\n[KBps]", justify="center")
        dashboardNetworkTable.add_column("RX-Max\n[KBps]", justify="center")
        dashboardNetworkTable.add_column("TX-Max\n[KBps]", justify="center")
        dashboardNetworkTable.add_column("RX-Total\n[KB]", justify="center")
        dashboardNetworkTable.add_column("TX-Total\n[KB]", justify="center")
        #Create layout for detailed view
        dashboardDetailedViewTable = Table()
        dashboardDetailedViewTable.add_column("Port\n", justify="center")
        dashboardDetailedViewTable.add_column("Protocol\n", justify="center")
        dashboardDetailedViewTable.add_column("State\n", justify="center")
        dashboardDetailedViewTable.add_column("Service\n", justify="center")
        dashboardDetailedViewTable.add_column("Product\n", justify="center")
        dashboardDetailedViewTable.add_column("Version\n", justify="center")

        #Put together dashboard
        progress = self.dashboardProgressbar()
        dashboardComplete["progressbar"].update(progress)
        dashboardComplete["banner"].update(self.META["BANNER"] if not self.options["quiet"]else "")
        if not last: dashboardComplete["navigator"].update(self.navigator())
        dashboardComplete["stats"].update(self.dashboardStats())
        dashboardComplete["command"].update(self.dashboardCommand())
        dashboardScrolled["progressbar"].update(progress)
        dashboardScrolled["banner"].update(self.META["BANNER"] if not self.options["quiet"] else "")
        if not last: dashboardScrolled["navigator"].update(self.navigator())
        dashboardScrolled["stats"].update(self.dashboardStats())
        dashboardScrolled["command"].update(self.dashboardCommand())
        progress.stop()

        # For complete
        dashboardComplete["dashboardMain"].update(self.dashboardMain(dashboardMainTable, last=last))
        dashboardComplete["dashboardNetwork"].update(self.dashboardNetwork(dashboardNetworkTable))

        #For scrolled
        # view=0 -> Default dashboard
        if self.dashboardInteractionState["view"] == 0:
            ##Scrolled dashboardMain
            #If more targets than can be shown at once, create scrolled dashboard
            if self.targetsTotal > Scheduler.DASHBOARD_MAX_SIZE:
                dashboardScrolledTable = None
                #If the threads don't fit into the window, create autoscroll
                tableActive = self.dashboardMain(dashboardMainTable, statusFilter=["active"], last=last)
                if self.threads > Scheduler.DASHBOARD_MAX_SIZE_THREADS:
                    # This buffer makes sure the scrolling is complete before new scans are added to list. Otherwise he would scroll weird as new scans are added while scrolling
                    if self.windowMainThreads == 0:
                        self.windowMainThreadsBuffer = copy.deepcopy(tableActive)
                    #Create dashboardMain with subset of targets
                    dashboardScrolledTable = self.padTable(self.sliceTable(dashboardMainTable, self.windowMainThreadsBuffer, self.windowMainThreads, self.windowMainThreads+Scheduler.DASHBOARD_MAX_SIZE_THREADS), Scheduler.DASHBOARD_MAX_SIZE_THREADS)
                    # Get current time
                    currentTime = time.time()
                    #This is done so the first page is shown and not instantly scrolled
                    if self.last_scroll_main_threads == 0:
                        self.last_scroll_main_threads = currentTime + (Scheduler.DASHBOARD_MAX_SIZE_THREADS * Scheduler.DASHBOARD_SCROLL_SPEED_MODIFIER) - 0.1
                    # Check if dashboard should be scrolled based on refresh rate * Scheduler.DASBOARD_MAX_SIZE
                    if currentTime - self.last_scroll_main_threads >= Scheduler.REFRESH_RATE * Scheduler.DASHBOARD_MAX_SIZE_THREADS * Scheduler.DASHBOARD_SCROLL_SPEED_MODIFIER:
                        # Track last scroll
                        self.last_scroll_main_threads = currentTime
                        #Limit counter to number of targets rounded to next Scheduler.DASBOARD_MAX_SIZE potenz
                        self.windowMainThreads = (self.windowMainThreads+Scheduler.DASHBOARD_MAX_SIZE_THREADS) % (len(self.windowMainThreadsBuffer.rows) + ((Scheduler.DASHBOARD_MAX_SIZE_THREADS - (len(self.windowMainThreadsBuffer.rows) % Scheduler.DASHBOARD_MAX_SIZE_THREADS)) if (len(self.windowMainThreadsBuffer.rows) % Scheduler.DASHBOARD_MAX_SIZE_THREADS) != 0 else 0)) if len(self.windowMainThreadsBuffer.rows) != 0 else 0
                #If the threads fit into window skip autoscroll
                else:
                    dashboardScrolledTable = self.padTable(self.dashboardMain(dashboardMainTable, statusFilter=["active"], last=last), Scheduler.DASHBOARD_MAX_SIZE_THREADS)

                #Add list of finished scans with autoscroll
                tableDone = self.dashboardMain(dashboardMainTable, statusFilterNegative=["active", "inactive"], last=last)
                if len(tableDone.rows) > Scheduler.DASHBOARD_MAX_SIZE_DONE:
                    #This buffer makes sure the scrolling is complete before new scans are added to list. Otherwise he would scroll weird as new scans are added while scrolling
                    if self.windowMainDone == 0:
                        self.windowMainDoneBuffer = copy.deepcopy(tableDone)
                    # Create dashboardMain with subset of targets
                    dashboardScrolledTable = self.appendTable(dashboardScrolledTable, self.padTable(self.sliceTable(dashboardMainTable, self.windowMainDoneBuffer, self.windowMainDone, self.windowMainDone + Scheduler.DASHBOARD_MAX_SIZE_DONE), Scheduler.DASHBOARD_MAX_SIZE_DONE), delimiter=True)
                    # Get current time
                    currentTime = time.time()
                    # This is done so the first page is shown and not instantly scrolled
                    if self.last_scroll_main_done == 0:
                        self.last_scroll_main_done = currentTime + (Scheduler.DASHBOARD_MAX_SIZE_DONE * Scheduler.DASHBOARD_SCROLL_SPEED_MODIFIER) - 0.1
                    # Check if dashboard should be scrolled based on refresh rate * Scheduler.DASHBOARD_MAX_SIZE_DONE
                    if currentTime - self.last_scroll_main_done >= Scheduler.REFRESH_RATE * Scheduler.DASHBOARD_MAX_SIZE_DONE * Scheduler.DASHBOARD_SCROLL_SPEED_MODIFIER:
                        # Track last scroll
                        self.last_scroll_main_done = currentTime
                        # Limit counter to number of targets rounded to next Scheduler.DASHBOARD_MAX_SIZE_DONE potenz
                        self.windowMainDone = (self.windowMainDone + Scheduler.DASHBOARD_MAX_SIZE_DONE) % (len(self.windowMainDoneBuffer.rows) + ((Scheduler.DASHBOARD_MAX_SIZE_DONE - (len(self.windowMainDoneBuffer.rows) % Scheduler.DASHBOARD_MAX_SIZE_DONE)) if (len(self.windowMainDoneBuffer.rows) % Scheduler.DASHBOARD_MAX_SIZE_DONE) != 0 else 0)) if len(self.windowMainDoneBuffer.rows) != 0 else 0
                else:
                    dashboardScrolledTable = self.appendTable(dashboardScrolledTable, self.padTable(tableDone, Scheduler.DASHBOARD_MAX_SIZE_DONE), delimiter=True)
                dashboardScrolled["dashboardMain"].update(dashboardScrolledTable)
            #If targets fit into dashboard, nothing needs to be changed
            else:
                # If dynamic is dashboard size is off, padTable
                if not Scheduler.DYNAMIC_DASHBOARD_SIZE:
                    dashboardScrolled["dashboardMain"].update(self.padTable(table=self.dashboardMain(dashboardMainTable, last=last), size=Scheduler.DASHBOARD_MAX_SIZE))
                else:
                    dashboardScrolled["dashboardMain"].update(self.dashboardMain(dashboardMainTable, last=last))

        ##Scrolled dashboardNetwork
        if len(self.networkStartData) > Scheduler.NETWORK_MAX_SIZE:
            # Create dashboardNetwork with subset of networks
            dashboardScrolled["dashboardNetwork"].update(self.sliceTable(copy.deepcopy(dashboardNetworkTable), self.dashboardNetwork(dashboardNetworkTable), self.windowNetworks, self.windowNetworks + Scheduler.NETWORK_MAX_SIZE))
            # Get current time
            currentTime = time.time()
            # This is done so the first page is shown and not instantly scrolled
            if self.last_scroll_network == 0:
                self.last_scroll_network = currentTime + ( Scheduler.NETWORK_MAX_SIZE * Scheduler.DASHBOARD_SCROLL_SPEED_MODIFIER) - 0.1
            # Check if dashboard should be scrolled based on refresh rate * Scheduler.DASBOARD_MAX_SIZE
            if currentTime - self.last_scroll_network >= Scheduler.REFRESH_RATE * Scheduler.NETWORK_MAX_SIZE * Scheduler.DASHBOARD_SCROLL_SPEED_MODIFIER:
                # Track last scroll
                self.last_scroll_network = currentTime
                # Limit counter to number of targets rounded to next Scheduler.DASBOARD_MAX_SIZE potenz
                self.windowNetworks = (self.windowNetworks + Scheduler.NETWORK_MAX_SIZE) % (len(self.networkStartData) + ((Scheduler.NETWORK_MAX_SIZE - (len(self.networkStartData) % Scheduler.NETWORK_MAX_SIZE)) if (len(self.networkStartData) % Scheduler.NETWORK_MAX_SIZE) != 0 else 0)) if len(self.networkStartData) != 0 else 0
        else:
            #If dynamic is dashboard size is off, padTable
            if not Scheduler.DYNAMIC_DASHBOARD_SIZE:
                dashboardScrolled["dashboardNetwork"].update(self.padTable(table=self.dashboardNetwork(dashboardNetworkTable), size=Scheduler.NETWORK_MAX_SIZE))
            else:
                dashboardScrolled["dashboardNetwork"].update(self.dashboardNetwork(dashboardNetworkTable))

        # view=1 -> replace "main dashboard" with detailed scan view
        if self.dashboardInteractionState["view"] == 1:
            #dashboardScrolled["dashboardMain"].update(self.buildDetailedViewOfScan(table=dashboardDetailedViewTable))
            # Copying scroll logic from main dashboard and keeping its size, meaning running + done -> max size
            if "data" in self.targetsStats[self.dashboardInteractionState["selectedTarget"]].keys() and len(self.getOpenPortsLive(self.dashboardInteractionState["selectedTarget"])) > Scheduler.DASHBOARD_MAX_SIZE:
                if self.windowDetailedView == 0:
                    self.windowDetailedViewBuffer = copy.deepcopy(self.buildDetailedViewOfScan(table=dashboardDetailedViewTable))
                #Create dashboardMain with subset of targets
                dashboardScrolledTableDetailedView = self.padTable(self.sliceTable(dashboardDetailedViewTable, self.windowDetailedViewBuffer, self.windowDetailedView, self.windowDetailedView+Scheduler.DASHBOARD_MAX_SIZE), Scheduler.DASHBOARD_MAX_SIZE)
                # Get current time
                currentTime = time.time()
                #This is done so the first page is shown and not instantly scrolled
                if self.last_scroll_detailed_view == 0:
                    self.last_scroll_detailed_view = currentTime + (Scheduler.DASHBOARD_MAX_SIZE * Scheduler.DASHBOARD_SCROLL_SPEED_MODIFIER) - 0.1
                # Check if dashboard should be scrolled based on refresh rate * Scheduler.DASBOARD_MAX_SIZE
                if currentTime - self.last_scroll_detailed_view >= Scheduler.REFRESH_RATE * Scheduler.DASHBOARD_MAX_SIZE * Scheduler.DASHBOARD_SCROLL_SPEED_MODIFIER:
                    # Track last scroll
                    self.last_scroll_detailed_view = currentTime
                    #Limit counter to number of targets rounded to next Scheduler.DASBOARD_MAX_SIZE potenz
                    self.windowDetailedView = (self.windowDetailedView+Scheduler.DASHBOARD_MAX_SIZE) % (len(self.windowDetailedViewBuffer.rows) + ((Scheduler.NETWORK_MAX_SIZE - (len(self.windowDetailedViewBuffer.rows) % Scheduler.DASHBOARD_MAX_SIZE)) if (len(self.windowDetailedViewBuffer.rows) % Scheduler.DASHBOARD_MAX_SIZE) != 0 else 0)) if len(self.windowDetailedViewBuffer.rows) != 0 else 0
            else:
                #If dynamic is dashboard size is off, padTable
                if not Scheduler.DYNAMIC_DASHBOARD_SIZE:
                    dashboardScrolledTableDetailedView = self.padTable(self.buildDetailedViewOfScan(table=dashboardDetailedViewTable), Scheduler.DASHBOARD_MAX_SIZE)
                else:
                    dashboardScrolledTableDetailedView = self.buildDetailedViewOfScan(table=dashboardDetailedViewTable)
            dashboardScrolled["dashboardMain"].update(dashboardScrolledTableDetailedView)

        #Only dashboardScrolled is modified according to selected view, as this will get printed, the complete is for the dashboard.txt and final last print
        return (dashboardScrolled, dashboardComplete)

    #Slice table, get subtable
    def sliceTable(self, tableBase, table, start, end):
        #New table, based on normal dashboardMain base
        # Clone object, otherwise weird reference effects
        slicedTable = copy.deepcopy(tableBase)
        table = copy.deepcopy(table)
        #List of columns with rows subset
        columns = []
        #Iterate over each column
        for column in table.columns:
            #Get all cells of column
            col = list(column.cells)
            #Cut out subset
            col = col[start:end]
            #Add to new columns list
            columns.append(col)
        #Iterate over each row
        for i in range(len(columns[0])):
            #Collect cells from row
            row = [column[i] for column in columns]
            #Add row and get style from original row
            slicedTable.add_row(*row, style=table.rows[start:end][i].style)
        return slicedTable

    #Append a table onto another
    def appendTable(self, tableComplete, tableToAdd, delimiter=False):
        # Clone object, otherwise weird reference effects
        tableComplete = copy.deepcopy(tableComplete)
        tableToAdd = copy.deepcopy(tableToAdd)
        # List of columns with rows
        columns = []
        # Iterate over each column
        for column in tableToAdd.columns:
            # Get all cells of column
            col = list(column.cells)
            # Add to new columns list
            columns.append(col)
        #If delimiter was set, set end_section so a line is inserted by rich
        if delimiter:
            tableComplete.rows[-1].end_section = True
        # Iterate over each row
        for i in range(len(columns[0])):
            # Collect cells from row
            row = [column[i] for column in columns]
            # Add row and get style from original row
            tableComplete.add_row(*row, style=tableToAdd.rows[i].style)
        return tableComplete

    #Pad table to specific size
    def padTable(self, table, size):
        table = copy.deepcopy(table)
        for i in range(size-len(table.rows)):
            table.add_row()
        return table

    #Calculates and creates main dashboard (Multithreaded)
    def dashboardMain(self, table, statusFilter: list = [], statusFilterNegative: list = [], last=False):
        #Clone object, otherwise weird reference effects
        table = copy.deepcopy(table)
        #Create list of workers to process data of each target in own separate thread to speed up data processing
        workers = [None for _ in range(self.targetsTotal)]
        #Create queue for worker results
        workerResultsQueue = queue.Queue()
        for workerID in range(len(workers)):
            # Prepare new worker
            workers[workerID] = threading.Thread(target=self.processThreadData, args=(self.targetsStats[workerID], workerResultsQueue, workerID), name=workerID)
            #Start worker
            workers[workerID].start()
        #Wait for workers to finish
        while any(w.is_alive() for w in workers if w is not None): time.sleep(Scheduler.REFRESH_RATE_FOR_WORKER)

        #Retrieve worker data
        while not workerResultsQueue.empty():
            targetID, stats = workerResultsQueue.get()
            self.targetsStats[targetID]["stats"] = stats
        #Create dashboardMain rows from targetStats
        for targetID in range(len(self.targetsStats)):
            #Set colors
            status = self.targetsStats[targetID]["status"]
            colorStatus = COLORS["woDarkOrange"] if status == "active" else COLORS["woDarkGreen"] if status == "completed" else COLORS["woGrey37"] if status == "inactive" else COLORS["woRed"] if status in ["aborted", "error"] else COLORS["white"]
            colorRow = COLORS["cyan1"]if status == "active" else COLORS["skyBlue"] if status == "completed" else COLORS["cyan"] if status == "inactive" else COLORS["red"] if status in ["aborted", "error"] else COLORS["white"]
            #Make selected row bold
            if targetID == self.dashboardInteractionState["selectedTarget"] and not last:
                colorRow += " bold"
            # Filter scans if filter is present
            if statusFilter != [] and status not in statusFilter: continue
            if statusFilterNegative != [] and status in statusFilterNegative: continue
            #Set parameter accordingly, general or individual
            parameter = self.parameter if self.targetsStats[targetID]["target"] not in self.parameterOfTargets.keys() else self.parameterOfTargets[self.targetsStats[targetID]["target"]]
            #If target has stats, add them
            if "stats" in self.targetsStats[targetID]:
                #Set more colors for field that only exists when thread runs or finished
                targetState = self.targetsStats[targetID]["stats"]["targetState"]
                colorTargetState = COLORS["darkGreen"]if targetState == "online" else COLORS["darkOrange"] if targetState == "offline" else COLORS["grey69"] if targetState == "unknown" else COLORS["white"]
                #Special row color grey if targetState unknown
                if status == "completed" and targetState == "unknown":
                    colorRow = COLORS["grey69"]
                #try to load open ports
                openPortsTcp = []
                openPortsUdp = []
                openPorts = ""
                ports = {}
                if "data" in self.targetsStats[targetID].keys() and not self.targetsStats[targetID]["done"]:
                    ports = self.getOpenPortsLive(targetID=targetID)
                # Set path
                pathTmp = os.getcwd()
                if not Scheduler.NO_FOLDER_PER_SCAN and os.path.exists(f'{pathTmp}/{self.targetsStats[targetID]["filename"]}'):
                    pathTmp = f'{pathTmp}/{self.targetsStats[targetID]["filename"]}'
                if self.targetsStats[targetID]["done"] and os.path.exists(f'{pathTmp}/{self.targetsStats[targetID]["filename"]}.xml'):
                    ports = self.getPortsAndServices(targetID=targetID)
                for port, values in ports.items():
                    if values["protocol"] == "tcp":
                        openPortsTcp.append(port)
                    elif values["protocol"] == "udp":
                        openPortsUdp.append(port)
                if openPortsTcp:
                    openPorts = f'tcp: {str(openPortsTcp).removeprefix("[").removesuffix("]").replace(", ", "|")}{", " if openPortsUdp else ""}'.replace("'","")
                if openPortsUdp:
                    openPorts += f'udp: {str(openPortsUdp).removeprefix("[").removesuffix("]").replace(", ", "|")}'.replace("'","")
                table.add_row(str(self.targetsStats[targetID]["stats"]["targetID"]),
                              #str(self.targetsStats[targetID]["stats"]["threadID"]),
                              #str(self.targetsStats[targetID]["stats"]["pid"]),
                              str(self.targetsStats[targetID]["stats"]["target"]),
                              f'[{colorTargetState}]{targetState}[/{colorTargetState}]',
                              f'[{colorStatus}]{status}[/{colorStatus}]',
                              str(self.targetsStats[targetID]["stats"]["progress"]),
                              str(self.targetsStats[targetID]["stats"]["runtime"]),
                              str(self.targetsStats[targetID]["stats"]["ete"]),
                              str(self.targetsStats[targetID]["stats"]["start"]),
                              str(self.targetsStats[targetID]["stats"]["stop"]),
                              str(openPorts),
                              *([parameter] if self.parameterOfTargets else []), style=self.COLORS["woRed"] if self.dashboardInteractionState["killPending"] and targetID == self.dashboardInteractionState["selectedTarget"] else colorRow)
            #If target doesn't have stats i.e. because it isn't started yet, add row accordingly with less data
            else:
                table.add_row(str(self.targetsStats[targetID]["targetID"]),
                              #"",
                              #"",
                              str(self.targetsStats[targetID]["target"]),
                              "",
                              f'[{colorStatus}]{status}[/{colorStatus}]',
                              "",
                              "",
                              "",
                              "",
                              "",
                              "",
                              *([parameter] if self.parameterOfTargets else []), style=colorRow)
        return table

    #Function for thread to process target data
    def processThreadData(self, targetStats, resultsQueue, workerID):

        targetID = workerID

        #If target has finished and data was processed one last time, skip function
        if self.targetsStats[workerID]["done"]:
            return


        #If there is data from thread, update stats
        if "threadInfo" in targetStats:
            # Set path
            path = os.getcwd()
            if not Scheduler.NO_FOLDER_PER_SCAN and os.path.exists(f'{path}/{self.targetsStats[targetID]["filename"]}'):
                path = f'{path}/{self.targetsStats[targetID]["filename"]}'
            targetID = targetStats["targetID"]
            threadID = targetStats["threadInfo"]["threadID"]
            pid = targetStats["threadInfo"]["pid"]
            target = targetStats["target"]
            # Extract hoststate from nmap output (from xml file)
            with subprocess.Popen(f'grep "<hosthint" {self.targetsStats[targetID]["filename"]}.xml | tail -n 1', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=path) as process:
                content = process.stdout.read()
                if "state=" in content:
                    targetState = content.split('state="')[1].split('"')[0]
                    targetState = "online" if targetState == "up" else "offline" if targetState == "down" else "N/A"
                else:
                    targetState = "N/A"
            #If first method for hostate didn't work, try second one
            if targetState == "N/A":
                with subprocess.Popen(f'grep "<hosts" {self.targetsStats[targetID]["filename"]}.xml | tail -n 1', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=path) as process:
                    content = process.stdout.read()
                    if "up=" in content and "down=" in content and "total" in content:
                        up = content.split('up="')[1].split('"')[0]
                        down = content.split('down="')[1].split('"')[0]
                        total = content.split('total="')[1].split('"')[0]
                        targetState = "online" if up == "1" else "offline" if down == "1" else "unknown" if total == "0" else "N/A"
                    else:
                        targetState = "N/A"

            #Set scan status
            status = targetStats["status"]
            #Extract progress from nmap output (from xml file)
            with subprocess.Popen(f'grep "<taskprogress" {self.targetsStats[targetID]["filename"]}.xml | tail -n 1', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=path) as process:
                content = process.stdout.read()
                if "percent=" in content:
                    progress = content.split('percent="')[1].split('"')[0]
                    progress = f'{progress}%'
                else:
                    progress = "N/A"
                if status == "completed":
                    progress = "100%"
            #Calculate runtime
            #Calculate passed time and remove milliseconds
            timeElapsed = str(datetime.datetime.now() - targetStats["threadInfo"]["timeStart"])
            runtime = timeElapsed if timeElapsed.split(".") == 1 else timeElapsed.split(".")[0]
            # Extract ete from nmap output (from xml file)
            with subprocess.Popen(f'grep "<taskprogress" {self.targetsStats[targetID]["filename"]}.xml | tail -n 1', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=path) as process:
                content = process.stdout.read()
                if "remaining=" in content:
                    ete = int(content.split('remaining="')[1].split('"')[0])
                    ete = f'{ete}s' if ete < 60 else f'{round(ete/60, 2)}m' if ete < 3600 else f'{round(ete/3600, 2)}h'
                else:
                    ete = "N/A"
                if status == "completed":
                    ete = "0s"
            #Format starttime
            start = targetStats["threadInfo"]["timeStart"].strftime(Scheduler.DATETIME_STR_FORMAT)
            #If present format stop time
            if targetStats["threadInfo"]["timeStop"]:
                stop = targetStats["threadInfo"]["timeStop"].strftime(Scheduler.DATETIME_STR_FORMAT)
            else:
                stop = "N/A"
            parameter = ""
            #Prepare stats
            stats = {"targetID": targetID,
                    "threadID": threadID,
                    "pid": pid,
                    "target": target,
                    "targetState": targetState,
                    "status": status,
                    "progress": progress,
                    "runtime": runtime,
                    "ete": ete,
                    "start": start,
                    "stop": stop,
                    "parameter": parameter}
            #Return stats
            resultsQueue.put((targetID, stats))
            #If target is done and data was process one last time, set status to done.
            #So data processing can be skipped
            if status in ["completed", "aborted", "error"]:
                self.targetsStats[workerID]["done"] = True

    #Create dashboard: network
    ##Calculates and displays bandwith / interface usage
    def dashboardNetwork(self, table):
        # Clone object, otherwise weird reference effects
        table = copy.deepcopy(table)
        #Get current interface / network stats
        networkIO = psutil.net_io_counters(pernic=True)
        networkIOTime = time.time()
        #Calculate usage and speed for each interface
        for interface, interfaceIO in networkIO.items():
            #Calculate total network usage since start in Kilobyte
            totalDown = round((interfaceIO.bytes_recv - self.networkStartData[interface].bytes_recv) / 1000, 3)
            totalUp = round((interfaceIO.bytes_sent - self.networkStartData[interface].bytes_sent) / 1000, 3)
            #Calculate current speed in Kilobytes per Second
            speedDown = round(((interfaceIO.bytes_recv-self.networkLastData[interface].bytes_recv) / (networkIOTime - self.networkLastTime) / 1000), 3)
            speedUp = round(((interfaceIO.bytes_sent-self.networkLastData[interface].bytes_sent) / (networkIOTime - self.networkLastTime) / 1000), 3)
            #Update MAX speed values
            if speedDown > self.networkMaxRX[interface]: self.networkMaxRX[interface] = speedDown
            if speedUp > self.networkMaxTX[interface]: self.networkMaxTX[interface] = speedUp
            # If option was set color up/down if over/at warning limit
            colorDown = None
            colorDownMax = None
            if int(Scheduler.NETWORK_WARNING_RECEIVE) > 0:
                if int(speedDown) >= int(Scheduler.NETWORK_WARNING_RECEIVE): colorDown = COLORS["woRed"]
                if int(self.networkMaxRX[interface]) >= int(Scheduler.NETWORK_WARNING_RECEIVE): colorDownMax = COLORS["woRed"]
            colorUp = None
            colorUpMax = None
            if int(Scheduler.NETWORK_WARNING_TRANSMIT) > 0:
                if int(speedUp) >= int(Scheduler.NETWORK_WARNING_RECEIVE): colorUp = COLORS["woRed"]
                if int(self.networkMaxTX[interface]) >= int(Scheduler.NETWORK_WARNING_TRANSMIT): colorUpMax = COLORS["woRed"]
            #Add row to network dashboard
            table.add_row(interface, f'{"["+colorDown+"]" if colorDown else ""}{str(speedDown)}{"[/"+colorDown+"]" if colorDown else ""}', f'{"["+colorUp+"]" if colorUp else ""}{str(speedUp)}{"[/"+colorUp+"]" if colorUp else ""}', f'{"["+colorDownMax+"]" if colorDownMax else ""}{str(self.networkMaxRX[interface])}{"[/"+colorDownMax+"]" if colorDownMax else ""}', f'{"["+colorUpMax+"]" if colorUpMax else ""}{str(self.networkMaxTX[interface])}{"[/"+colorUpMax+"]" if colorUpMax else ""}', str(totalDown), str(totalUp), style=COLORS["skyBlue"])
        #Take new measures for next speed calculation
        self.networkLastData = psutil.net_io_counters(pernic=True)
        self.networkLastTime = time.time()
        #Return network dashboard table
        return table

    #Create dashboard: stats
    def dashboardStats(self):
        # Create stats: progress of targets and active threads
        stats = f'[bold]Progress:[/bold] {self.targetsCompleted}/{self.targetsTotal} | [bold]Threads:[/bold] {self.threadsActive}/{self.threads} | [bold]NMAP-Parameter:[/bold] [{COLORS["woGrey19"]}]{self.parameter} [/{COLORS["woGrey19"]}]'
        return stats

    #Create dashboard: progressbar
    def dashboardProgressbar(self):
        # Create Progress bar
        # Calculate passed time and remove milliseconds
        timeElapsed = str(datetime.datetime.now() - self.timeStart)
        timeElapsed = timeElapsed if timeElapsed.split(".") == 1 else timeElapsed.split(".")[0]
        #Create progressbar
        progress = Progress(BarColumn(complete_style="cyan", finished_style="green3", bar_width=50),
                            TextColumn("[cyan][progress.percentage]{task.percentage:>3.1f}%[/cyan]"),
                            TextColumn(timeElapsed))
        #Add progressbar to progress object
        progressbar = progress.add_task("Progress", total=self.targetsTotal)
        progress.update(progressbar, advance=self.targetsCompleted)
        return progress

    # Create dashboard: calling command
    def dashboardCommand(self):
        stupidQuote = '"'
        return f'[bold]Command:[/bold] [{COLORS["woGrey19"]}] {" ".join([var if "=" not in var else stupidQuote+var+stupidQuote for var in sys.argv])} [/{COLORS["woGrey19"]}] [{COLORS["grey69"]}]{"" if not self.options["parameterSet"] else "{"+self.options["parameterSet"]+": "+self.parameterSets[self.options["parameterSet"]]+"}"}[/{COLORS["grey69"]}]'

    #Keyboard input listener
    def keyboardListener(self):
        #Create keybindings
        keybindings = KeyBindings()
        #Catch ctrl+c and selfdestroy
        @keybindings.add("c-c")
        def _(event):
            #kill all process
            for process in self.scanProcesses.values():
                try:
                    process.terminate()
                    process.wait()
                except:
                    pass
            self.rawMode.__exit__()
            os._exit(0)
        #Select row with down and up arrow key
        @keybindings.add("up")
        def _(event):
            #Block selection while kill is pending
            if self.dashboardInteractionState["killPending"]: return
            self.dashboardInteractionState["selectedTarget"] = (self.dashboardInteractionState["selectedTarget"] - 1) % self.targetsTotal
        @keybindings.add("down")
        def _(event):
            # Block selection while kill is pending
            if self.dashboardInteractionState["killPending"]: return
            self.dashboardInteractionState["selectedTarget"] = (self.dashboardInteractionState["selectedTarget"] + 1) % self.targetsTotal
        #Enter detailed view of selected scan with enter
        @keybindings.add("enter")
        @keybindings.add("c-m")
        @keybindings.add("c-j")
        def _(event):
            self.dashboardInteractionState["enter"] = True
            self.dashboardInteractionState["quit"] = False
            self.dashboardInteractionState["view"] = 1
        #Quit currently selected detailed scan view back to main dashboard with q
        @keybindings.add("q")
        @keybindings.add("escape")
        def _(event):
            self.dashboardInteractionState["quit"] = True
            self.dashboardInteractionState["enter"] = False
            self.dashboardInteractionState["view"] = 0
        #Kill selected scan
        @keybindings.add("k")
        def _(event):
            #Start pending kill
            if not self.dashboardInteractionState["killPending"]:
                #Check if a valid target is selected
                if self.targetsStats[self.dashboardInteractionState["selectedTarget"]]["status"] == "active":
                    self.dashboardInteractionState["killPending"] = True
                return
            #Confirm kill
            if self.dashboardInteractionState["killPending"]:
                self.dashboardInteractionState["killExecute"] = True

        # Apply keybindings, with dummy layout
        app = Application(key_bindings=keybindings, full_screen=False, layout=prompt_toolkitLayout(prompt_toolkitTextArea(text="")), mouse_support=False)
        app.run()

    # Monitor pending kill, if waited to long, reset
    def pendingReseter(self):
        while True:
            if self.dashboardInteractionState["killPending"]:
                time.sleep(Scheduler.SCAN_KILL_PENDING_WAIT)
                self.dashboardInteractionState["killPending"] = False
            time.sleep(Scheduler.SCAN_KILL_PENDING_REFRESH)

    #Build navigator section of dashboard
    def navigator(self):
        #Load currently selected target
        targetID = self.dashboardInteractionState["selectedTarget"]
        #Load targets status and relating color
        status = self.targetsStats[targetID]["status"]
        colorStatus = COLORS["woDarkOrange"] if status == "active" else COLORS["woDarkGreen"] if status == "completed" else COLORS["woGrey37"] if status == "inactive" else COLORS["woRed"] if status in ["aborted", "error"] else COLORS["white"]
        return f'[bold]Inspect Target:[/bold] {"["+self.COLORS["woRed"]+"]" if self.dashboardInteractionState["killPending"] else ""}[ {targetID} | {self.TARGETS[targetID]} | [{colorStatus}]{status}[/{colorStatus}] ]{"[/"+self.COLORS["woRed"]+"]" if self.dashboardInteractionState["killPending"] else ""}\nSelect: "↑" & "↓" | Open: "ENTER" | Quit: "ESC | q" | Kill: "k" {"| [red]PRESS k AGAIN TO CONFIRM SCAN KILL[/red]" if self.dashboardInteractionState["killPending"] else ""}'

    #Build dashboard for detailed view of scan
    def buildDetailedViewOfScan(self, table):
        targetID = self.dashboardInteractionState["selectedTarget"]
        target = self.TARGETS[targetID]
        filename = self.targetsStats[targetID]["filename"]
        # Set path
        path = os.getcwd()
        if not Scheduler.NO_FOLDER_PER_SCAN and os.path.exists(f'{path}/{filename}'):
            path = f'{path}/{filename}'
        #If scan is running or done
        if os.path.exists(f'{path}/{filename}.xml') and "data" in self.targetsStats[targetID].keys():
            portsAndServices = {}
            #Read info from live data, only basic port information
            if not self.targetsStats[targetID]["done"]:
                portsAndServices = self.getOpenPortsLive(targetID=targetID)
            #Read info from finished file, full information
            if self.targetsStats[targetID]["done"]:
                portsAndServices = self.getPortsAndServices(targetID=targetID)
            #build table
            # Clone object, otherwise weird reference effects
            table = copy.deepcopy(table)
            # Fill table
            for port in portsAndServices.keys():
                table.add_row(port, str(portsAndServices[port]["protocol"]), str(portsAndServices[port]["state"]), str(portsAndServices[port]["service"]),
                              str(portsAndServices[port]["product"]), str(portsAndServices[port]["version"]))
        #If no scan data is present
        else:
            # Clone object, otherwise weird reference effects
            table = copy.deepcopy(table)
            # Create empty table with note that scan has not been started yet
            table.add_row("SCAN NOT STARTED", "N/A", "N/A", "N/A", "N/A", "N/A")

        return table

    #Create filename based on output filename pattern
    def createFilename(self, target):
        # Load parameter
        parameter = self.parameter
        # Load individual parameter if present
        if target in self.parameterOfTargets:
            parameter = self.parameterOfTargets[target]
        # Replace spaces
        parameter = parameter.replace(" ", "_")
        # Replace :
        target = target.replace(":", "..")
        # Format file name according to output pattern
        fileName = Scheduler.OUTPUT_PATTERN
        fileName = fileName.replace("{target}", target)
        if "{parameter}" in fileName:
            fileName = fileName.replace("{parameter}", parameter)

        return fileName

    #Get open / discovered from live data
    def getOpenPortsLive(self, targetID):
        ports = {}
        for line in self.targetsStats[targetID]["data"].split('\n'):
            if "Discovered open port " in line:
                portAndType = line.split("Discovered open port ")[1].split(" on")[0]
                ports[portAndType.split("/")[0]] = portAndType.split("/")[1]
        #align format according to getPortsAndServices
        portsAndServices = {}
        for key, value in ports.items():
            portsAndServices[key] = {
                "protocol": value,
                "state": "",
                "service": "",
                "product": "",
                "version": "",
            }
        return portsAndServices

    #Get ports and service info from finished scan data from xml file
    def getPortsAndServices(self, targetID):
        target = self.TARGETS[targetID]
        filename = self.targetsStats[targetID]["filename"]
        # Set path
        path = os.getcwd()
        if not Scheduler.NO_FOLDER_PER_SCAN and os.path.exists(f'{path}/{filename}'):
            path = f'{path}/{filename}'
        portsAndServices = {}
        with open(f'{path}/{filename}.xml', "r") as file:
            for line in file.readlines():
                if "<port protocol" in line:
                    port = ""
                    protocol = ""
                    state = ""
                    service = ""
                    product = ""
                    version = ""
                    try:
                        port = line.split('portid="')[1].split('"')[0]
                        protocol = line.split('protocol="')[1].split('"')[0]
                        state = line.split('state="')[1].split('"')[0]
                    except:
                            pass
                    try:
                        service = line.split('name="')[1].split('"')[0]
                        product = line.split('product="')[1].split('"')[0]
                        version = line.split('version="')[1].split('"')[0]
                    except:
                        pass
                    # scripts = {}
                    # for script in line.split('<script')[1:]:
                    #    id = script.split('id="')[1].split('"')[0]
                    #    output = script.split('output="')[1].split('"')[0]
                    #    scripts[id] = output
                    portsAndServices[port] = {
                        "protocol": protocol,
                        "state": state,
                        "service": service,
                        "product": product,
                        "version": version,
                        #   "scripts": scripts,
                    }
        return portsAndServices

    #Executes additional features while main thread is running
    def featureLoaderParallel(self):
        while True:
            #Kill executer; checks if a kill of a scan should be performed and if so executes it
            self.featureParallelKillScan()
            #Activate auto kill scan with threshold if option was set
            if self.options["killThreshold"]:
                self.featureParallelAutoKill(threshold=self.options["killThreshold"])
            #Wait x before executing features again
            time.sleep(Scheduler.FEATURE_LOADER_PARALLEL_REFRESHRATE)

    #Checks if a kill of a scan should be performed and if so executes it
    def featureParallelKillScan(self):
        if self.dashboardInteractionState["killExecute"]:
            self.dashboardInteractionState["killExecute"] = False
            self.dashboardInteractionState["killPending"] = False
            targetID = self.dashboardInteractionState["selectedTarget"]
            if targetID in self.scanProcesses.keys() and self.scanProcesses[targetID].poll() is None:
                self.scanProcesses[targetID].terminate()

    #If relating option was set, check if a scan exceeds the auto kill threshold, if so kill it
    def featureParallelAutoKill(self, threshold: int):
        #Iterate over each running target
        for targetID in [targetID for targetID in range(len(self.targetsStats)) if self.targetsStats[targetID]["status"] == "active"]:
            try:
                runtime = self.targetsStats[targetID]["stats"]["runtime"]
                #if runtime exceeds threshold, kill scan
                #Not 100% sure but this might be problematic if a scan runs longer than a day.
                if (int(runtime.split(":")[0])*60+int(runtime.split(":")[1])) >= threshold:
                    if targetID in self.scanProcesses.keys() and self.scanProcesses[targetID].poll() is None:
                        self.scanProcesses[targetID].terminate()
            except:
                continue

    #Function to cleanup some things
    # It specifically implements the deletion of specific scan files --remove-files or complete if target not online --keep-offline-files
    def cleanup(self):
        for targetID in range(len(self.TARGETS)):
            fileName = self.createFilename(self.targetsStats[targetID]["target"])
            # If option is not disabled create folder for scan based on filename
            path = os.getcwd()
            if not Scheduler.NO_FOLDER_PER_SCAN and os.path.exists(f'{path}/{fileName}'):
                path = f'{path}/{fileName}'
            # If option / config was set, clean up and remove scan files
            if Scheduler.REMOVE_FILES != "" and not Scheduler.ONLY_SCANS_FILE:
                try:
                    for fileType in Scheduler.REMOVE_FILES.split(";"):
                        os.remove(f'{path}/{fileName}.{fileType}')
                except:
                    pass
            # if option was set remove all individual scan files
            if Scheduler.ONLY_SCANS_FILE:
                for fileType in ["xml","html","nmap","gnmap"]:
                    try:
                        os.remove(f'{path}/{fileName}.{fileType}')
                    except:
                        pass
                    if path != os.getcwd():
                        try:
                            os.rmdir(path)
                        except:
                            pass
            # Remove all files if target was not online, except when option / config tells to keep them
            if not Scheduler.KEEP_OFFLINE_FILES and self.targetsStats[targetID]["stats"]["targetState"] != "online" and not Scheduler.ONLY_SCANS_FILE:
                # Try to remove each file type
                for fileType in ["nmap", "gnmap", "xml", "html"]:
                    try:
                        os.remove(f'{path}/{fileName}.{fileType}')
                    except:
                        pass
                # If folder for scan was created, remove it
                if not Scheduler.NO_FOLDER_PER_SCAN and os.path.exists(path):
                    os.rmdir(path)

    #Feature loader pre, for functions previous to main function run
    def featureLoaderPre(self):
        return

    # Feature loader post, for functions after main execution before cleanup
    def featureLoaderPost(self):
        #Merge scans into one xml / html
        self.mergeScanResults()

    #Here the nmap scan is performed. This function is passed to the threads.
    def scan(self, target: str, parameter: str, threadID: int, targetID: int, fileName: str):
        # If option is not disabled create folder for scan based on filename
        path = os.getcwd()
        if not Scheduler.NO_FOLDER_PER_SCAN:
            if not os.path.exists(f'{path}/{fileName}/'):
                os.mkdir(fileName)
            path = f'{path}/{fileName}'
        #Open process with nmap scan
        #process = subprocess.Popen([f'nmap {parameter} -oA {fileName} --stats-every {Scheduler.REFRESH_NMAP_STATS} {target}'], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        #                                                             the -v should stay where it is, this position is used in self.recoverOption to find paramter
        with subprocess.Popen(["nmap", *parameter.split(), "-v", "-oA", fileName, "--stats-every", str(Scheduler.REFRESH_NMAP_STATS), target], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=path) as process:
            #Make process reachable from main thread
            self.scanProcesses[targetID] = process
            try:
                #Check if the process output new line, if so put them in the data_queue to transfer them to the main thread and then into threadListInfo
                for line in process.stdout:
                    self.data_queue.put({"targetID": targetID, "data": line})
            finally:
                #Properly close thread and stdout
                process.stdout.close()
                exitCode = process.wait()
                self.scanProcesses.pop(targetID)
        #Use xsltproc to create html version of scan files
        processConvert = subprocess.Popen(["xsltproc", "-o", f'{fileName}.html', f'{fileName}.xml'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=path)
        processConvert.wait()
        #Update progress
        self.targetsCompleted += 1
        #Decrement active threads
        self.threadsActive -= 1
        #Set status according to exit code
        if exitCode == 0:
            #Set own thread / scan status to completed
            self.targetsStats[targetID]["status"] = "completed"
        elif exitCode < 0:
            self.targetsStats[targetID]["status"] = "aborted"
        else:
            self.targetsStats[targetID]["status"] = "error"
        #Set own thread / scan completion datetime
        self.targetsStats[targetID]["threadInfo"]["timeStop"] = datetime.datetime.now()

        #If a kill is pending while thread finished, reset it
        if self.dashboardInteractionState["killPending"] and targetID == self.dashboardInteractionState["selectedTarget"]:
            self.dashboardInteractionState["killPending"] = False

    #Try to load external config
    def loadConfig(self, config):
        # Trying to load external config
        try:
            if config:
                Scheduler.NETWORK_WARNING_RECEIVE = CONFIG["configuration"]["NETWORK_WARNING_RECEIVE"]
                Scheduler.NETWORK_WARNING_TRANSMIT = CONFIG["configuration"]["NETWORK_WARNING_TRANSMIT"]
                Scheduler.OUTPUT_PATTERN = CONFIG["configuration"]["OUTPUT_PATTERN"]
                Scheduler.REMOVE_FILES = CONFIG["configuration"]["REMOVE_FILES"]
                Scheduler.NO_FOLDER_PER_SCAN = CONFIG["configuration"]["NO_FOLDER_PER_SCAN"]
                Scheduler.KEEP_OFFLINE_FILES = CONFIG["configuration"]["KEEP_OFFLINE_FILES"]
                Scheduler.NO_DASHBOARD_FILE = CONFIG["configuration"]["NO_DASHBOARD_FILE"]
                Scheduler.REFRESH_RATE = CONFIG["configuration"]["REFRESH_RATE"]
                Scheduler.REFRESH_RATE_FOR_WORKER = CONFIG["configuration"]["REFRESH_RATE_FOR_WORKER"]
                Scheduler.REFRESH_RATE_FOR_FINAL_THREAT_WAIT = CONFIG["configuration"]["REFRESH_RATE_FOR_FINAL_THREAT_WAIT"]
                Scheduler.REFRESH_NMAP_STATS = CONFIG["configuration"]["REFRESH_NMAP_STATS"]
                Scheduler.DATETIME_STR_FORMAT = CONFIG["configuration"]["DATETIME_STR_FORMAT"]
                Scheduler.DASHBOARD_MAX_SIZE_THREADS = CONFIG["configuration"]["DASHBOARD_MAX_SIZE_THREADS"]
                Scheduler.DASHBOARD_MAX_SIZE_DONE = CONFIG["configuration"]["DASHBOARD_MAX_SIZE_DONE"]
                Scheduler.DASHBOARD_MAX_SIZE = CONFIG["configuration"]["DASHBOARD_MAX_SIZE"]
                Scheduler.NETWORK_MAX_SIZE = CONFIG["configuration"]["NETWORK_MAX_SIZE"]
                Scheduler.DASHBOARD_SCROLL_SPEED_MODIFIER = CONFIG["configuration"]["DASHBOARD_SCROLL_SPEED_MODIFIER"]
                Scheduler.DYNAMIC_DASHBOARD_SIZE = CONFIG["configuration"]["DYNAMIC_DASHBOARD_SIZE"]
                Scheduler.SCAN_KILL_PENDING_WAIT = CONFIG["configuration"]["SCAN_KILL_PENDING_WAIT"]
                Scheduler.SCAN_KILL_PENDING_REFRESH = CONFIG["configuration"]["SCAN_KILL_PENDING_REFRESH"]
                Scheduler.FEATURE_LOADER_PARALLEL_REFRESHRATE = CONFIG["configuration"]["FEATURE_LOADER_PARALLEL_REFRESHRATE"]
                Scheduler.RECOVERY_FILE = CONFIG["configuration"]["RECOVERY_FILE"]
                Scheduler.TRACK_STATE_FILE = CONFIG["configuration"]["TRACK_STATE_FILE"]
                Scheduler.TRACK_TARGET_STATE_REFRESHRATE = CONFIG["configuration"]["TRACK_TARGET_STATE_REFRESHRATE"]
                Scheduler.MERGED_SCAN_FILE = CONFIG["configuration"]["MERGED_SCAN_FILE"]
                Scheduler.NO_SCANS_FILE = CONFIG["configuration"]["NO_SCANS_FILE"]
                Scheduler.ONLY_SCANS_FILE = CONFIG["configuration"]["ONLY_SCANS_FILE"]
                Scheduler.ORIGINAL_COLORS = CONFIG["configuration"]["ORIGINAL_COLORS"]
                # Store parameter sets
                self.parameterSets = CONFIG["parameterSets"]
        except:
            pass

    #Merge scan results into one xml / html
    def mergeScanResults(self):
        if Scheduler.NO_SCANS_FILE: return
        templateHead='''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<?xml-stylesheet href="file:///usr/bin/../share/nmap/nmap.xsl" type="text/xsl"?>
<nmaprun scanner="nmapUnleashed" args="<<command>>" start="1770144034" startstr="<<starttime>>" version="7.94SVN" xmloutputversion="1.05">'''
        templateTail='''</nmaprun>'''
        hosthint = []
        host = []
        #load each xml and extract hosthint and host elements
        for targetID in range(len(self.TARGETS)):
            # Create path to scans xml file
            fileName = self.createFilename(self.targetsStats[targetID]["target"])
            # If option is not disabled prepand folder for scan based on filename
            path = os.getcwd()
            if not Scheduler.NO_FOLDER_PER_SCAN and os.path.exists(f'{path}/{fileName}'):
                path = f'{path}/{fileName}'
            file = f'{path}/{fileName}.xml'
            # Load as xml and extract elements
            xml = ET.parse(file)
            for element in xml.getroot():
                if element.tag == "hosthint":
                    hosthint.append(ET.tostring(element).decode('utf8'))
                if element.tag == "host":
                    host.append(ET.tostring(element).decode('utf8'))
        # create merged xml file
        ##parts from dashboard command
        ###really stupid, i know. Makes it more compatible for older python versions
        stupidQuote = "'" #need to use single quotes here even when double were used, otherwise xml breaks
        stupidNewline = '\n'
        command =  f'nmapUnleashed {" ".join([var if "=" not in var else stupidQuote + var + stupidQuote for var in sys.argv[1:]])}{"" if not self.options["parameterSet"] else " | {" + self.options["parameterSet"] + ": " + self.parameterSets[self.options["parameterSet"]] + "}"}'
        mergedXml = f'{templateHead.replace("<<command>>", command).replace("<<starttime>>", self.timeStart.strftime(Scheduler.DATETIME_STR_FORMAT))}{stupidNewline.join(map(str, hosthint))}{stupidNewline}{stupidNewline.join(map(str, host))}{templateTail}'
        with open(f'{Scheduler.MERGED_SCAN_FILE}.xml', "w") as file:
            file.write(mergedXml)
        # Use xsltproc to create html version of merged scan file
        processConvert = subprocess.Popen(["xsltproc", "-o", f'{Scheduler.MERGED_SCAN_FILE}.html', f'{Scheduler.MERGED_SCAN_FILE}.xml'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=os.getcwd())
        processConvert.wait()
        # Patch html to nmapUnleashed style
        if Scheduler.ORIGINAL_COLORS: return
        patched = ""
        with open(f'{Scheduler.MERGED_SCAN_FILE}.html', "r") as file:
            patched = file.read()
        #change headline
        patched = patched.replace('Nmap Scan Report', "nmapUnleashed Scan Report")
        #change main header color
        patched = patched.replace('#2A0D45', "#069aeb")
        #change section header color
        patched = patched.replace('#E1E1E1', "#02f4ce")
        #change background color
        patched = patched.replace('#CCFFCC', "#8cd8fe")
        with open(f'{Scheduler.MERGED_SCAN_FILE}.html', "w") as file:
            file.write(patched)




def checkDependencies():
    pkgs = ["nmap", "xsltproc", "grep"]
    for pkg in pkgs:
        if shutil.which(pkg) is None:
            print(f'Missing Package: {pkg} is not installed on the system and is required for nmapUnleashed.')
            sys.exit(1)

###Main
########################################################################################################################
########################################################################################################################
########################################################################################################################
if __name__ == '__main__':
    checkDependencies()
    typer.run(main)

def entry():
    checkDependencies()
    typer.run(main)

![Banner](assets/banner.png)
[![Home](https://img.shields.io/badge/🏠-Home-069aeb?labelColor=01cef4)](https://github.com/sharkeonix/nmap-unleashed/)
[![Installation and Requirements](https://img.shields.io/badge/📦-Installation-069aeb?labelColor=01cef4)](https://github.com/sharkeonix/nmap-unleashed/#-installation-and-requirements)
[![Quick Usage and Examples](https://img.shields.io/badge/🚀-Quick_Usage-069aeb?labelColor=01cef4)](https://github.com/sharkeonix/nmap-unleashed/#-quick-usage-and-examples)
[![Commands and Options](https://img.shields.io/badge/🧰-Commands-069aeb?labelColor=01cef4)](https://github.com/sharkeonix/nmap-unleashed/#-commands-and-options)
[![Docs](https://img.shields.io/badge/📚-Docs-069aeb?labelColor=01cef4)](https://docs.nmap-unleashed.com)
[![Changelog](https://img.shields.io/badge/📜-Changelog-069aeb?labelColor=01cef4)](https://github.com/sharkeonix/nmap-unleashed/#-changelog)
[![License](https://img.shields.io/badge/📄-Dual--License-069aeb?labelColor=01cef4)](https://license.nmap-unleashed.com)

# [nmapUnleashed Docs](/docs/README.md)

## 🚀 Quick Usage and Examples

nmapUnleashed is intended to feel familiar to [Nmap](https://nmap.org/) users while adding scan management and productivity features.

After nmapUnleashed finishes, a `dashboard.txt` file is generated containing a complete overview of all performed scans, results, and statuses.

_Config file location: `~/.config/nmapUnleashed/nmapUnleashed.conf`_

**Basic Scan**
```bash
# Classic Nmap scan of all ports with version detection.
nu -d -p- -A scanme.nmap.org
```

**Powerfull target loading and custom multithreading**
```bash
# Scan multiple targets specified as IPs, CIDRs, or files in 8 parallel scans.
nu -th 8 -p- -A scanme.nmap.org 192.168.178.0/24 targets.txt
```

**Using predefined parameter sets / presets (nmap and unleashed parameter)**
```bash
# Define parameter sets / presets, in config, and load any set with a single command to start scans faster.
# Example: {'basic': '-d -p- -A', 'basic-offline': '-d -p- -A -Pn', 'safe': '-th 8 -kt 120 -d -p - -sV --exclude-ports 9100 --exclude localhost', 'default': '-th 4 -kt 120 --exclude localhost -nwr 5000 -nwt 5000 -d -p- -A'}
nu -ps basic scanme.nmap.org
```

**Parallel scans with auto-abort and bandwitdh usage warning**
```bash
# 8 threads, auto-abort after 120 min, warn if network >1000 KBps, keep files for non-online targets.
nu -th 8 -kt 120 -nwr 1000 -nwt 1000 -ko -p- -sV scanme.nmap.org
```

**Scan output and files configuration**
```bash
# Keep scan files for non-online targets, store all scans in the current folder, remove specified file types after scan.
nu -ko -nf -rf "xml;html;gnamp" -p- -A fd12:3456:789a::/28
```

**Define targets and networks, exclude specific targets and set individual nmap parameters**
```bash
# Specify Nmap parameters and targets, set custom parameters for a target network, and exclude one target of the specified network.
nu -p- -A 10.10.2.1 10.10.02.2 "10.10.1.0/24=--top-ports 100 -A" -ex 10.10.1.5
```

<br>

---

> [!NOTE]
> At the end of each quarter, there is a patch day. During this release, all accumulated [features](https://github.com/Sharkeonix/nmap-unleashed/issues?q=state%3Aopen%20label%3Afeature) and [bugs](https://github.com/Sharkeonix/nmap-unleashed/issues?q=state%3Aopen%20label%3Apatchday) are implemented and released together.
> Only [hotfixes](https://github.com/Sharkeonix/nmap-unleashed/issues?q=state%3Aopen%20label%3Ahotfix) and critical bugs are addressed before the scheduled patch day.

![Banner](/docs/assets/banner.png)
[![Home](https://img.shields.io/badge/🏠-Home-069aeb?labelColor=01cef4)](https://github.com/sharkeonix/nmap-unleashed/)
[![Installation and Requirements](https://img.shields.io/badge/📦-Installation-069aeb?labelColor=01cef4)](https://github.com/sharkeonix/nmap-unleashed/#-installation-and-requirements)
[![Quick Usage and Examples](https://img.shields.io/badge/🚀-Quick_Usage-069aeb?labelColor=01cef4)](https://github.com/sharkeonix/nmap-unleashed/#-quick-usage-and-examples)
[![Commands and Options](https://img.shields.io/badge/🧰-Commands-069aeb?labelColor=01cef4)](https://github.com/sharkeonix/nmap-unleashed/#-commands-and-options)
[![Docs](https://img.shields.io/badge/📚-Docs-069aeb?labelColor=01cef4)](https://docs.nmap-unleashed.com)
[![Changelog](https://img.shields.io/badge/📜-Changelog-069aeb?labelColor=01cef4)](https://github.com/sharkeonix/nmap-unleashed/#-changelog)
[![License](https://img.shields.io/badge/📄-Dual--License-069aeb?labelColor=01cef4)](https://license.nmap-unleashed.com)
# nmapUnleashed (nu)

![Version](https://img.shields.io/badge/version-v1.1.1-brightgreen)
![Status](https://img.shields.io/badge/status-stable-brightgreen)
![Python](https://img.shields.io/badge/python-3.11+-yellow)
![Platform](https://img.shields.io/badge/platform-linux-yellow)
[![License](https://img.shields.io/badge/License-Free/Commercial-red?labelColor=grey)](/LICENSE.md)

**nmapUnleashed (nu)** is a modern CLI wrapper for [Nmap](https://nmap.org/), designed to make network scanning more comfortable and effective. Nmap is THE tool for penetration testing and network auditing, you can use `nu` just like Nmap with all its familiar commands but with extended features such as multithreading, easy scan management, and improved overview of your scans and more.

![Dashboard](/docs/assets/dashboard.png)

**Contents**
- [✨ Feature Summary](/#-feature-summary)
- [📦 Installation and Requirements](/#-installation-and-requirements)
- [🚀 Quick Usage and Examples](/#-quick-usage-and-examples)
- [🧰 Commands and Options](/#-commands-and-options)
- [🎬 Showcase](/#-showcase)
- [📄 License](https://license.nmap-unleashed.com)
- [🤝 Contributing and Contact](/#-contributing--credits-and-contact)
- [📜 Changelog](/#-changelog)

<br>

> This software is free for personal and small-company use (<50 employees).<br>
> Commercial use requires a license. See [license](https://license.nmap-unleashed.com) or contact sharkeonix@pm.me.

<br>

---

<br>

### ✨ Feature Summary

- **Modern Nmap wrapper — all Nmap commands, but extended**  
  Use `nu` exactly like [Nmap](https://nmap.org/) while benefiting from additional usability improvements and sensible defaults combined in an appealing CLI-dashboard.

- **Multithreading**  
  Run scans in parallel and tune concurrency to fit your environment and network bandwidth.

- **Easy scan management — appealing overview & live inspection**  
  Manage queued/active/completed scans, open live results, and get a clear summary view.

- **Network usage monitor**  
  See throughput and progress in real time to balance speed and network impact including custom warning thresholds.

- **Automatic & manual abort of scans**  
  Set automatic timeouts for long-running jobs or abort scans manually to avoid runaway tasks.

- **Powerful target specification loader**  
  Import targets from files, CIDR ranges, host patterns, and combine multiple sources effortlessly.

- **Parameter sets / presets**  
  Define parameter sets / presets and load any set with a single command to start scans faster.

- **Persistent dashboard and scan summary**  
  After nmapUnleashed finishes, a `dashboard.txt` file is generated containing a complete overview of all performed scans and their statuses.<br>
  Also, all scan results are merged into `scans.xml` and `scans.html`, for centralized inspection and post-processing.

- **…and more**  
  Check out the [docs](https://docs.nmap-unleashed.com) and help page for all features.

<br>

---

<br>

### 📦 Installation and Requirements

**Required Installed Packages** (Already installed on Kali)

- `nmap`
- `xsltproc`
- `grep`

~~~bash
sudo apt install -y nmap xsltproc grep
~~~

#### Quick Install using pipx

~~~bash
pipx ensurepath
pipx install git+https://github.com/sharkeonix/nmap-unleashed.git
# now "nu" and "nmapUnleashed" are available
~~~

_**Offline: Quick Install using pipx**_
~~~bash
cd ./nmap-unleashed #where nmap-unleashed is the repository
pipx ensurepath
pipx install
# now "nu" and "nmapUnleashed" are available
~~~

<br>

---

<br>

### 🚀 Quick Usage and Examples

nmapUnleashed is intended to feel familiar to [Nmap](https://nmap.org/) users while adding scan management and productivity features.

After nmapUnleashed finishes, a `dashboard.txt` file is generated containing a complete overview of all performed scans and their statuses.<br>
Also, all scan results are merged into `scans.xml` and `scans.html`, for centralized inspection and post-processing.

_Config file location: `~/.config/nmapUnleashed/nmapUnleashed.conf`_

**Basic Scan**
```bash
# Classic Nmap scan of all ports with version detection.
nu -d -p- -A scanme.nmap.org
```

**Powerfull target loading and custom multithreading**
```bash
# Scan multiple targets specified as IPs, CIDRs, or files in 8 parallel scans and only create merged scan results (scans.xml, scans.html).
nu -th 8 -p- -A scanme.nmap.org 192.168.178.0/24 targets.txt -os
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
nu -p- -A 10.10.2.1 10.10.2.2 "10.10.1.0/24=--top-ports 100 -A" -ex 10.10.1.5
```

<br>

---

<br>

### 🧰 Commands and Options
nmapUnleashed provides a set of options which are briefly described down below, these extend the normal option set of [Nmap](https://nmap.org/).
For the official Nmap parameters, that nmapUnleashed inheritates, please checkout the official [Nmap docs](https://nmap.org/book/man.html).
For permanent changes the [config file](/docs/configuration-and-presets.md) can be edited.
For detailed information please visit the ![docs](https://docs.nmap-unleashed.com).

_(Only `-v`, `-iL`, `-oN`, `-oX`, `-oS`, `-oG` and `-oA` are not available as these functions are handeld through nmapUnleashed.)_

After nmapUnleashed finishes, a `dashboard.txt` file is generated containing a complete overview of all performed scans and their statuses.<br>
Also, all scan results are merged into `scans.xml` and `scans.html`, for centralized inspection and post-processing.

#### Usage

```bash
Usage: nmapUnleashed [OPTIONS] [TARGETS]...
```

#### Arguments

**`[TARGETS]...`** — Specify one or more targets for the scan.  

Targets can be:

- Single IP addresses (e.g., `192.168.1.1` or `fd12:3456:789a::`)  
- CIDR ranges (e.g., `10.0.0.0/24` or `fd12:3456:789a::/28`)  
- Hostnames / DNS names (e.g., `scanme.nmap.org`)  
- Files containing one target per line (e.g., `targets.txt`)

You can also assign custom Nmap parameters per target using the syntax:
"`<target>=<nmapParameter>`"

#### Scan Options
| Option                 |  Value Type | Default Value | Description                                                                                     |
|------------------------|:-----------:|:-------------:|-------------------------------------------------------------------------------------------------|
| `-th` /<br> `--threads`        |  \<number\> |       4       | Number of threads (max parallel scans).                                                         |
| `-ps` /<br> `--parameter-set`  |    \<id\>   |      None     | Apply a predefined parameter set / preset (nmap and unleashed parameter) from config, merged with parameters given at runtime. |
| `-kt` /<br> `--kill-threshold` | \<minutes\> |      None     | Automatically abort a scan if it reaches the specified runtime.                                 |
| `-ex` /<br> `--exclude`        |  \<target\> |      None     | Exclude passed target(s) (IP, CIDR, DNS, File) from target list.                                |

#### Dashboard Options
| Option                            |    Value Type    | Default Value | Description                                                           |
|-----------------------------------|:----------------:|:-------------:|-----------------------------------------------------------------------|
| `-nwr` /<br> `--network-warning-receive`  | \<integerInKBp\> |       0       | Warn if incoming network traffic reaches defined KBps (0 to disable). |
| `-nwt` /<br> `--network-warning-transmit` | \<integerInKBp\> |       0       | Warn if outgoing network traffic reaches defined KBps (0 to disable). |
| `-fs` /<br> `--fixed-size`                |        N/A       |     False     | Keep the dashboard size fixed.                                        |

#### Output Options
| Option                 |      Value Type     | Default Value | Description                                                                                           |
|------------------------|:-------------------:|:-------------:|-------------------------------------------------------------------------------------------------------|
| `-ko` /<br> `--keep-offline`    |          N/A        |      False    | Preserve scan files for non-online targets; they are always listed in dashboard.txt.                                       |
| `-rf` /<br> `--remove-files`    | \<listOfFileTypes\> |      None     | Delete specified scan files after completion (e.g., "xml" or "xml;gnmap").                                                 |
| `-nf` /<br> `--no-folder`       |          N/A        |      False    | Store all scan files in the current directory instead of creating a subfolder per scan.                                    |
| `-op` /<br> `--output-pattern`  | \<outputPattern\>   | {target}      | Set the naming pattern for scan files and folders (e.g., {target}_{parameter});{target} is mandatory.                      |
| `-nd` /<br> `--no-dashboard`    |          N/A        |      False    | Do not create the dashboard.txt file (holding an overview over performed scans and their states).                          |
| `-ns` /<br> `--no-scans`        |          N/A        |      False    | Do not create the scans.xml and scans.html file (holding the merged scan results).                                         |
| `-os` /<br> `--only-scans`      |          N/A        |      False    | Only create the scans.xml and scans.html file (holding the merged scan results) and no files for each individual scan.     |
| `-oc` /<br> `--original-colors` |          N/A        |      False    | Do not tamper the scans.html and keep nmap's original color scheme.                                                        |

#### Misc Options
| Option               |           Value Type          | Default Value | Description                                                                                        |
|----------------------|:-----------------------------:|:-------------:|----------------------------------------------------------------------------------------------------|
| `-c` /<br> `--config`        | "\<configKey\>:\<value\>;..." |      None     | Temporarily adjust configuration settings for this run (adjust config file for permanent changes). |
| `-qm` /<br> `--quiet-mode`   |              N/A              |     False     | Enable quiet mode (no banner or version info).                                                     |
| `-sm` /<br> `--silence-mode` |              N/A              |     False     | Enable silent mode (suppress all terminal output).                                                 |
| `-v` /<br> `--version`       |              N/A              |      N/A      | Display nmapUnleashed version.                                                                     |
| `-h` /<br> `--help`         |              N/A              |      N/A      | Display help message.                                                                              |

<br>

---

<br>

### 🎬 Showcase

_Detailed information for the dashboard: [📊 Dashboard Overview](https://docs.nmap-unleashed.com/dashboard-overview)_

#### Dashboard

The nmapUnleashed dashboard provides a clear, real-time overview of all scans.  
It displays queued, active, aborted and completed scans, allows live inspection of results and manual aborting of scans, and monitors network usage and performance at a glance, helping you manage multiple scans efficiently.
The dashboard is also outputted with all final results as `dashboard.txt`, holding information on all performed scans.

![Dashboard](/docs/assets/dashboard.png)

#### Live Results

Navigate through scans in real-time using the arrow keys (`↑`, `↓`), `ENTER` to view details, `q` / `ESC` to quit detailed view, and `k` to manually abort a scan if it’s taking too long.  
(DISCLAIMER: During active [Nmap](https://nmap.org/) scans, only port information is available; service and version details appear after the scan completes.)

![Dashboard](/docs/assets/service.png)

<br>

---

<br>

### 🤝 Contributing / Credits and Contact
_The process and possibilities for contribution will be announced soon._

<br>

**Credits**

Special thanks to the beta testers for their participation and feedback, among them were
- Anton Kettling, wandton


**Contact**

sharkeonix@pm.me

<br>

---

<br>

### 📜 Changelog
| Version | Release Date | Description                                                                                                                                                                                                               |
|---------|--------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| v1.1.1  | 08.02.2026   | Quickfix. Aborted scans don't have a proper xml file which made the merge scans feature crash. Custom xml elements are now added so aborted scans are listed in scans.xml and scans.html with note that scan was aborted. |
| v1.1.0  | 03.02.2026   | Adding merged scans feature (`scans.xml`, `scans.html`) and relating options (`-ns`, `-os`, `-oc`).                                                                                                                       |
| v1.0.0  | 31.01.2026   | Official Release                                                                                                                                                                                                          |

<br>

---

<br>

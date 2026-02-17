![Banner](assets/banner.png)
[![Home](https://img.shields.io/badge/🏠-Home-069aeb?labelColor=01cef4)](https://github.com/sharkeonix/nmap-unleashed/)
[![Installation and Requirements](https://img.shields.io/badge/📦-Installation-069aeb?labelColor=01cef4)](https://github.com/sharkeonix/nmap-unleashed/#-installation-and-requirements)
[![Quick Usage and Examples](https://img.shields.io/badge/🚀-Quick_Usage-069aeb?labelColor=01cef4)](https://github.com/sharkeonix/nmap-unleashed/#-quick-usage-and-examples)
[![Commands and Options](https://img.shields.io/badge/🧰-Commands-069aeb?labelColor=01cef4)](https://github.com/sharkeonix/nmap-unleashed/#-commands-and-options)
[![Docs](https://img.shields.io/badge/📚-Docs-069aeb?labelColor=01cef4)](https://docs.nmap-unleashed.com)
[![Changelog](https://img.shields.io/badge/📜-Changelog-069aeb?labelColor=01cef4)](https://github.com/sharkeonix/nmap-unleashed/#-changelog)
[![License](https://img.shields.io/badge/📄-Apache_2.0_License-069aeb?labelColor=01cef4)](https://license.nmap-unleashed.com)

# [nmapUnleashed Docs](/docs/README.md)

## 🧰 Commands and Options
nmapUnleashed provides a set of options which are briefly described down below, these extend the normal option set of [Nmap](https://nmap.org/).
For the official Nmap parameters, that nmapUnleashed inheritates, please checkout the official [Nmap docs](https://nmap.org/book/man.html).
For permanent changes the [config file](/docs/configuration-and-presets.md) can be edited.
For detailed information please visit the ![docs](/docs/README.md).

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
| `-ko` /<br> `--keep-offline`    |          N/A        |      False    | Preserve scan files for non-online targets; they are always listed in dashboard.txt.                  |
| `-rf` /<br> `--remove-files`    | \<listOfFileTypes\> |      None     | Delete specified scan files after completion (e.g., "xml" or "xml;gnmap").                            |
| `-nf` /<br> `--no-folder`       |          N/A        |      False    | Store all scan files in the current directory instead of creating a subfolder per scan.               |
| `-op` /<br> `--output-pattern`  | \<outputPattern\>   | {target}      | Set the naming pattern for scan files and folders (e.g., {target}_{parameter});{target} is mandatory. |
| `-nd` /<br> `--no-dashboard`    |          N/A        |      False    | Do not create the dashboard.txt file (holding an overview over performed scans and their states).     |
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

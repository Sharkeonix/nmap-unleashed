![Banner](assets/banner.png)
[![Home](https://img.shields.io/badge/🏠-Home-069aeb?labelColor=01cef4)](https://github.com/sharkeonix/nmap-unleashed/)
[![Installation and Requirements](https://img.shields.io/badge/📦-Installation-069aeb?labelColor=01cef4)](https://github.com/sharkeonix/nmap-unleashed/#-installation-and-requirements)
[![Quick Usage and Examples](https://img.shields.io/badge/🚀-Quick_Usage-069aeb?labelColor=01cef4)](https://github.com/sharkeonix/nmap-unleashed/#-quick-usage-and-examples)
[![Commands and Options](https://img.shields.io/badge/🧰-Commands-069aeb?labelColor=01cef4)](https://github.com/sharkeonix/nmap-unleashed/#-commands-and-options)
[![Docs](https://img.shields.io/badge/📚-Docs-069aeb?labelColor=01cef4)](https://docs.nmap-unleashed.com)
[![Changelog](https://img.shields.io/badge/📜-Changelog-069aeb?labelColor=01cef4)](https://github.com/sharkeonix/nmap-unleashed/#-changelog)
[![License](https://img.shields.io/badge/📄-Apache_2.0_License-069aeb?labelColor=01cef4)](https://license.nmap-unleashed.com)

# [nmapUnleashed Docs](/docs/README.md)

## ⚙️ Configuration and Presets

nmapUnleashed uses a configuration file at `~/.config/nmapUnleashed/nmapUnleashed.conf` to define global settings and reusable presets to fine tune nmapUnleashed's beahviour and speed up scan workflows.

The configuration file allows you to:
- Define **parameter sets** with catchy names containing both Nmap and nmapUnleashed options  
- Store **global configuration variables** that control the behavior of the tool  

Configuration values can also be **overridden at runtime for current execution** using the `-c` / `--config` option, allowing temporary changes without modifying the configuration file.

For example the parameter sets and their names can be defined in the relating section inside the config file as dictionary entries
> //// Default Parameter sets<br>
> //--------------------------------------------------<br>
> "parameterSets":    {<br>
>         "basic": "-d -p- -A",<br>
>         "basic-offline": "-d -p- -A -Pn",<br>
>         "safe": "-th 2 -kt 120 -d -p - -sV --exclude-ports 9100 --exclude localhost",<br>
>         "default": "-th 4 -kt 120 --exclude localhost -nwr 5000 -nwt 5000 -d -p- -A"<br>
>     },<br>
> //--------------------------------------------------

<br>

Different configurations relating to the behaviour of nmapUnleashed and it's dashboard can be done via the "Dashboard and Backend Configuration" section in the config file.

<br>

---

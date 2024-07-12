# Windows Memory Analysis Report

## Introduction

This repository contains the findings from a memory analysis conducted on a Windows 10 system suspected of being compromised. The analysis was performed using Volatility and other forensic tools.

## Table of Contents

1. [Introduction](#introduction)
2. [Process Analysis](#process-analysis)
3. [Suspicious IP Connections](#suspicious-ip-connections)
4. [Malware Identification](#malware-identification)
5. [Urgent Findings](#urgent-findings)
6. [Conclusion](#conclusion)
7. [Recommendations](#recommendations)

## Process Analysis

### Suspicious IP Connections with Chrome.exe

- 74.125.206.188:5228 (static IP, datacenter)
- 142.251.168.188:5228 (static IP, datacenter)
- 192.229.221.95:80

[Chrome.exe VirusTotal Report](https://www.virustotal.com/gui/file/311e6f805f5f0ca710e41276b905afe4e66d04df95c4bf9e04d590885f157441/details)

### Service Analysis

[Service VirusTotal Report](https://www.virustotal.com/gui/file/f878b9cdef26f4c46e1babda40acc15ffb0a7eaca9312e49ed0ee8566574954a/behavior)

## Malware Identification

### Possibly Malware Found: MFResident.exe

- **Hash:** 00D4A7FF3FFE03712CF3C62D695D1E19975881313A0E702CB4BB39A112B42E2F
- **Path:** C:\Program Files (x86)\Common Files\iMyFone\Components\Resident\MFResident.exe
- **Installed by:** iMyFone

#### URLs and Details

- https://accountapi.imyfone.com
- UserDetail.json
- /v2/reside-message
- /v2/reside-uninstall-message

[MFResident.exe VirusTotal Report](https://www.virustotal.com/gui/file/56f03bda112a6eebc4513280728fac74eaf3fd10ef25ebdd1a5ee47e4715e57d/behavior)

### Parent Process

- **Parent Process ID:** LocalService.exe
- **Hash:** FDB9FEC2A2809B72C4897955EAA4B960BBC46C183EE15ED706F66DB4E3D46484

## Urgent Findings

### Volatility Handle Plugin

#### SearchTextHarvester

```plaintext
 vol -f DESKTOP-C5IQLQB-20240710-110534.dmp windows.handles | grep "SearchTextHarvester"
```

#### Conclusion
This memory analysis has revealed several suspicious activities and potential indicators of compromise on the system. The identified suspicious IP connections, potentially malicious files, and other findings warrant further investigation to confirm any malicious intent and to take appropriate remediation actions.

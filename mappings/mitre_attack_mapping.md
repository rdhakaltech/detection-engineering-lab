# MITRE ATT&CK Mapping

## Overview

This file maps the lab detections to relevant MITRE ATT&CK techniques. The mappings are intended for educational and portfolio use and should be validated against an organization's telemetry, threat model, and detection requirements before production use.

## Detection-to-Technique Mapping

| Detection | Technique ID | Technique Name | Explanation |
| --- | --- | --- | --- |
| Windows 4688 Encoded PowerShell Execution | T1059.001 | Command and Scripting Interpreter: PowerShell | The detection identifies suspicious PowerShell command-line execution using process creation telemetry. |
| Windows 4688 Encoded PowerShell Execution | T1027 | Obfuscated Files or Information | Encoded PowerShell commands can hide the true command content from analysts and simple pattern matching. |
| Windows 4688 Encoded PowerShell Execution | T1140 | Deobfuscate/Decode Files or Information | Encoded commands are commonly decoded at runtime before execution. |
| Windows 4688 Encoded PowerShell Execution | T1055 | Process Injection | PowerShell may be used as a staging mechanism before memory-based execution, though this detection alone does not prove injection. |
| Suspicious Command-Line Binary Patterns | T1105 | Ingress Tool Transfer | Native binaries such as `certutil` and `bitsadmin` can be used to retrieve files from remote locations. |
| Suspicious Command-Line Binary Patterns | T1197 | BITS Jobs | `bitsadmin` can create Background Intelligent Transfer Service jobs for file transfer. |
| Suspicious Command-Line Binary Patterns | T1218.005 | System Binary Proxy Execution: Mshta | `mshta.exe` can execute malicious HTA files or inline script content. |
| Suspicious Command-Line Binary Patterns | T1218.011 | System Binary Proxy Execution: Rundll32 | `rundll32.exe` can execute DLL exports or abuse script-related components. |
| Suspicious Command-Line Binary Patterns | T1027 | Obfuscated Files or Information | Encoding, decoding, and indirect execution can be used to obscure attacker intent. |

## Technique Details

### T1059.001 - Command and Scripting Interpreter: PowerShell

PowerShell is frequently used by administrators and attackers. Suspicious flags such as `-EncodedCommand`, `-NoProfile`, and hidden execution can indicate an attempt to run commands stealthily or bypass simple controls.

### T1027 - Obfuscated Files or Information

Attackers may encode, compress, encrypt, or otherwise obfuscate commands and payloads to make detection and analysis harder. Encoded PowerShell is a common example.

### T1140 - Deobfuscate/Decode Files or Information

Encoded commands often need to be decoded before execution. PowerShell can decode and execute content directly in memory, which may reduce visible artifacts on disk.

### T1055 - Process Injection

PowerShell can be used in attack chains that lead to memory-based execution. This lab detection does not directly detect injection, but suspicious PowerShell should be reviewed for follow-on behavior that may indicate process injection.

### T1105 - Ingress Tool Transfer

Attackers may transfer tools, payloads, or scripts into a target environment using built-in utilities. `certutil` and `bitsadmin` are commonly observed in download-related tradecraft.

### T1197 - BITS Jobs

BITS can transfer files in the background and may be abused to download payloads or maintain persistence through transfer jobs.

### T1218.005 - System Binary Proxy Execution: Mshta

`mshta.exe` is a trusted Windows binary that can execute HTA files and script content. Attackers may use it to proxy execution through a signed Microsoft binary.

### T1218.011 - System Binary Proxy Execution: Rundll32

`rundll32.exe` is a trusted Windows binary that executes DLL exports. Attackers may abuse it to execute malicious DLLs or scriptlet-related payloads.

## Notes For Production Use

- Validate field names against the target SIEM schema.
- Review known administrative workflows before enabling high-severity alerting.
- Tune detections using known-good parent processes, service accounts, software paths, and approved update infrastructure.
- Pair process detections with network, file, registry, and authentication telemetry for higher confidence.

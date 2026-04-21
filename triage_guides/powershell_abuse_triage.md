# PowerShell Abuse Triage Guide

## Purpose

This guide provides a practical workflow for investigating alerts related to suspicious PowerShell execution, including encoded commands, hidden windows, inline execution, and unusual parent-child process relationships.

All examples assume simulated lab data or generic endpoint telemetry.

## Investigation Steps

### 1. Validate the Alert Context

- Confirm the alert timestamp, host, user, process name, and command line.
- Verify whether the event came from Windows Event ID 4688, EDR telemetry, or another process creation source.
- Check whether command-line logging is complete or truncated.
- Identify whether PowerShell was executed as `powershell.exe`, `pwsh.exe`, or another renamed binary.

### 2. Review the Full Command Line

- Look for encoded command flags such as `-enc` or `-encodedcommand`.
- Look for execution control flags such as `-nop`, `-noprofile`, `-executionpolicy bypass`, or `-w hidden`.
- Look for inline execution patterns such as `iex`, `invoke-expression`, or download cradles.
- Identify URLs, IP addresses, suspicious file paths, base64 strings, or unusual environment variable usage.

### 3. Decode Encoded Content Safely

- Decode base64 content in an isolated analysis environment.
- Confirm whether the encoded content uses UTF-16LE, which is common for PowerShell encoded commands.
- Do not execute decoded content.
- Extract indicators such as domains, IP addresses, file names, registry paths, and script functions.

### 4. Analyze Parent and Child Processes

- Review the parent process that launched PowerShell.
- Treat Office applications, browsers, email clients, archive utilities, and script engines as higher-risk parents.
- Review child processes spawned by PowerShell.
- Look for follow-on execution such as `cmd.exe`, `rundll32.exe`, `regsvr32.exe`, `mshta.exe`, `wscript.exe`, or unknown executables.

### 5. Review User and Host Context

- Determine whether the user normally performs administrative work.
- Check whether the host is a workstation, server, domain controller, or privileged admin system.
- Review recent login activity for the same user.
- Identify whether the account has elevated privileges.

### 6. Correlate With Network Activity

- Search proxy, DNS, firewall, and EDR network telemetry for connections near the PowerShell execution time.
- Look for newly observed domains, direct IP connections, dynamic DNS, paste sites, file-sharing services, or suspicious user agents.
- Confirm whether downloaded content was saved to disk or executed in memory.

### 7. Correlate With File and Persistence Activity

- Look for files written to user-writable locations such as Downloads, Desktop, AppData, Temp, or ProgramData.
- Review scheduled task creation, service creation, registry run keys, startup folder writes, and WMI persistence.
- Search for script files such as `.ps1`, `.vbs`, `.js`, `.hta`, `.bat`, and `.cmd`.

## What To Look For

- Encoded commands that decode to download or execution logic
- PowerShell launched by Office documents or email clients
- Hidden window execution
- Execution policy bypass
- Suspicious URLs or IP addresses
- Newly created files in temporary directories
- Credential access commands
- Discovery commands such as `whoami`, `hostname`, `net user`, `nltest`, `ipconfig`, or `systeminfo`
- Lateral movement preparation such as remote service creation or admin share access
- Repeated execution across multiple hosts

## Correlation Ideas

- PowerShell execution followed by outbound network connections
- PowerShell execution followed by file creation in user-writable directories
- PowerShell execution followed by suspicious child processes
- Encoded PowerShell on a host with recent suspicious authentication activity
- Multiple hosts running similar encoded commands
- Same user executing PowerShell from unusual locations or at unusual times
- PowerShell activity followed by endpoint detection alerts

## When To Escalate

Escalate the alert when one or more of the following are true:

- The decoded command downloads or executes remote content.
- PowerShell was launched by an Office application, browser, email client, or archive utility.
- The command includes credential access, persistence, or lateral movement behavior.
- The host is a sensitive system or belongs to a privileged user.
- The user cannot explain the activity.
- Similar activity appears across multiple hosts.
- The command uses known suspicious infrastructure.
- The activity is followed by malware detections, blocked connections, or suspicious file creation.

## Initial Response Actions

- Preserve relevant logs and endpoint telemetry.
- Collect the suspicious command line and decoded script content.
- Capture process tree details.
- Identify related files and network indicators.
- Scope for the same command, URL, hash, parent process, or user across the environment.
- Consider isolating the endpoint if active compromise is suspected.

# Windows 4688 Encoded PowerShell Execution

## Title

Windows Event ID 4688 - Encoded or Obfuscated PowerShell Execution

## Goal

Detect suspicious PowerShell process creation events that may indicate command obfuscation, payload execution, defense evasion, or script-based attacker activity.

## Data Source

- Windows Security Event Log
- Event ID 4688 - Process Creation
- Endpoint detection telemetry with process command-line capture

Recommended fields:

- `timestamp`
- `host`
- `user`
- `event_id`
- `process_name`
- `command_line`
- `parent_process_name`
- `parent_command_line`
- `process_id`
- `parent_process_id`

## Detection Logic

Trigger when a PowerShell process is created with command-line arguments commonly associated with suspicious execution:

- Encoded command usage: `-enc`, `-encodedcommand`
- No profile execution: `-nop`, `-noprofile`
- Hidden window execution: `-w hidden`, `-windowstyle hidden`
- Inline execution or download cradle behavior: `iex`, `invoke-expression`
- Suspicious combination of PowerShell flags in a single command line

This detection is stronger when multiple suspicious indicators appear in the same command line.

## Example SIEM Query

```sql
SELECT
  timestamp,
  host,
  user,
  process_name,
  command_line,
  parent_process_name,
  parent_command_line
FROM windows_process_events
WHERE event_id = 4688
  AND LOWER(process_name) IN ('powershell.exe', 'pwsh.exe')
  AND (
    LOWER(command_line) LIKE '% -enc %'
    OR LOWER(command_line) LIKE '% -encodedcommand %'
    OR LOWER(command_line) LIKE '% -nop %'
    OR LOWER(command_line) LIKE '% -noprofile %'
    OR LOWER(command_line) LIKE '% -w hidden%'
    OR LOWER(command_line) LIKE '% -windowstyle hidden%'
    OR LOWER(command_line) LIKE '%iex%'
    OR LOWER(command_line) LIKE '%invoke-expression%'
  );
```

## Why It Matters

PowerShell is a legitimate administrative tool, but it is also frequently abused by attackers because it is installed by default on Windows systems and provides access to scripting, memory execution, remote download, and system administration capabilities. Encoded or hidden PowerShell commands can indicate an attempt to avoid detection or obscure intent.

## False Positives

Possible benign sources include:

- Administrative scripts using encoded commands for compatibility
- Endpoint management platforms
- Software deployment tools
- IT automation frameworks
- Security testing tools used by authorized teams
- Internal scripts that run with `-NoProfile` for predictable behavior

## Tuning Ideas

- Allowlist known management servers and automation service accounts.
- Suppress approved scripts by hash, path, or signer when available.
- Raise severity only when multiple suspicious flags are present.
- Correlate with network connections, file writes, or child processes.
- Exclude known-good parent processes from software deployment tools.
- Alert only when the parent process is unusual, such as `winword.exe`, `excel.exe`, `outlook.exe`, browser processes, or archive utilities.

## MITRE ATT&CK Mapping

| Technique ID | Technique | Explanation |
| --- | --- | --- |
| T1059.001 | Command and Scripting Interpreter: PowerShell | Detects suspicious PowerShell execution through process command-line telemetry. |
| T1027 | Obfuscated Files or Information | Encoded PowerShell commands may be used to hide the intent of a command. |
| T1140 | Deobfuscate/Decode Files or Information | Encoded commands are often decoded at runtime before execution. |
| T1055 | Process Injection | PowerShell may be used as a staging mechanism before memory-based execution, depending on follow-on behavior. |

## Triage Steps

1. Review the full PowerShell command line.
2. Identify whether the command is encoded and decode it in a safe analysis environment.
3. Review the parent process and determine whether the execution chain is expected.
4. Check the user account, host role, and source of execution.
5. Correlate with network activity around the same timestamp.
6. Look for related file creation, registry modification, scheduled task creation, or service creation.
7. Determine whether the behavior matches known administrative tooling.
8. Escalate if the command downloads remote content, runs from an Office parent process, launches additional payloads, or uses suspicious external infrastructure.

## Severity

**Medium to High**

Severity should be treated as high when encoded PowerShell is launched from an unusual parent process, executes remotely downloaded content, or appears on a sensitive host.

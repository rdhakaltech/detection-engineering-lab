# Suspicious Command-Line Binary Patterns

## Title

Suspicious Use of Native Windows Binaries in Command-Line Activity

## Goal

Detect potentially malicious or unusual use of native Windows binaries that are commonly abused for file download, script execution, proxy execution, or defense evasion.

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

Trigger when one of the following binaries appears with suspicious command-line patterns:

- `certutil.exe`
  - Download behavior
  - URL usage
  - Encoding or decoding behavior
- `bitsadmin.exe`
  - File transfer job creation
  - Remote URL usage
- `mshta.exe`
  - Execution of remote HTA content
  - Inline script execution
- `rundll32.exe`
  - Suspicious script handlers
  - Unexpected DLL execution paths
  - URL-based or JavaScript-related invocation

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
  AND (
    (
      LOWER(process_name) = 'certutil.exe'
      AND (
        LOWER(command_line) LIKE '%http%'
        OR LOWER(command_line) LIKE '%urlcache%'
        OR LOWER(command_line) LIKE '%-decode%'
        OR LOWER(command_line) LIKE '%-encode%'
      )
    )
    OR (
      LOWER(process_name) = 'bitsadmin.exe'
      AND (
        LOWER(command_line) LIKE '%/transfer%'
        OR LOWER(command_line) LIKE '%http%'
        OR LOWER(command_line) LIKE '%download%'
      )
    )
    OR (
      LOWER(process_name) = 'mshta.exe'
      AND (
        LOWER(command_line) LIKE '%http%'
        OR LOWER(command_line) LIKE '%javascript:%'
        OR LOWER(command_line) LIKE '%vbscript:%'
      )
    )
    OR (
      LOWER(process_name) = 'rundll32.exe'
      AND (
        LOWER(command_line) LIKE '%javascript:%'
        OR LOWER(command_line) LIKE '%url.dll%'
        OR LOWER(command_line) LIKE '%scrobj.dll%'
        OR LOWER(command_line) LIKE '%http%'
      )
    )
  );
```

## Why It Matters

Attackers often use trusted operating system binaries to avoid introducing new files, bypass application controls, or blend into normal administrative activity. This behavior is commonly called living off the land. Detecting suspicious command-line usage helps identify early-stage intrusion activity, payload retrieval, and proxy execution.

## False Positives

Possible benign sources include:

- Software installation or update workflows
- IT troubleshooting activity
- Legacy administrative scripts
- Certificate management tasks using `certutil`
- Internal deployment jobs using BITS
- Vendor applications that invoke Windows binaries as part of normal operation

## Tuning Ideas

- Allowlist known software deployment paths and update servers.
- Require suspicious command-line arguments in addition to process name.
- Increase severity when the command includes an external URL.
- Increase severity when launched by Office applications, browsers, scripting engines, or archive utilities.
- Suppress expected certificate administration activity by approved administrators.
- Correlate with DNS, proxy, firewall, and file creation telemetry.
- Track command frequency per host and alert on rare usage.

## MITRE ATT&CK Mapping

| Technique ID | Technique | Explanation |
| --- | --- | --- |
| T1105 | Ingress Tool Transfer | `certutil` and `bitsadmin` may be used to download tools or payloads. |
| T1197 | BITS Jobs | `bitsadmin` can create background transfer jobs for payload retrieval. |
| T1218.005 | System Binary Proxy Execution: Mshta | `mshta.exe` can execute malicious HTA or script content. |
| T1218.011 | System Binary Proxy Execution: Rundll32 | `rundll32.exe` can execute malicious DLLs or scriptlet-related payloads. |
| T1027 | Obfuscated Files or Information | Encoding, decoding, or indirect execution may be used to obscure activity. |

## Triage Steps

1. Review the full command line and identify the suspicious binary.
2. Determine whether the command includes a URL, encoded content, script handler, or unusual DLL path.
3. Review the parent process and user context.
4. Check whether the host normally runs this binary.
5. Correlate with DNS, proxy, and firewall logs for external connections.
6. Look for downloaded files, temporary files, or newly created executables.
7. Review nearby process activity for follow-on execution.
8. Determine whether the activity aligns with approved IT operations.
9. Escalate if the command retrieves content from the internet, runs from a user-writable path, or is spawned by an unusual parent process.

## Severity

**Medium**

Severity should be raised to high when the command retrieves external content, launches from a suspicious parent process, or executes on a high-value host.

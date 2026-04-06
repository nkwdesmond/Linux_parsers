# 🐧 Linux Log Parsers (Python 🐍)

![Platform](https://img.shields.io/badge/platform-linux-gold)
![Python](https://img.shields.io/badge/python-3.x-blue)
![Status](https://img.shields.io/badge/status-active-darkgreen)
![Use Case](https://img.shields.io/badge/use--case-DFIR%20%7C%20Log%20Parsing-purple)

A collection of Python scripts to parse common Linux log files into structured CSV outputs for digital forensics analysis.

## 🔍 Overview

| Parser | Log Type | 
|--------|----------|
| parse_audit.py | audit.log |
| parse_authSecure.py | auth.log and secure |
| parse_bashHistory.py | .bash_history |
| parse_lastlog_passwd.py | lastlog |
| parse_syslogMessages.py | syslog and messages |
| parse_wtmp.py | wtmp |

## 📦 Parsers
<details>
<summary><strong>parse_audit.py</strong></summary>

- **Description:**
  - Parses Linux `audit.log` files into structured CSV format.
  - Extracts key audit fields and normalizes timestamps into a human-readable format (GMT+8).

- **Features:**
  - Supports both plain text and `.gz` compressed audit logs
  - Extracts important fields such as:
    - `epoch`
    - `timestamp_GMT+8`
    - `type`
    - `exe`
    - `uid`
    - `auid`
    - `syscall`
  - Preserves the original log line (cleaned) in a `data` column
  - Converts epoch timestamps to human-readable format with millisecond precision
  - Batch processing of multiple files in a directory

- **File parsed:**
  - `audit.log`
  - Variants supported:
    - `audit.log.N`
    - `audit.log.gz`
    - `audit.log.N.gz`
    - Custom variants like `audit.log_<suffix>.gz`

- **Auto detect file names in directory:**
  - Yes
  - Matches files using pattern:
    - `audit.log*` (including numbered, suffixed, and `.gz` files)

- **Default output file name:**
  - Input file name appended with `.csv`
  - Examples:
    - `audit.log` → `audit.log.csv`
    - `audit.log.1.gz` → `audit.log.1.gz.csv`

- **Default output file location:**
  - Same directory as input file

- **Output timezone:**
  - GMT+8
  - Original epoch timestamp is also preserved

- **Flags:**
  - `-f`, `--file`
    - Parse a single audit log file
  - `-d`, `--dir`
    - Parse all matching audit log files in a directory
  - Notes:
    - Flags are mutually exclusive (must use either `-f` or `-d`)

- **Usage:**
  - Parse a single file:
    ```bash
    parse_audit.py -f audit.log
    ```
  - Parse a compressed file:
    ```bash
    parse_audit.py -f audit.log.1.gz
    ```
  - Parse all audit logs in a directory:
    ```bash
    parse_audit.py -d /path/to/audit_logs/
    ```

</details>


<details>
<summary><strong>parse_authSecure.py</strong></summary>

- **Description:**
  - Parses Linux authentication logs (`auth.log` and `secure`) into structured CSV format.
  - Supports both traditional syslog format and ISO 8601 timestamps.
  - Extracts authentication-related details such as user, IP address, port, method, and login result.

- **Features:**
  - Supports both plain text and `.gz` compressed log files
  - Automatically detects and parses:
    - Syslog format (e.g., `Jan 10 12:34:56`), with the year being inferred from the modified time of the file
    - ISO 8601 format (e.g., `2024-01-10T12:34:56+00:00`)
  - Extracts authentication details:
    - `user`
    - `ip`
    - `port`
    - `method` (password, publickey, keyboard-interactive)
  - Classifies authentication outcomes:
    - Accepted, Failed, Invalid, Disconnected, Session opened/closed, etc.
  - Handles year rollover automatically when parsing rotated logs
  - Optional extraction of `.gz` files before parsing
    - The extracted file will then be parsed
  - Optional logging of malformed/unparsed lines
  - Batch processing of multiple log files in a directory

- **File parsed:**
  - `auth.log`
  - `secure`
  - Variants supported:
    - Rotated logs (e.g., `auth.log.1`, `secure-20240101`)
    - Compressed logs (e.g., `.gz`)

- **Auto detect file names in directory:**
  - Yes
  - Matches files using pattern:
    - `auth.log*`
    - `secure*`
    - Includes rotated and compressed variants

- **Default output file name:**
  - Input file name appended with `.csv`
  - Examples:
    - `auth.log` → `auth.log.csv`
    - `secure-20240101.gz` → `secure-20240101.gz.csv`

- **Default output file location:**
  - Same directory as input file

- **Output timezone:**
  - Logging system's local time zone
  - ISO timestamps are preserved as-is (normalized to space-separated format)

- **Flags:**
  - `-f`, `--file`
    - Parse a single log file
  - `-d`, `--dir`
    - Parse all matching log files in a directory
  - `-e`, `--extract`
    - Extract `.gz` files before processing (creates decompressed copy)
  - `--log-malformed`
    - Output unparsed/malformed lines to a `.malformed.log` file
  - Notes:
    - `-f` and `-d` are mutually exclusive (must use one)

- **Usage:**
  - Parse a single file:
    ```bash
    parse_authSecure.py -f auth.log
    ```
  - Parse a compressed file without extraction:
    ```bash
    parse_authSecure.py -f auth.log.1.gz
    ```
  - Parse and extract compressed file:
    ```bash
    parse_authSecure.py -f auth.log.1.gz -e
    ```
  - Parse all auth/secure logs in a directory:
    ```bash
    parse_authSecure.py -d /path/to/logs/
    ```
  - Enable malformed log output:
    ```bash
    parse_authSecure.py -f auth.log --log-malformed
    ```

</details>


<details>
<summary><strong>parse_bashHistory.py</strong></summary>

- **Description:**
  - Parses Linux `.bash_history` files into CSV format.
  - Extracts executed commands and associates them with timestamps when available.

- **Features:**
  - Supports parsing of standard `.bash_history` files
  - Detects and processes epoch timestamps (if present)
    - Converts epoch timestamps to human-readable format (GMT+8)
  - Handles mixed entries:
    - Commands with timestamps
    - Commands without timestamps (marked as `N/A`)
  - Outputs clean CSV with proper escaping for special characters
  - Batch processing of multiple files in a directory

- **File parsed:**
  - `.bash_history`
  - Any file following bash history format (including exported or copied history files)

- **Auto detect file names in directory:**
  - No strict filtering
  - Processes **all files** in the specified directory

- **Default output file name:**
  - Input file name appended with `.csv`
  - Examples:
    - `.bash_history` → `.bash_history.csv`
    - `user_history` → `user_history.csv`

- **Default output file location:**
  - Same directory as input file

- **Output timezone:**
  - GMT+8 (for entries with epoch timestamps)
  - Entries without timestamps are marked as `N/A`

- **Flags:**
  - `-f`, `--file`
    - Parse a single `.bash_history` file
  - `-d`, `--dir`
    - Parse all files in a directory
  - Notes:
    - Flags are mutually exclusive (must use either `-f` or `-d`)

- **Usage:**
  - Parse a single file:
    ```bash
    parse_bashHistory.py -f .bash_history
    ```
  - Parse all files in a directory:
    ```bash
    parse_bashHistory.py -d /path/to/history_files/
    ```

</details>


<details>
<summary><strong>parse_lastlog_passwd.py</strong></summary>

- **Description:**
  - Parses Linux `lastlog` binary file and maps user IDs (UIDs) to usernames using a provided `/etc/passwd` file.
  - Outputs last login information for each user in a structured CSV format.

- **Features:**
  - Reads and parses binary `lastlog` structure
  - Maps UIDs to usernames using an external `passwd` file
  - Extracts key fields:
    - `Username`
    - `Terminal`
    - `Host`
    - `Last Login (UTC)`
  - Identifies users who have never logged in
  - Handles missing or incomplete entries gracefully
  - Outputs clean CSV for easy analysis

- **File parsed:**
  - `lastlog` (binary file)

- **Auto detect file names in directory:**
  - No
  - Requires explicit file paths for both:
    - `lastlog`
    - `passwd`

- **Default output file name:**
  - `lastlog_output.csv` (if not specified)

- **Default output file location:**
  - Current working directory (unless a custom output path is provided)

- **Output timezone:**
  - UTC

- **Flags:**
  - None (uses positional arguments instead)
  - Required arguments:
    - Path to `lastlog` file
    - Path to `passwd` file
  - Optional argument:
    - Output CSV file path

- **Usage:**
  - Basic usage:
    ```bash
    python parse_lastlog.py /path/to/lastlog /path/to/passwd
    ```
  - Specify custom output file:
    ```bash
    python parse_lastlog.py /path/to/lastlog /path/to/passwd output.csv
    ```

</details>


<details>
<summary><strong>parse_syslogMessages.py</strong></summary>

- **Description:**
  - Parses Linux `syslog` and `messages` log files into structured CSV format.
  - Supports both traditional syslog timestamps and modern ISO-8601 formats.
  - Designed for system log analysis and forensic investigations.

- **Features:**
  - Supports both plain text and `.gz` compressed log files
  - Parses multiple timestamp formats:
    - Classic syslog format (e.g., `Jan 25 10:15:03`)
    - ISO-8601 format (e.g., `2026-03-08T00:05:01+08:00`)
    - ISO format without timezone
  - Automatically reconstructs full timestamps (including year) for classic syslog logs
  - Handles year rollover for rotated logs
  - Extracts key fields:
    - `timestamp`
    - `host`
    - `process`
    - `pid`
    - `message`
  - Optional extraction of `.gz` files before parsing
  - Optional logging of malformed/unparsed lines
  - Batch processing of multiple log files in a directory

- **File parsed:**
  - `syslog`
  - `messages`
  - Variants supported:
    - Rotated logs (e.g., `syslog.1`, `messages.2`)
    - Compressed logs (e.g., `.gz`)

- **Auto detect file names in directory:**
  - Yes
  - Matches files using pattern:
    - `syslog`
    - `syslog.N`
    - `messages`
    - `messages.N`
    - Includes `.gz` variants

- **Default output file name:**
  - Input file name appended with `.csv`
  - Examples:
    - `syslog` → `syslog.csv`
    - `messages.1.gz` → `messages.1.gz.csv`

- **Default output file location:**
  - Same directory as input file

- **Output timezone:**
  - Derived from log content:
    - ISO timestamps retain their original timezone (if present)
    - Classic syslog timestamps use system file modification year (no explicit timezone)

- **Flags:**
  - `-f`, `--file`
    - Parse a single syslog/messages file
  - `-d`, `--dir`
    - Parse all matching files in a directory
  - `-e`, `--extract`
    - Extract `.gz` files to disk before parsing
  - `--log-malformed`
    - Save malformed/unparsed lines to a `.malformed.log` file
  - Notes:
    - `-f` and `-d` are mutually exclusive (must use one)

- **Usage:**
  - Parse a single file:
    ```bash
    parse_syslogMessages.py -f syslog
    ```
  - Parse a compressed file:
    ```bash
    parse_syslogMessages.py -f messages.1.gz
    ```
  - Parse and extract compressed file:
    ```bash
    parse_syslogMessages.py -f syslog.1.gz -e
    ```
  - Parse all syslog/messages files in a directory:
    ```bash
    parse_syslogMessages.py -d /path/to/logs/
    ```
  - Enable malformed log output:
    ```bash
    parse_syslogMessages.py -f syslog --log-malformed
    ```

</details>


<details>
<summary><strong>parse_wtmp.py</strong></summary>

- **Description:**
  - Parses Linux `wtmp` binary log files into human-readable structured CSV format.
  - Extracts login sessions, system events, and user activity records from binary structures.

- **Features:**
  - Supports both plain `wtmp` and `.gz` compressed files
  - Parses binary `utmp/wtmp` structures into readable fields
  - Extracts key session information:
    - `Timestamp (GMT+8)`
    - `Username`
    - `SessionID`
    - `Terminal`
    - `Host`
    - `IP Address`
    - `PID`
    - `Type` (e.g., USER_PROCESS, DEAD_PROCESS, BOOT_TIME)
  - Converts timestamps from epoch to human-readable format with millisecond precision
  - Maps numeric record types to descriptive labels
  - Handles malformed or partial records gracefully (skips invalid entries)
  - Batch processing of multiple files in a directory

- **File parsed:**
  - `wtmp`
  - Variants supported:
    - `wtmp.N`
    - `wtmp-N`
    - `wtmp_<suffix>`
    - Compressed files (e.g., `.gz`)

- **Auto detect file names in directory:**
  - Yes
  - Matches files:
    - Starting with `wtmp`
    - Includes rotated and suffixed variants
    - Includes `.gz` files

- **Default output file name:**
  - Input file name appended with `.csv`
  - Examples:
    - `wtmp` → `wtmp.csv`
    - `wtmp.1.gz` → `wtmp.1.gz.csv`

- **Default output file location:**
  - Same directory as input file (for directory mode)
  - Current working directory (for single file mode, uses filename only)

- **Output timezone:**
  - GMT+8

- **Flags:**
  - `-f`, `--file`
    - Parse a single `wtmp` file
  - `-d`, `--dir`
    - Parse all matching `wtmp` files in a directory
  - Notes:
    - Flags are mutually exclusive (must use either `-f` or `-d`)

- **Usage:**
  - Parse a single file:
    ```bash
    parse_wtmp.py -f /var/log/wtmp
    ```
  - Parse a compressed file:
    ```bash
    parse_wtmp.py -f wtmp.1.gz
    ```
  - Parse all wtmp files in a directory:
    ```bash
    parse_wtmp.py -d /var/log/
    ```

</details>

# LinuxParsers
Some Linux file parsers that were vibe coded.

|Linux Parser              |File parsed        |Input file names|Output file name|Output timezone|Flags|Sample command|Remarks|
| ------------- |:-------------:|-|-|-|-|-|-|
|parse_audit.py             |`audit.log`          |Start with `audit.log`|Input file name appended with `.csv`|GMT+8|`-f` for file<br><br>`-d` for directory|`parse_audit.py -f audit.log`|Supports `.gz` files|
|parse_authlog.py           |`auth.log`         |User specified|User specified|Logging system's local time zone|-|`parse_authlog.py <input_log_file> <output_csv_file>`|-|
|parse_bashHistory.py       |`.bash_history`      |User specified|Input file name appended with `.csv`|GMT+8|`-f` for file<br><br>`-d` for directory|`parse_bashHistory.py -f .bash_history`|Timestamp is only available if epoch time is stored|
|parse_lastlog_passwd.py    |`lastlog`     |User specified|lastlog_output.csv (default)|UTC|-|`parse_lastlog.py /path/to/lastlog /path/to/passwd [output.csv]`|Retrieves the user account list used to map UIDs to usernames using provided `passwd`|
|parse_lastlog_wsl.py       |`lastlog`    |User specified|lastlog_output.csv (default)|UTC|-|`parse_lastlog_wsl.py /path/to/lastlog [output.csv]`|Retrieves the user account list used to map UIDs to usernames from local system's `passwd`|
|parse_secureAndMessage.py  |`secure`<br><br>`messages`|Start with `messages` or `secure`|Input file name appended with `.csv`|Logging system's local time zone|`-f` for file<br><br>`-d` for directory|`parse_secureAndMessage.py -f secure`|Supports `.gz` files|
|parse_wtmp.py              |`wtmp`               |Starts with `wtmp`|Input file name appended with `.csv`|GMT+8|`-f` for file<br><br>`-d` for directory|`parse_wtmp.py -f wtmp`|Supports `.gz` files|

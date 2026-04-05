#!/usr/bin/env python3

import argparse
import os
import csv
import gzip
import re
from datetime import datetime
import shutil

# -----------------------------
# Patterns
# -----------------------------

SYSLOG_PATTERN = re.compile(
    r'^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+'
    r'(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+'
    r'(?P<process>[\w\-/]+)(?:\[(?P<pid>\d+)\])?:\s+'
    r'(?P<message>.*)$'
)

ISO_PATTERN = re.compile(
    r'^(?P<timestamp_iso>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2})?)\s+'
    r'(?P<host>\S+)\s+'
    r'(?P<process>[\w\-/]+)(?:\[(?P<pid>\d+)\])?:\s+'
    r'(?P<message>.*)$'
)

# Improved extraction
AUTH_DETAILS = {
    "user": re.compile(r'(?:for user\s+|for\s+|user\s+)(?:invalid user\s+)?(?P<user>\S+)'),
    "ip": re.compile(r'from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})'),
    "port": re.compile(r'port (?P<port>\d+)'),
    "method": re.compile(r'\b(password|publickey|keyboard-interactive)\b'),
}

MONTHS = {
    'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4,
    'May': 5, 'Jun': 6, 'Jul': 7, 'Aug': 8,
    'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12
}

# -----------------------------
# Helper Functions
# -----------------------------

def extract_auth_details(message):
    details = {}
    for key, pattern in AUTH_DETAILS.items():
        match = pattern.search(message)
        if match:
            details[key] = match.groupdict().get(key, match.group(0))
        else:
            details[key] = ''
    return details


def classify_result(message):
    msg = message.lower()

    if "accepted" in msg:
        return "Accepted"
    elif "failed" in msg:
        return "Failed"
    elif "invalid user" in msg:
        return "Invalid"
    elif "received disconnect" in msg:
        return "Received disconnect"
    elif "disconnected" in msg:
        return "Disconnected"
    elif "session opened" in msg:
        return "Connection open"
    elif "session closed" in msg:
        return "Connection close"
    else:
        return ""


def extract_gzip(gz_path):
    extracted_path = gz_path[:-3]
    if os.path.exists(extracted_path):
        return extracted_path

    print(f"[+] Extracting {gz_path} → {extracted_path}")
    with gzip.open(gz_path, 'rb') as gz, open(extracted_path, 'wb') as out:
        shutil.copyfileobj(gz, out)

    gz_stat = os.stat(gz_path)
    os.utime(extracted_path, (gz_stat.st_atime, gz_stat.st_mtime))
    return extracted_path


def normalize_iso_timestamp(ts):
    return ts.replace('T', ' ')


def parse_auth_line(line, year):
    iso_match = ISO_PATTERN.match(line)
    if iso_match:
        data = iso_match.groupdict()
        timestamp = normalize_iso_timestamp(data['timestamp_iso'])
        auth_details = extract_auth_details(data['message'])
        result = classify_result(data['message'])

        return {
            'timestamp': timestamp,
            'month': '',
            'day': '',
            'time': '',
            'host': data['host'],
            'process': data['process'],
            'pid': data['pid'],
            'user': auth_details['user'],
            'ip': auth_details['ip'],
            'port': auth_details['port'],
            'method': auth_details['method'],
            'result': result,
            'message': data['message'],
            'malformed': ''
        }

    sys_match = SYSLOG_PATTERN.match(line)
    if sys_match:
        data = sys_match.groupdict()
        try:
            timestamp = datetime(
                year=year,
                month=MONTHS[data['month']],
                day=int(data['day']),
                hour=int(data['time'][0:2]),
                minute=int(data['time'][3:5]),
                second=int(data['time'][6:8])
            ).strftime('%Y-%m-%d %H:%M:%S')

            auth_details = extract_auth_details(data['message'])
            result = classify_result(data['message'])

            return {
                'timestamp': timestamp,
                'month': data['month'],
                'day': data['day'],
                'time': data['time'],
                'host': data['host'],
                'process': data['process'],
                'pid': data['pid'],
                'user': auth_details['user'],
                'ip': auth_details['ip'],
                'port': auth_details['port'],
                'method': auth_details['method'],
                'result': result,
                'message': data['message'],
                'malformed': ''
            }
        except Exception:
            pass

    return {
        'timestamp': '',
        'month': '',
        'day': '',
        'time': '',
        'host': '',
        'process': '',
        'pid': '',
        'user': '',
        'ip': '',
        'port': '',
        'method': '',
        'result': '',
        'message': line,
        'malformed': 'PARSE_ERROR'
    }

# -----------------------------
# Main Processing
# -----------------------------

def process_file(file_path, extract=False, log_malformed=False):
    is_gz = file_path.endswith('.gz')

    if is_gz and extract:
        file_path = extract_gzip(file_path)

    print(f"[+] Processing {file_path}")

    log_fh = gzip.open(file_path, 'rt', errors='replace') if is_gz and not extract else open(file_path, 'r', errors='replace')

    base_year = datetime.fromtimestamp(os.path.getmtime(file_path)).year
    current_year = base_year
    previous_month = None

    output_csv = file_path + '.csv'
    malformed_file = file_path + '.malformed.log' if log_malformed else None

    with log_fh as f, \
         open(output_csv, 'w', newline='', encoding='utf-8') as csvfile, \
         open(malformed_file, 'w', encoding='utf-8') if log_malformed else open(os.devnull, 'w') as malformed_log:

        fieldnames = [
            'timestamp', 'month', 'day', 'time', 'host',
            'process', 'pid', 'user', 'ip', 'port',
            'method', 'result', 'message', 'malformed'
        ]

        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for line in f:
            line = line.rstrip()

            month_match = re.match(r'^(\w{3})\s+\d{1,2}', line)
            if month_match:
                month_num = MONTHS.get(month_match.group(1))
                if previous_month and month_num < previous_month:
                    current_year += 1
                previous_month = month_num

            parsed = parse_auth_line(line, current_year)
            writer.writerow(parsed)

    print(f"[+] CSV written: {output_csv}")


def find_auth_logs(directory):
    files = []
    for f in os.listdir(directory):
        if re.match(r'^(auth\.log|secure)([-._]\d{8}|[-._][\w\d]+)*(\.gz)?$', f):
            files.append(os.path.join(directory, f))
    return sorted(files)

# -----------------------------
# CLI
# -----------------------------

def main():
    parser = argparse.ArgumentParser(description="Parse auth.log/secure files to CSV")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-f', '--file', help='Single file')
    group.add_argument('-d', '--dir', help='Directory of logs')

    parser.add_argument('-e', '--extract', action='store_true')
    parser.add_argument('--log-malformed', action='store_true')

    args = parser.parse_args()

    if args.file:
        process_file(args.file, extract=args.extract, log_malformed=args.log_malformed)
    else:
        files = find_auth_logs(args.dir)
        if not files:
            print("[-] No auth/secure files found")
            return
        for f in files:
            process_file(f, extract=args.extract, log_malformed=args.log_malformed)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3

import argparse
import os
import csv
import gzip
import re
import shutil
from datetime import datetime

# -----------------------------
# Regex patterns
# -----------------------------

# Classic syslog format
SYSLOG_PATTERN = re.compile(
    r'^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+'
    r'(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+'
    r'(?P<process>[\w\-/\.]+)(?:\[(?P<pid>\d+)\])?:\s+'
    r'(?P<message>.*)$'
)

# ISO8601 timestamp format
ISO_PATTERN = re.compile(
    r'^(?P<timestamp_iso>'
    r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}'
    r'(?:\.\d+)?'
    r'(?:Z|[+-]\d{2}:\d{2})?'
    r')\s+'
    r'(?P<host>\S+)\s+'
    r'(?P<process>[\w\-/\.]+)(?:\[(?P<pid>\d+)\])?:\s+'
    r'(?P<message>.*)$'
)

MONTHS = {
    'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4,
    'May': 5, 'Jun': 6, 'Jul': 7, 'Aug': 8,
    'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12
}

# -----------------------------
# Gzip extraction
# -----------------------------

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

# -----------------------------
# Line parsing
# -----------------------------

def parse_syslog_line(line, year):

    # -------- ISO timestamp --------
    iso_match = ISO_PATTERN.match(line)
    if iso_match:
        data = iso_match.groupdict()

        return {
            'timestamp': data['timestamp_iso'],
            'month': '',
            'day': '',
            'time': '',
            'host': data['host'],
            'process': data['process'],
            'pid': data['pid'],
            'message': data['message'],
            'malformed': ''
        }

    # -------- Classic syslog --------
    match = SYSLOG_PATTERN.match(line)
    if match:
        data = match.groupdict()

        try:
            timestamp = datetime(
                year=year,
                month=MONTHS[data['month']],
                day=int(data['day']),
                hour=int(data['time'][0:2]),
                minute=int(data['time'][3:5]),
                second=int(data['time'][6:8])
            ).isoformat()

            return {
                'timestamp': timestamp,
                'month': data['month'],
                'day': data['day'],
                'time': data['time'],
                'host': data['host'],
                'process': data['process'],
                'pid': data['pid'],
                'message': data['message'],
                'malformed': ''
            }

        except Exception:
            pass

    # -------- malformed --------
    return {
        'timestamp': '',
        'month': '',
        'day': '',
        'time': '',
        'host': '',
        'process': '',
        'pid': '',
        'message': line,
        'malformed': 'PARSE_ERROR'
    }

# -----------------------------
# File processing
# -----------------------------

def process_file(file_path, extract=False, log_malformed=False):

    is_gz = file_path.endswith('.gz')

    if is_gz and extract:
        file_path = extract_gzip(file_path)

    print(f"[+] Processing {file_path}")

    if is_gz and not extract:
        log_fh = gzip.open(file_path, 'rt', errors='replace')
        mtime_source = file_path
    else:
        log_fh = open(file_path, 'r', errors='replace')
        mtime_source = file_path

    current_year = datetime.fromtimestamp(os.path.getmtime(mtime_source)).year
    previous_month = None

    output_csv = file_path + '.csv'
    malformed_file = file_path + '.malformed.log' if log_malformed else None

    with log_fh as f, \
         open(output_csv, 'w', newline='', encoding='utf-8') as csvfile, \
         open(malformed_file, 'w', encoding='utf-8') if log_malformed else open(os.devnull, 'w') as malformed_log:

        fieldnames = [
            'timestamp', 'month', 'day', 'time',
            'host', 'process', 'pid', 'message', 'malformed'
        ]

        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for line in f:

            line = line.rstrip()

            # rollover detection only applies to classic syslog format
            month_match = re.match(r'^(\w{3})\s+\d{1,2}', line)

            if month_match:
                month_num = MONTHS.get(month_match.group(1))

                if previous_month is not None and month_num < previous_month:
                    current_year += 1

                previous_month = month_num

            parsed = parse_syslog_line(line, current_year)

            writer.writerow(parsed)

            if parsed['malformed'] == 'PARSE_ERROR' and log_malformed:
                malformed_log.write(line + '\n')

    print(f"[+] CSV saved: {output_csv}")

    if log_malformed:
        print(f"[+] Malformed lines logged: {malformed_file}")

# -----------------------------
# Directory discovery
# -----------------------------

def find_syslog_files(directory):

    files = []

    for f in os.listdir(directory):

        if re.match(r'^(syslog|messages)(\.\d+)?(\.gz)?$', f):
            files.append(os.path.join(directory, f))

    return sorted(files)

# -----------------------------
# CLI
# -----------------------------

def main():

    parser = argparse.ArgumentParser(
        description='Parse Linux syslog/messages files to CSV with optional gzip extraction'
    )

    group = parser.add_mutually_exclusive_group(required=True)

    group.add_argument(
        '-f', '--file',
        help='Single syslog/messages file'
    )

    group.add_argument(
        '-d', '--dir',
        help='Directory containing syslog/messages files'
    )

    parser.add_argument(
        '-e', '--extract',
        action='store_true',
        help='Extract .gz files to disk before parsing'
    )

    parser.add_argument(
        '--log-malformed',
        action='store_true',
        help='Save malformed lines to a separate log file'
    )

    args = parser.parse_args()

    if args.file:

        process_file(
            args.file,
            args.extract,
            args.log_malformed
        )

    else:

        files = find_syslog_files(args.dir)

        if not files:
            print("[-] No syslog/messages files found")
            return

        for f in files:

            process_file(
                f,
                args.extract,
                args.log_malformed
            )

if __name__ == '__main__':
    main()

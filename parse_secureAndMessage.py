#!/usr/bin/env python3

import sys
import csv
import re
import os
import gzip
import argparse
from datetime import datetime

MONTH_MAP = {
    'Jan': '01', 'Feb': '02', 'Mar': '03', 'Apr': '04',
    'May': '05', 'Jun': '06', 'Jul': '07', 'Aug': '08',
    'Sep': '09', 'Oct': '10', 'Nov': '11', 'Dec': '12'
}

def parse_event(event):
    # Match: process[pid]: message OR process: message
    match = re.match(r'([^\[\]:]+)\[(\d+)\]: (.+)', event)
    if match:
        process, pid, msg = match.groups()
        message = f"{process}: {msg}"  # Exclude [pid] from message
    else:
        parts = event.split(": ", 1)
        process = parts[0].strip()
        pid = ""
        msg = parts[1].strip() if len(parts) > 1 else ""
        message = f"{process}: {msg}" if msg else process
    return process, pid, message

def parse_line(line, year):
    parts = line.strip().split(maxsplit=4)
    if len(parts) < 5:
        return None

    month_str, day_str, time_str, hostname, event = parts
    month = MONTH_MAP.get(month_str)
    if not month:
        return None

    try:
        datetime_str = f"{year}/{month}/{int(day_str):02d} {time_str}"
        process, pid, message = parse_event(event)
        return [datetime_str, hostname, process, pid, message]
    except Exception:
        return None

def open_log_file(path):
    if path.endswith(".gz"):
        return gzip.open(path, 'rt', encoding='utf-8', errors='ignore')
    else:
        return open(path, 'r', encoding='utf-8', errors='ignore')

def process_file(input_path, output_path):
    try:
        mod_time = os.path.getmtime(input_path)
        inferred_year = datetime.fromtimestamp(mod_time).year
    except Exception as e:
        print(f"⚠️ Error reading file modification time: {e}")
        inferred_year = datetime.now().year

    with open_log_file(input_path) as infile, \
         open(output_path, 'w', newline='', encoding='utf-8') as outfile:

        writer = csv.writer(outfile, quoting=csv.QUOTE_MINIMAL, escapechar='\\')
        writer.writerow(["Timestamp_(Local)", "hostname", "process", "pid", "message"])

        for line in infile:
            parsed = parse_line(line, inferred_year)
            if parsed:
                writer.writerow(parsed)

    print(f"✅ Parsed: {input_path} → {output_path}")

def main():
    parser = argparse.ArgumentParser(description="Parse Linux secure/messages logs (supports .gz) into CSV.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-f', '--file', help="Single log file to parse")
    group.add_argument('-d', '--dir', help="Directory of log files to parse")

    args = parser.parse_args()

    def is_valid_log(filename):
        base = os.path.basename(filename)
        return (base.startswith("messages") or base.startswith("secure")) and \
            (base.endswith(".gz") or '.' not in os.path.splitext(base)[1])
  
    if args.file:
        if not os.path.isfile(args.file):
            print(f"❌ File not found: {args.file}")
            sys.exit(1)
        output_file = args.file + ".csv"
        process_file(args.file, output_file)

    elif args.dir:
        if not os.path.isdir(args.dir):
            print(f"❌ Directory not found: {args.dir}")
            sys.exit(1)

        for fname in os.listdir(args.dir):
            if not is_valid_log(fname):
                continue
            full_path = os.path.join(args.dir, fname)
            if os.path.isfile(full_path):
                output_file = full_path + ".csv"
                process_file(full_path, output_file)

if __name__ == '__main__':
    main()

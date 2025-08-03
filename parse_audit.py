#!/usr/bin/env python3

import re
import csv
import sys
import os
import argparse
import gzip
from datetime import datetime, timedelta, timezone

def parse_audit_line(line):
    data = {}

    # Extract event type
    type_match = re.search(r'type=(\w+)', line)
    if type_match:
        data['type'] = type_match.group(1)

    # Extract timestamp from msg=audit(...)
    msg_match = re.search(r'msg=audit\((\d+)\.(\d+):(\d+)\)', line)
    if msg_match:
        epoch_seconds = int(msg_match.group(1))
        milliseconds_raw = msg_match.group(2)[:3].ljust(3, '0')  # pad/truncate to 3 digits
        data['epoch'] = f"{epoch_seconds}.{milliseconds_raw}"

        # Convert to datetime with timezone offset
        utc_time = datetime.fromtimestamp(epoch_seconds, tz=timezone.utc)
        gmt8_time = utc_time + timedelta(hours=8)
        formatted_time = gmt8_time.strftime('%Y-%m-%d %H:%M:%S')
        data['timestamp_GMT+8'] = f"{formatted_time}.{milliseconds_raw}"

    # Extract all key=value pairs
    pairs = re.findall(r'(\w+)=("[^"]*"|\S+)', line)
    for key, value in pairs:
        value = value.strip('"')
        data[key] = value

    return data, line.strip()

def open_file(filepath):
    return gzip.open(filepath, 'rt', encoding='utf-8') if filepath.endswith('.gz') else open(filepath, 'r', encoding='utf-8')

def process_file(input_path, output_path):
    important_fields = ['epoch', 'timestamp_GMT+8', 'type', 'exe', 'uid', 'auid', 'syscall']
    csv_fields = important_fields + ['data']

    with open(output_path, mode='w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=csv_fields)
        writer.writeheader()

        with open_file(input_path) as f:
            for line in f:
                parsed, original_line = parse_audit_line(line)
                if 'timestamp_GMT+8' in parsed and 'epoch' in parsed:
                    row = {field: parsed.get(field, '') for field in important_fields}
                    # Remove 'msg=audit(...)' for data column
                    data_cleaned = re.sub(r'msg=audit\([^)]+\)\s*', '', original_line)
                    row['data'] = data_cleaned.strip()
                    writer.writerow(row)

    print(f"✅ Parsed: {input_path} → {output_path}")

def is_audit_log_file(filename):
    # Matches audit.log, audit.log.N, audit.log.gz, audit.log.N.gz, audit.log_SkibiDi_77.gz, audit.log.5_hippo_31.gz
    return re.match(r'audit\.log([._][\w\d]+)*(\.gz)?$', filename)

def main():
    parser = argparse.ArgumentParser(description="Parse Linux audit logs to CSV (supports .gz files).")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-f', '--file', help="Path to a single audit log file (plain or .gz)")
    group.add_argument('-d', '--dir', help="Path to a directory of audit log files")

    args = parser.parse_args()

    if args.file:
        if not os.path.isfile(args.file):
            print(f"❌ File not found: {args.file}")
            sys.exit(1)
        output_csv = args.file + ".csv"
        process_file(args.file, output_csv)

    elif args.dir:
        if not os.path.isdir(args.dir):
            print(f"❌ Directory not found: {args.dir}")
            sys.exit(1)

        for filename in sorted(os.listdir(args.dir)):
            if is_audit_log_file(filename):
                input_path = os.path.join(args.dir, filename)
                if os.path.isfile(input_path):
                    output_path = input_path + ".csv"
                    process_file(input_path, output_path)

if __name__ == "__main__":
    main()

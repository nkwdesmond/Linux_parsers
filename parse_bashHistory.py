#!/usr/bin/env python3

import sys
import csv
import os
import argparse
from datetime import datetime, timezone, timedelta

def parse_bash_history(input_file, output_csv):
    entries = []
    current_time = None
    epoch_time = None
    gmt8 = timezone(timedelta(hours=8))

    with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()

    i = 0
    while i < len(lines):
        line = lines[i].strip()

        if line.startswith('#') and line[1:].isdigit():
            # Timestamp line
            epoch_time = int(line[1:])
            current_time = datetime.fromtimestamp(epoch_time, tz=timezone.utc).astimezone(gmt8)
            i += 1
            if i < len(lines):
                command = lines[i].strip()
                timestamp = current_time.strftime('%Y-%m-%d %H:%M:%S')
                entries.append((str(epoch_time), timestamp, command))
        else:
            # No timestamp, mark epoch as N/A
            entries.append(('N/A', 'N/A', line))
        i += 1

    with open(output_csv, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile, quoting=csv.QUOTE_MINIMAL, escapechar='\\')
        writer.writerow(['Epoch', 'Timestamp (GMT+8)', 'Command'])
        writer.writerows(entries)

    print(f"✅ Parsed: {input_file} → {output_csv}")

def main():
    parser = argparse.ArgumentParser(description="Parse .bash_history files into CSV format.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-f', '--file', help="Path to a single .bash_history file")
    group.add_argument('-d', '--dir', help="Path to a directory of .bash_history files")

    args = parser.parse_args()

    if args.file:
        if not os.path.isfile(args.file):
            print(f"❌ File not found: {args.file}")
            sys.exit(1)
        output_csv = args.file + ".csv"
        parse_bash_history(args.file, output_csv)

    elif args.dir:
        if not os.path.isdir(args.dir):
            print(f"❌ Directory not found: {args.dir}")
            sys.exit(1)

        for fname in os.listdir(args.dir):
            full_path = os.path.join(args.dir, fname)
            if os.path.isfile(full_path):
                output_csv = full_path + ".csv"
                parse_bash_history(full_path, output_csv)

if __name__ == "__main__":
    main()

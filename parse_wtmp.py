#!/usr/bin/env python3

import struct
import argparse
import csv
import os
import socket
import gzip
from datetime import datetime, timezone, timedelta

# Constants
UTMP_STRUCT = 'hi32s4s32s256shhiii4i20s'
UTMP_SIZE = 384

UT_TYPE = {
    0: 'EMPTY',
    1: 'RUN_LVL',
    2: 'BOOT_TIME',
    3: 'NEW_TIME',
    4: 'OLD_TIME',
    5: 'INIT_PROCESS',
    6: 'LOGIN_PROCESS',
    7: 'USER_PROCESS',
    8: 'DEAD_PROCESS',
    9: 'ACCOUNTING'
}

def open_wtmp_file(path):
    return gzip.open(path, 'rb') if path.endswith('.gz') else open(path, 'rb')

def parse_wtmp(file_path, output_path):
    with open_wtmp_file(file_path) as f, open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow([
            'Timestamp (GMT+8)', 'Username', 'SessionID', 'Terminal', 'Host',
            'IP Address', 'PID', 'Type'
        ])

        while True:
            bytes_read = f.read(UTMP_SIZE)
            if not bytes_read or len(bytes_read) < UTMP_SIZE:
                break

            try:
                unpacked = struct.unpack(UTMP_STRUCT, bytes_read)
                (ut_type, pid, ut_line, ut_id, ut_user, ut_host, exit1, exit2, session,
                 sec, usec, addr_v6_1, *_rest) = unpacked

                username = ut_user.decode('utf-8', errors='ignore').strip('\x00')
                session_id = ut_id.decode('utf-8', errors='ignore').strip('\x00')
                terminal = ut_line.decode('utf-8', errors='ignore').strip('\x00')
                host = ut_host.decode('utf-8', errors='ignore').strip('\x00')

                ip_address = ''
                try:
                    if addr_v6_1 != 0:
                        ip_address = socket.inet_ntoa(struct.pack('<I', addr_v6_1 & 0xffffffff))
                except Exception:
                    ip_address = ''

                timestamp_utc = datetime.fromtimestamp(sec + usec / 1_000_000, tz=timezone.utc)
                timestamp_gmt8 = timestamp_utc.astimezone(timezone(timedelta(hours=8)))
                formatted_ts = timestamp_gmt8.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]

                writer.writerow([
                    formatted_ts, username, session_id, terminal, host,
                    ip_address, pid, UT_TYPE.get(ut_type, str(ut_type))
                ])
            except Exception:
                continue

def is_wtmp_file(filename):
    return (
        filename == 'wtmp' or
        filename.startswith('wtmp-') or
        filename.startswith('wtmp.') or
        filename.startswith('wtmp_')
    ) and (filename.endswith('.gz') or '.' not in filename or filename.count('.') == 1)

def main():
    parser = argparse.ArgumentParser(description="Parse Linux wtmp or wtmp.gz files into CSV.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-f", "--file", help="Path to a single wtmp or wtmp.gz file")
    group.add_argument("-d", "--dir", help="Path to a directory of wtmp files")

    args = parser.parse_args()

    if args.file:
        if not os.path.isfile(args.file):
            print(f"❌ File not found: {args.file}")
            return
        filename = os.path.basename(args.file)
        output_csv = filename + '.csv'
        parse_wtmp(args.file, output_csv)
        print(f"✅ Output written to: {output_csv}")

    elif args.dir:
        if not os.path.isdir(args.dir):
            print(f"❌ Directory not found: {args.dir}")
            return

        for fname in os.listdir(args.dir):
            if is_wtmp_file(fname):
                full_path = os.path.join(args.dir, fname)
                if os.path.isfile(full_path):
                    output_csv = os.path.join(args.dir, fname + '.csv')
                    parse_wtmp(full_path, output_csv)
                    print(f"✅ Output written to: {output_csv}")

if __name__ == "__main__":
    main()

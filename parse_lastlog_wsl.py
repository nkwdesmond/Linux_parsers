import os
import pwd
import struct
import datetime
import csv
import sys

STRUCT_FORMAT = "I32s256s"  # time_t, line (tty), host
ENTRY_SIZE = struct.calcsize(STRUCT_FORMAT)

def read_lastlog(lastlog_path, csv_output_path="lastlog_output.csv"):
    users = pwd.getpwall()

    with open(lastlog_path, "rb") as f, open(csv_output_path, mode="w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Username", "Terminal", "Host", "Last Login (UTC)"])

        for user in users:
            uid = user.pw_uid
            offset = uid * ENTRY_SIZE
            try:
                f.seek(offset)
                data = f.read(ENTRY_SIZE)
                if len(data) != ENTRY_SIZE:
                    continue

                ll_time, ll_line, ll_host = struct.unpack(STRUCT_FORMAT, data)

                line = ll_line.decode('utf-8', errors='ignore').strip('\x00').strip()
                host = ll_host.decode('utf-8', errors='ignore').strip('\x00').strip()

                if ll_time == 0:
                    last_login = "Never logged in"
                else:
                    last_login = datetime.datetime.utcfromtimestamp(ll_time).strftime('%Y-%m-%d %H:%M:%S')

                writer.writerow([user.pw_name, line, host, last_login])
            except Exception as e:
                print(f"Error reading UID {uid}: {e}")

    print(f"CSV output written to {csv_output_path}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python parse_lastlog.py /path/to/lastlog [output.csv]")
        sys.exit(1)

    lastlog_path = sys.argv[1]
    output_csv = sys.argv[2] if len(sys.argv) > 2 else "lastlog_output.csv"

    if not os.path.exists(lastlog_path):
        print(f"Error: File not found: {lastlog_path}")
        sys.exit(1)

    read_lastlog(lastlog_path, output_csv)

import sys
import re
import csv

def parse_custom_log_line(line):
    pattern = r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\s+([\w\-]+)\[(\d+)\]:\s+(.*)'
    match = re.match(pattern, line)
    if match:
        timestamp, process, pid, message = match.groups()
        return (timestamp, process, pid, message)
    return None

def parse_log_to_csv(input_file, output_file):
    with open(input_file, 'r') as infile, open(output_file, 'w', newline='') as outfile:
        writer = csv.writer(outfile)
        writer.writerow(["timestamp", "process", "pid", "message"])  # Header

        for line in infile:
            parsed = parse_custom_log_line(line.strip())
            if parsed:
                writer.writerow(parsed)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: python3 {sys.argv[0]} <input_log_file> <output_csv_file>")
        sys.exit(1)

    input_path = sys.argv[1]
    output_path = sys.argv[2]
    parse_log_to_csv(input_path, output_path)
    print(f"Log parsed and written to: {output_path}")


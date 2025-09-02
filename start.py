import csv

# Read names from file1.csv
with open('file1.csv', 'r', newline='') as f1:
    names = [line.strip() for line in f1 if line.strip()]

# Read name and IP from file2.csv into a dictionary
name_ip_map = {}
with open('file2.csv', 'r', newline='') as f2:
    reader = csv.reader(f2)
    for row in reader:
        if len(row) >= 2:
            name = row[0].strip()
            ip = row[1].strip()
            name_ip_map[name] = ip

# Write all names from file1.csv with IP or "unknown" to output.csv
with open('output.csv', 'w', newline='') as out:
    writer = csv.writer(out)
    for name in names:
        ip = name_ip_map.get(name, "unknown")
        writer.writerow([name, ip])

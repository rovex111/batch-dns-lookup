import pandas as pd
import re
import ipaddress
import json

# Load matrix from file
with open('matrix.json', 'r') as f:
    matrix = json.load(f)

risk_levels = matrix['risk_levels']
risk_weights = matrix['risk_weights']
thresholds = matrix['thresholds']
overall_risk_thresholds = matrix['overall_risk_thresholds']
appid_keywords = matrix['appid_keywords']
port_keywords = matrix['port_keywords']

cidr_pattern = r'\((\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?)\)'
port_number_pattern = re.compile(r'(?:\[|\()(?:TCP|UDP):(\d+)(?:-(\d+))?(?:\]|\))', re.IGNORECASE)
port_object_pattern = re.compile(r'[a-zA-Z0-9_\-]+(?:\[[^\]]+\]|\([^\)]+\))')

def count_ip_addresses(column_values):
    total_ips_any = 2**32
    if pd.isna(column_values):
        return 0
    if "any" in column_values.lower():
        return total_ips_any
    cidr_blocks = re.findall(cidr_pattern, column_values)
    total_ips = 0
    for cidr in cidr_blocks:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            total_ips += network.num_addresses
        except ValueError:
            # Skip invalid CIDR blocks
            continue
    return total_ips

def count_ports(column_values):
    if pd.isna(column_values):
        return 0

    # Remove quotes and normalize spaces and case
    normalized = column_values.strip().lower().replace('"', '').replace("'", "")

    # If the entire string is 'any' or 'any(any)' or contains them as standalone tokens, count as 65535
    if re.search(r'\bany\s*(\(\s*any\s*\))?\b', normalized):
        return 65535

    # Extract content inside Members(...) if present
    members_match = re.search(r'Members\((.*?)\)', column_values, re.IGNORECASE)
    if members_match:
        content = members_match.group(1)
    else:
        content = column_values

    port_objects = port_object_pattern.findall(content)

    num_ports = 0
    for port_obj in port_objects:
        match = port_number_pattern.search(port_obj)
        if match:
            start_port_str = match.group(1)
            end_port_str = match.group(2)
            try:
                start = int(start_port_str)
                if end_port_str:
                    end = int(end_port_str)
                    if start > end:
                        start, end = end, start
                    num_ports += (end - start + 1)
                else:
                    num_ports += 1
            except ValueError:
                num_ports += 1
        else:
            num_ports += 1

    return num_ports

def determine_risk_num(count, category):
    if category not in thresholds:
        low_max, med_max = 10, 2000
    else:
        low_max, med_max = thresholds[category]

    if 0 <= count <= low_max:
        return "Low"
    elif low_max < count <= med_max:
        return "Medium"
    elif count > med_max:
        return "High"
    else:
        return "Unknown"

def determine_risk_num_sources(num_sources):
    return determine_risk_num(num_sources, 'sources_risk')

def determine_risk_num_addresses(num_addresses):
    return determine_risk_num(num_addresses, 'destinations_risk')

def determine_risk_num_services(num_services):
    return determine_risk_num(num_services, 'servicesno_risk')

def determine_appid_risk(applications):
    if pd.isna(applications):
        return "Low"
    applications_lower = applications.lower()
    if "any" in applications_lower:
        return "High"
    matches = [kw for kw in appid_keywords if kw in applications_lower]
    count = len(matches)
    return determine_risk_num(count, 'appid_risk')

def determine_port_risk(services):
    # New condition: if services exactly equals APPLICATION_DEFAULT_SERVICE(...)
    if services == "APPLICATION_DEFAULT_SERVICE(APPLICATION_DEFAULT_SERVICE)":
        return "Unknown"
    matches = [p for p in port_keywords if p in services]
    count = len(matches)
    return determine_risk_num(count, 'port_risk')

def calculate_overall_risk(row):
    if any(row[col] == "Unknown" for col in ['sources_risk', 'destinations_risk', 'servicesno_risk', 'appid_risk', 'port_risk']):
        return "Unknown"
    scores = {level: idx+1 for idx, level in enumerate(risk_levels)}  # e.g. {"Low":1, "Medium":2, "High":3}
    total_score = sum(scores[row[col]] * risk_weights[col] for col in risk_weights)
    total_weight = sum(risk_weights.values())
    avg_score = total_score / total_weight

    sorted_thresholds = sorted(overall_risk_thresholds.items(), key=lambda x: x[1])
    for risk_name, threshold in sorted_thresholds:
        if avg_score <= threshold:
            return risk_name
    return "High"

def truncate_field(value, max_len=300):
    if pd.isna(value):
        return value
    if isinstance(value, str) and len(value) > max_len:
        return value[:max_len] + "<truncated>"
    return value

# Main processing
csv_file_path = 'input.csv'  # Replace with your CSV file path
df = pd.read_csv(csv_file_path)

df['sources_no'] = df['sources'].apply(count_ip_addresses)
df['destinations_no'] = df['destinations'].apply(count_ip_addresses)
df['services_no'] = df['services'].apply(count_ports)

df['sources_risk'] = df['sources_no'].apply(determine_risk_num_sources)
df['destinations_risk'] = df['destinations_no'].apply(determine_risk_num_addresses)
df['servicesno_risk'] = df['services_no'].apply(determine_risk_num_services)
df['appid_risk'] = df['applications'].apply(determine_appid_risk)
df['port_risk'] = df['services'].apply(determine_port_risk)

df['overall_risk'] = df.apply(calculate_overall_risk, axis=1)

print("Columns in DataFrame:", df.columns.tolist())  # Debug

columns_to_sort = [
    'overall_risk', 'sources_risk','destinations_risk','servicesno_risk', 'port_risk', 'appid_risk','sources_no',  'destinations_no', 
    'services_no','rule_number', 'rule_name', 'sources', 'destinations', 'services',
    'applications', 'action'
]
remaining_columns = [col for col in df.columns if col not in columns_to_sort]

sorted_df = df[columns_to_sort + remaining_columns]

for col in sorted_df.select_dtypes(include=['object']).columns:
    sorted_df[col] = sorted_df[col].apply(truncate_field)

output_csv_file_path = 'output.csv'
sorted_df.to_csv(output_csv_file_path, index=False)

print(f"CSV file created: {output_csv_file_path}")

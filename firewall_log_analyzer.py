import re
from prettytable import PrettyTable

# Define the log file path here
log_file_path = "firewall_log.txt"

# Define regular expression for log parsing
log_entry_pattern = r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (ALLOW|BLOCK) (TCP|UDP|ICMP) ([\d.]+) ([\d.]+) (\d+) (\d+) (\d+) ([\w\s-]+)"

# Initialize dictionaries and counters for detailed analysis
action_counts = {"ALLOW": 0, "BLOCK": 0}
protocol_counts = {"TCP": 0, "UDP": 0, "ICMP": 0}
source_ip_counts = {}
threat_categories = {"SSH": 0, "DNS": 0, "SQL": 0, "SNMP": 0, "Other": 0}
detailed_logs = []

# Function to analyze log entries
def analyze_log_entry(line):
    match = re.search(log_entry_pattern, line)
    if match:
        date, action, protocol, src_ip, dst_ip, src_port, dst_port, size, info = match.groups()
        
        # Update action and protocol counts
        action_counts[action] += 1
        protocol_counts[protocol] += 1

        # Update source IP counts
        source_ip_counts[src_ip] = source_ip_counts.get(src_ip, 0) + 1

        # Classify threats based on protocol and info
        threat_categories["SSH"] += (1 if protocol == "TCP" and "SSH" in info else 0)
        threat_categories["DNS"] += (1 if protocol == "UDP" and "DNS" in info else 0)
        threat_categories["SQL"] += (1 if protocol == "TCP" and "SQL" in info else 0)
        threat_categories["SNMP"] += (1 if protocol == "UDP" and "SNMP" in info else 0)
        threat_categories["Other"] += (1 if protocol not in ["TCP", "UDP"] else 0)

        # Append summarized log information
        detailed_logs.append({
            "Date": date,
            "Action": action,
            "Protocol": protocol,
            "Src IP": src_ip,
            "Threat Category": get_threat_category(protocol, info),
        })

# Function to get threat category
def get_threat_category(protocol, info):
    if protocol == "TCP" and "SSH" in info:
        return "SSH"
    elif protocol == "UDP" and "DNS" in info:
        return "DNS"
    elif protocol == "TCP" and "SQL" in info:
        return "SQL"
    elif protocol == "UDP" and "SNMP" in info:
        return "SNMP"
    else:
        return "Other"

# Read and analyze the log file
try:
    with open(log_file_path, "r") as log_file:
        for line in log_file:
            if not line.startswith("#"):  # Ignore comments or headers
                analyze_log_entry(line)
except FileNotFoundError:
    print("Log file not found.")
except Exception as e:
    print(f"An error occurred: {str(e)}")

# Generate a concise summary report with insights and recommendations
print("Summary Report:")
print("\nTotal Actions:")
for action, count in action_counts.items():
    print(f"{action}: {count} entries")

print("\nProtocol Distribution:")
for protocol, count in protocol_counts.items():
    print(f"{protocol}: {count} entries")

print("\nSource IP Analysis:")
for source_ip, count in source_ip_counts.items():
    print(f"Source IP: {source_ip}, Count: {count}")

print("\nThreat Categories:")
for threat_category, count in threat_categories.items():
    print(f"{threat_category}: {count} entries")

print("\nLog Information summary:")
table = PrettyTable()
table.field_names = ["Date", "Action", "Protocol", "Source IP", "Threat Category"]
for log_entry in detailed_logs:
    table.add_row([log_entry["Date"], log_entry["Action"], log_entry["Protocol"], log_entry["Src IP"], log_entry["Threat Category"]])

print(table)

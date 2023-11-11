Firewall Log Analyzer

## Overview

ABC Tech Firewall Log Analyzer is a Python script designed to analyze firewall logs generated by ip tables on Linux servers and logs from AWS security groups. The script aims to help in identifying potential threats, understanding traffic patterns, and improving the network's security posture.

## Features

- Parses and analyzes firewall logs from different sources.
- Provides a concise summary of actions, protocol distribution, source IP analysis, and threat categories.
- Outputs detailed and concise log information, including recommendations for potential threats.

## Requirements

- Python 3.x
- Dependencies: (Install dependencies using `pip install -r requirements.txt`)
  - `prettytable` (for tabulating data)

## Usage

1. Clone the repository:

    
    git clone https://github.com/Hanan-Wolverine/Firewall_Log_Analyzer.git
   
    cd firewall-log-analyzer
  

3. Install dependencies:

    
    pip install -r requirements.txt
    

4. Run the script:

	"log_file_path = "firewall_log.txt"  - Make Sure Your Firewall Log file that  mention to this Script in here. And also log file must available in same directory"   

 
        python firewall_log_analyzer.py   (It will show Summary Report in Same terminal)
				or
   	python firewall_log_analyzer.py > firewall_log.txt   ( It will show summary report in firewall_log.txt file which will create in same directory)
	
	 
 

5. View the generated summary and log information.
![Screenshot](https://github.com/Hanan-Wolverine/Firewall_Log_Analyzer/assets/84009927/2f34075f-9ea0-4ff8-947c-c5d93ea5deb4)

"Summary Report:

Total Actions:
ALLOW: 6 entries
BLOCK: 5 entries

Protocol Distribution:
TCP: 8 entries
UDP: 3 entries
ICMP: 0 entries

Source IP Analysis:
Source IP: 192.168.1.105, Count: 5
Source IP: 192.168.1.106, Count: 1
Source IP: 192.168.1.107, Count: 1
Source IP: 192.168.1.108, Count: 1
Source IP: 192.168.1.109, Count: 1
Source IP: 192.168.1.111, Count: 1
Source IP: 192.168.1.112, Count: 1

Threat Categories:
SSH: 2 entries
DNS: 1 entries
SQL: 2 entries
SNMP: 1 entries
Other: 0 entries

Log Information summary:
+---------------------+--------+----------+---------------+-----------------+
|         Date        | Action | Protocol |   Source IP   | Threat Category |
+---------------------+--------+----------+---------------+-----------------+
| 2023-03-15 06:25:31 | ALLOW  |   TCP    | 192.168.1.105 |      Other      |
| 2023-03-15 06:26:45 | BLOCK  |   UDP    | 192.168.1.105 |      Other      |
| 2023-03-15 06:27:02 | ALLOW  |   TCP    | 192.168.1.105 |      Other      |
| 2023-03-15 06:27:58 | BLOCK  |   TCP    | 192.168.1.105 |       SSH       |
| 2023-03-15 06:29:10 | ALLOW  |   UDP    | 192.168.1.105 |       DNS       |
| 2023-03-15 06:30:05 | BLOCK  |   TCP    | 192.168.1.106 |      Other      |
| 2023-03-15 06:30:42 | ALLOW  |   TCP    | 192.168.1.107 |      Other      |
| 2023-03-15 06:31:19 | BLOCK  |   TCP    | 192.168.1.108 |       SQL       |
| 2023-03-15 06:32:00 | ALLOW  |   TCP    | 192.168.1.109 |       SSH       |
| 2023-03-15 06:34:31 | ALLOW  |   TCP    | 192.168.1.111 |       SQL       |
| 2023-03-15 06:35:27 | BLOCK  |   UDP    | 192.168.1.112 |       SNMP      |
+---------------------+--------+----------+---------------+-----------------+"

## Contributing

If you'd like to contribute to the project, please follow the standard GitHub flow: Fork -> Branch -> Pull Request.

## License

This project is licensed under the [MIT License](LICENSE).


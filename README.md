# Tron Security Monitor

A network security monitoring tool that captures and analyzes network traffic in real-time to detect suspicious activity.

## Overview

Tron Security Monitor is a Python-based intrusion detection system (IDS) that monitors network traffic, identifies potential threats, and logs security events. Built as a learning project to understand network security fundamentals and packet analysis.

## Features

- **Real-time Packet Capture**: Monitors all network traffic on specified interface
- **Threat Detection**: Identifies suspicious patterns including:
  - Port scanning attempts
  - Unusual connection patterns
  - High-volume traffic from single sources
  - Potential DDoS patterns
- **Device Discovery**: Automatically identifies devices on the network
- **Event Logging**: Stores all security events in SQLite database
- **Alert System**: Provides real-time notifications of detected threats

## Technologies Used

- **Python 3**: Core programming language
- **Scapy**: Packet manipulation and analysis
- **SQLite**: Event logging and storage
- **Linux**: Operating system (tested on Ubuntu/Kali)

## Prerequisites

- Linux operating system (Ubuntu, Kali, Debian)
- Python 3.8 or higher
- Root/sudo privileges (required for packet capture)
- Network interface in promiscuous mode

## Installation

1. Clone the repository:
```bash
git clone https://github.com/YOUR_USERNAME/tron-security-monitor.git
cd tron-security-monitor
```

2. Create and activate virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Install system dependencies:
```bash
sudo apt update
sudo apt install python3-dev libpcap-dev tcpdump -y
```

## Usage

1. Run with sudo (required for packet capture):
```bash
sudo python3 tron_security.py
```

2. The tool will:
   - Start monitoring network traffic
   - Display real-time alerts in terminal
   - Log events to SQLite database

3. Stop monitoring with `Ctrl+C`

## Configuration

Edit the following variables in `tron_security.py`:

- `INTERFACE`: Network interface to monitor (default: auto-detect)
- `ALERT_THRESHOLD`: Number of suspicious packets before alerting
- Database location: `/tmp/tron_security.db` (modify as needed)

## What I Learned

This project helped me develop skills in:
- Network protocols (TCP/IP, DNS, HTTP/HTTPS)
- Packet analysis with Scapy
- Linux system administration and permissions
- Database design and SQL
- Security concepts (intrusion detection, threat patterns)
- Python programming and debugging

## Future Enhancements

- [ ] Web dashboard for monitoring
- [ ] Email/SMS alert notifications
- [ ] Machine learning for anomaly detection
- [ ] Support for multiple network interfaces
- [ ] Integration with external threat intelligence feeds

## Limitations

- Requires root privileges to capture packets
- May generate false positives on busy networks
- Detection rules are signature-based (not behavior-based)
- Not intended for production use - educational purposes only

## Educational Purpose

This project was created as part of my Computer Information Systems degree at Metropolitan State University of Denver. It demonstrates practical understanding of network security concepts and serves as a foundation for learning cybersecurity principles.

## License

MIT License - See LICENSE file for details

## Author

Gabriel Smith  
Computer Information Systems Student  
Metropolitan State University of Denver  
Expected Graduation: December 2025

## Acknowledgments

- Built with guidance on network security best practices
- Inspired by professional IDS systems like Snort and Suricata
- Special thanks to the Scapy community for excellent documentation

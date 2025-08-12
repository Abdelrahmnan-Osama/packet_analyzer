# Packet Analyzer

A network packet capture tool for Ethernet networks that monitors live traffic and provides protocol statistics (TCP, UDP, ICMP, Other).

## Requirements

- Linux/Unix system with root privileges
- Ethernet network interface
- libpcap library
- GCC compiler with C11 support

## Build Process

### 1. Clone the Repository
```bash
git clone <repository_url>
cd packet_analyzer
```

### 2. Verify Project Files
```bash
ls -la
# Expected files:
# main.c main_utils.c packet_parser.c test_parser.c
# main_utils.h packet_parser.h constants.h
# Makefile
```

### 3. Install Dependencies
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install libpcap-dev build-essential valgrind gdb net-tools

# CentOS/RHEL/Fedora  
sudo yum install libpcap-devel gcc make valgrind gdb net-tools
# or for newer versions:
sudo dnf install libpcap-devel gcc make valgrind gdb net-tools

# Verify installations
pkg-config --modversion libpcap
gcc --version
valgrind --version
```

### 4. Build with Make

#### Available Make Targets
```bash
# Build everything (recommended)
make all

# Build only main application
make packet_analyzer

# Build only test suite  
make test_parser

# Build and run tests
make test

# Clean all generated files
make clean

# Run with custom arguments (requires sudo)
make run ARGS="-i eth0 -t 30 -o stats.txt"

# Memory leak detection with Valgrind (checks for memory issues)
make memcheck ARGS="-i eth0 -t 5"
```

## Usage

```bash
sudo ./packet_analyzer -i <ethernet_interface> [-f <filter>] [-t <seconds>] [-o <output_file>]
```

### Options
- `-i <interface>` - Ethernet interface (required, e.g., eth0, enp0s3, ens33)
- `-f <filter>` - BPF filter expression (optional)
- `-t <seconds>` - Capture duration (optional, 0=indefinite)
- `-o <file>` - Output statistics file (optional, default=console)


### Examples
```bash
# Monitor eth0 for 30 seconds
sudo ./packet_analyzer -i eth0 -t 30

# Capture HTTP traffic to file
sudo ./packet_analyzer -i eth0 -f "tcp port 80" -o web_stats.txt

# Stop capture anytime with Ctrl+C
```

## Troubleshooting

### Compilation Issues
```bash
# Missing pcap headers
sudo apt-get install libpcap-dev

# Missing compiler
sudo apt-get install build-essential

# Verify installation
pkg-config --modversion libpcap
gcc --version
```

### Runtime Issues
```bash
# Permission denied - need root privileges
sudo ./packet_analyzer -i eth0

# Interface not found - check available interfaces  
ip link show

# Unsupported link type - only Ethernet supported
# Error: Unsupported link type (expected Ethernet)
# Solution: Use Ethernet interface (eth0, enp0s3, etc.)
```

## Sample Output
```
Packet Analyzer (E-VAS Tel Team)
---------------------------------
Interface: eth0
Buffer Size: 1000 packets
Filter: none
Duration: 30 seconds
Output File: none

^C
Received signal 2, shutting down...

Final Statistics:
================
[30 seconds elapsed]
Packets captured: 1247
TCP:   856 (68.6%)
UDP:   298 (23.9%)
ICMP:  45 (3.6%)
Other: 48 (3.9%)
Memory usage: 2.1 KB

Packet analyzer terminated.
```
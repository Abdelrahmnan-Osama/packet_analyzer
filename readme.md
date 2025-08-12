# Packet Analyzer

A network packet capture tool for Ethernet networks that monitors live traffic and provides protocol statistics (TCP, UDP, ICMP, Other).

## Requirements

- Linux/Unix system with root privileges
- Ethernet network interface
- libpcap library
- GCC compiler with C11 support

### Install Dependencies
```bash
# Ubuntu/Debian
sudo apt-get install libpcap-dev build-essential

# CentOS/RHEL/Fedora  
sudo yum install libpcap-devel gcc make
```

## Building the Project

### Available Make Targets
```bash
# Build everything (recommended)
make all

# Build only main application
make packet_analyzer

# Build only test suite  
make test_parser

# Build and run tests
make test

# Run with custom arguments (requires sudo)
make run ARGS="-i eth0 -t 30 -o stats.txt"

# Memory leak detection with Valgrind
make memcheck ARGS="-i eth0 -t 5"

# Clean all generated files
make clean
```

### Build Process
1. **Clone/download** the project files
2. **Install dependencies** using commands above
3. **Build the project**:
   ```bash
   make all
   ```
4. **Run tests** to verify build:
   ```bash
   make test
   ```
5. **Test with actual interface**:
   ```bash
   make run ARGS="-i eth0 -t 5"
   ```

## Usage

```bash
sudo ./packet_analyzer -i <ethernet_interface> [-f <filter>] [-t <seconds>] [-o <output_file>]
```

### Options
- `-i <interface>` - Ethernet interface (required, e.g., eth0, enp0s3)
- `-f <filter>` - BPF filter expression (optional)
- `-t <seconds>` - Capture duration (optional, 0=indefinite)
- `-o <file>` - Output statistics file (optional, default=console)

### Examples
```bash
# Monitor eth0 for 30 seconds
sudo ./packet_analyzer -i eth0 -t 30

# Capture HTTP traffic to file
sudo ./packet_analyzer -i eth0 -f "tcp port 80" -o web_stats.txt
```

## Build Troubleshooting

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
# Permission denied - need root
sudo ./packet_analyzer -i eth0

# Interface not found - check available interfaces  
ip link show

# No Ethernet interface found
# Error: Unsupported link type (expected Ethernet)
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
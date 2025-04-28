# PCAP Forensics Parser

A lightweight command-line tool for forensic analysis of PCAP files.  
Parses global headers, per-packet metadata, Ethernet/IPv4/TCP/UDP layers, and generates summaries. Supports verbose output, CSV export, and interactive search.

## Requirements

- Python 3.7 or newer (standard library only)

## Usage

```bash
python3 pcap_forensics_parser.py [options] <capture.pcap>
```

### Options

| Flag                   | Description                                                                                       |
|------------------------|---------------------------------------------------------------------------------------------------|
| `-v`, `--verbose`      | Show full details for each packet: file offsets, MAC addresses, Ethertype, IP headers, ports.     |
| `-o FILE`, `--output`  | Write per-packet data to the specified CSV file (one row per packet with all parsed fields).      |
| `-s`, `--search`       | After parsing, enter an interactive prompt. Type any term (IP, MAC, port, etc.) to filter results. |
| `-h`, `--help`         | Display help message and exit.                                                                    |

## Examples

- **Summary only**  
  ```bash
  python3 pcap_forensics_parser.py capture.pcap
  ```

- **Verbose output**  
  ```bash
  python3 pcap_forensics_parser.py -v capture.pcap
  ```

- **Write CSV and show summary**  
  ```bash
  python3 pcap_forensics_parser.py -o results.csv capture.pcap
  ```

- **Verbose + CSV export**  
  ```bash
  python3 pcap_forensics_parser.py -v -o results.csv capture.pcap
  ```

- **Interactive search**  
  ```bash
  python3 pcap_forensics_parser.py -s capture.pcap
  # > Enter search term: 10.0.0.5
  # (displays only packets matching “10.0.0.5”)
  ```

## Brief Overview of Output

- **Per-packet lines**  
  - Packet number, timestamp, capture/original lengths  
  - (Verbose) File offsets, source/dest MAC, Ethertype, IP addresses, ports, protocol  
- **Summary statistics**  
  - Total packets, total bytes, capture duration  
  - Top talkers (by bytes) and top flows (5-tuple counts)

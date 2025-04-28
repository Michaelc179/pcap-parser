#!/usr/bin/env python3
import sys, struct, argparse, datetime, ipaddress, collections, csv

# PCAP header formats
global_header_fmt = 'IHHIIII'
packet_header_fmt = 'IIII'


def mac_addr(raw):
    return ':'.join(f'{b:02x}' for b in raw)


def parse_ethernet(data):
    dst, src, ethertype = struct.unpack('!6s6sH', data[:14])
    return mac_addr(src), mac_addr(dst), ethertype, data[14:]


def parse_ipv4(data):
    ver_ihl = data[0]
    ihl = (ver_ihl & 0x0F) * 4
    fields = struct.unpack('!BBHHHBBH4s4s', data[:20])
    protocol = fields[6]
    src_ip = str(ipaddress.IPv4Address(fields[8]))
    dst_ip = str(ipaddress.IPv4Address(fields[9]))
    return src_ip, dst_ip, protocol, data[ihl:]


def parse_transport(protocol, data):
    if protocol == 6 and len(data) >= 4:  # TCP
        return struct.unpack('!HH', data[:4])
    if protocol == 17 and len(data) >= 4:  # UDP
        return struct.unpack('!HH', data[:4])
    return None, None


def parse_pcap(path, verbose=False, csvfile=None, search=False):
    with open(path, 'rb') as fp:
        raw = fp.read(struct.calcsize(global_header_fmt))
        if len(raw) < struct.calcsize(global_header_fmt):
            print('File too small to be a PCAP')
            return
        magic = raw[:4]
        if magic == b'\xd4\xc3\xb2\xa1': endian = '<'
        elif magic == b'\xa1\xb2\xc3\xd4': endian = '>'
        else:
            print('Not a PCAP file')
            return
        gh = struct.unpack(endian + global_header_fmt, raw)
        snaplen, linktype = gh[5], gh[6]
        print(f"PCAP v{gh[1]}.{gh[2]}, snaplen={snaplen}, linktype={linktype}\n")

        pkt_fmt = endian + packet_header_fmt
        stats = {
            'total_packets': 0,
            'total_bytes': 0,
            'first_ts': None,
            'last_ts': None,
            'talkers': collections.Counter(),
            'flows': collections.defaultdict(lambda: {'pkts': 0, 'bytes': 0, 'start': None, 'end': None})
        }
        packets = []

        # Prepare CSV writer if requested
        csv_writer = None
        if csvfile:
            out_fp = open(csvfile, 'w', newline='')
            csv_writer = csv.writer(out_fp)
            csv_writer.writerow(["packet_no", "timestamp", "caplen", "origlen", "src_mac", "dst_mac",
                                 "ethertype", "src_ip", "dst_ip", "protocol", "src_port", "dst_port"])

        # Iterate packets
        while True:
            hdr = fp.read(struct.calcsize(packet_header_fmt))
            if len(hdr) < struct.calcsize(packet_header_fmt): break
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(pkt_fmt, hdr)
            data = fp.read(incl_len)
            if len(data) < incl_len: break

            ts = datetime.datetime.fromtimestamp(ts_sec, tz=datetime.timezone.utc) + \
                 datetime.timedelta(microseconds=ts_usec)

            if stats['first_ts'] is None:
                stats['first_ts'] = ts
            stats['last_ts'] = ts
            stats['total_packets'] += 1
            stats['total_bytes'] += incl_len

            src_mac, dst_mac, ethertype, l3 = parse_ethernet(data)
            src_ip = dst_ip = None
            src_port = dst_port = None
            proto = None
            l4 = None

            if ethertype == 0x0800 and len(l3) >= 20:
                src_ip, dst_ip, proto, l4 = parse_ipv4(l3)
                if proto in (6, 17) and l4:
                    src_port, dst_port = parse_transport(proto, l4)

            # Build output line
            if verbose:
                line = (f"[# {stats['total_packets']:4d}] hdr@0x{fp.tell() - incl_len - struct.calcsize(packet_header_fmt):08X} "
                        f"data@0x{fp.tell() - incl_len:08X} time={ts.isoformat()} "
                        f"caplen={incl_len} origlen={orig_len} {src_mac}→{dst_mac} eth=0x{ethertype:04x} ")
                if src_ip and dst_ip:
                    line += f"IP {src_ip}→{dst_ip} proto={proto} "
                if src_port and dst_port:
                    line += f"ports {src_port}→{dst_port}"
            else:
                line = (f"[# {stats['total_packets']:4d}] time={ts.isoformat()} caplen={incl_len} origlen={orig_len}")
                if src_ip and dst_ip:
                    line += f" IP {src_ip}→{dst_ip}"
                if src_port and dst_port:
                    line += f" ports {src_port}→{dst_port}"
            print(line)

            # Store for search and CSV
            packets.append({'line': line, 'search_str': line})
            if csv_writer:
                csv_writer.writerow([stats['total_packets'], ts.isoformat(), incl_len, orig_len,
                                     src_mac, dst_mac, hex(ethertype), src_ip, dst_ip, proto,
                                     src_port, dst_port])

            if src_ip:
                stats['talkers'][src_ip] += incl_len
            if dst_ip:
                stats['talkers'][dst_ip] += incl_len
            if src_ip and dst_ip and proto and src_port is not None:
                key = (src_ip, dst_ip, src_port, dst_port, proto)
                f = stats['flows'][key]
                f['pkts'] += 1
                f['bytes'] += incl_len
                if f['start'] is None:
                    f['start'] = ts
                f['end'] = ts

        # Close CSV file handle
        if csv_writer:
            out_fp.close()

        # Summary
        duration = (stats['last_ts'] - stats['first_ts']) if stats['first_ts'] else None
        print(f"\nTotal packets: {stats['total_packets']}")
        print(f"Total bytes: {stats['total_bytes']}")
        if duration:
            print(f"Capture duration: {duration}\n")

        print("Top 5 talkers (by bytes):")
        for ip, b in stats['talkers'].most_common(5):
            print(f"  {ip}: {b} bytes")

        print("\nTop 5 flows (by bytes):")
        top_flows = sorted(stats['flows'].items(), key=lambda x: x[1]['bytes'], reverse=True)[:5]
        for (sip, dip, sp, dp, pr), info in top_flows:
            print(f"  {sip}:{sp} → {dip}:{dp} proto={pr} -- {info['pkts']} pkts, {info['bytes']} bytes, "
                  f"{info['start'].isoformat()} → {info['end'].isoformat()}" )

        # Interactive search mode
        if search:
            print("\nEnter search terms (or 'exit' to quit):")
            while True:
                term = input('search> ')
                if term.lower() in ('exit', 'quit'):
                    break
                for pkt in packets:
                    if term in pkt['search_str']:
                        print(pkt['line'])

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Forensics-focused PCAP parser")
    parser.add_argument('pcap_file', help='Path to the PCAP file')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output with full packet details')
    parser.add_argument('-o', '--output', metavar='CSV_FILE', help='Write per-packet data to CSV')
    parser.add_argument('-s', '--search', action='store_true', help='Enter interactive search mode after parsing')
    args = parser.parse_args()
    parse_pcap(args.pcap_file, verbose=args.verbose, csvfile=args.output, search=args.search)

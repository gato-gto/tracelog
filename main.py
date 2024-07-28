#!/opt/net_diag/env/bin/python3

import argparse
import asyncio
from scapy.all import IP, TCP, UDP, ICMP, sr1
from datetime import datetime
import socket
from colorama import Fore, Style

COLUMN_WIDTHS = [18, 15]


async def send_packet(host, protocol, port, ttl, timeout=1):
    """Sends a packet with the specified protocol, port, and TTL, and returns the response."""
    if protocol == 'tcp':
        pkt = IP(dst=host, ttl=ttl) / TCP(dport=port, flags='S')
    elif protocol == 'udp':
        pkt = IP(dst=host, ttl=ttl) / UDP(dport=port)
    else:
        pkt = IP(dst=host, ttl=ttl) / ICMP()

    start_time = datetime.now().timestamp()

    def send_pkt():
        return sr1(pkt, verbose=0, timeout=timeout)

    loop = asyncio.get_event_loop()
    reply = await loop.run_in_executor(None, send_pkt)
    end_time = datetime.now().timestamp() + 0.00010
    rtt = round((end_time - start_time) * 1000, 2)
    if reply:
        return reply.src, rtt
    return 'No response', -1


async def traceroute(host, protocol, port, max_hops=32, timeout=1):
    """Performs a traceroute to the specified host and returns the result."""
    results = []
    for ttl in range(1, max_hops + 1):
        reply, rtt = await send_packet(host, protocol, port, ttl, timeout)
        results.append((ttl, reply, rtt))
        if reply == host:
            break
    return results


def get_column_width(index):
    """Returns the column width by index."""
    if index < len(COLUMN_WIDTHS):
        return COLUMN_WIDTHS[index]
    return COLUMN_WIDTHS[-1]


def print_headers(headers, file=None):
    """Prints the table headers."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    header_line = " | ".join(header.center(get_column_width(i)) for i, header in enumerate(headers))
    if file:
        file.write(f"{timestamp} | {header_line}\n")
    else:
        print(f"{timestamp} | {header_line}")


def print_values(values, file=None):
    """Prints the table values."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    value_line = " | ".join(value.center(get_column_width(i)) for i, value in enumerate(values))
    if file:
        file.write(f"{timestamp} | {value_line}\n")
    else:
        print(f"{timestamp} | {value_line}")


async def main(endpoint, interval, protocol, port, max_hops, iterations, output_file=None):
    columns = []
    hop_mapping = {}
    current_values = {}
    last_values = {}
    prev_headers = []

    iteration_count = 0

    file = None
    if output_file:
        try:
            file = open(output_file, 'a')
        except Exception as e:
            print(f"Error opening file {output_file}: {e}")
            return

    try:
        while iterations == 0 or iteration_count < iterations:
            results = await traceroute(endpoint, protocol, port, max_hops)

            for data in results:
                hop, host, rtt = data
                column = f"{host}"
                value = str(rtt) if rtt != -1 else f"{Fore.RED}Loss{Style.RESET_ALL}"

                if column not in columns:
                    columns.append(column)

                hop_mapping[column] = hop
                current_values[column] = value
                last_values[column] = value

            for col in columns:
                if col not in hop_mapping:
                    hop_mapping[col] = -1

            sorted_columns = sorted(columns, key=lambda col: hop_mapping[col])

            if sorted_columns != prev_headers:
                print_headers(sorted_columns, file)
                prev_headers = sorted_columns

            sorted_values = [current_values.get(col, last_values.get(col, f"{Fore.RED}Loss{Style.RESET_ALL}")) for col in sorted_columns]

            print_values(sorted_values, file)

            if file:
                plain_values = [v.replace(Fore.RED, '').replace(Style.RESET_ALL, '') for v in sorted_values]
                file.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | " + " | ".join(plain_values) + "\n")

            current_values = {}
            iteration_count += 1
            await asyncio.sleep(interval)
    finally:
        if file:
            file.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Perform traceroute using ICMP, TCP, or UDP.")
    parser.add_argument("endpoint", type=str, help="Target endpoint")
    parser.add_argument("-i", "--interval", type=int, default=1, help="Interval between traceroute iterations (default: 1 second)")
    parser.add_argument("-p", "--protocol", type=str, default='icmp', choices=['tcp', 'udp', 'icmp'], help="Protocol to use (default: icmp)")
    parser.add_argument("--port", type=int, help="Port to use for TCP and UDP protocols")
    parser.add_argument("-n", "--max_hops", type=int, default=32, help="Maximum number of hops for traceroute (default: 32)")
    parser.add_argument("-c", "--iterations", type=int, default=0, help="Number of traceroute iterations (default: infinite)")
    parser.add_argument("-o", "--output", type=str, help="File path to log the output instead of printing to the console")

    args = parser.parse_args()

    if args.protocol == 'tcp':
        port = args.port if args.port else 80
    elif args.protocol == 'udp':
        port = args.port if args.port else 33434
    else:
        port = None

    asyncio.run(main(args.endpoint, args.interval, args.protocol, port, args.max_hops, args.iterations, args.output))

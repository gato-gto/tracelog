#!/opt/net_diag/env/bin/python3

import argparse
import asyncio
from scapy.all import IP, TCP, UDP, ICMP, sr1
from datetime import datetime
import socket

COLUMN_WIDTHS = [18, 15]


def create_packet(host, ttl, protocol):
    """
    Creates a packet based on the protocol.

    Parameters:
    host (str): The destination host.
    ttl (int): Time-to-Live for the packet.
    protocol (str): Protocol to use ('tcp', 'udp', 'icmp').

    Returns:
    Scapy packet: Constructed packet according to the protocol.
    """
    protocols = {
        'tcp': IP(dst=host, ttl=ttl) / TCP(dport=80, flags='S'),
        'udp': IP(dst=host, ttl=ttl) / UDP(dport=33434),
        'icmp': IP(dst=host, ttl=ttl) / ICMP()
    }
    return protocols.get(protocol)


async def send_probe(host, ttl, timeout, protocol):
    """
    Sends a packet with the specified TTL and returns the response based on the chosen protocol.

    Parameters:
    host (str): The destination host.
    ttl (int): Time-to-Live for the packet.
    timeout (float): Timeout for waiting for a response.
    protocol (str): Protocol to use ('tcp', 'udp', 'icmp').

    Returns:
    tuple: (IP address of the responder, RTT in milliseconds or 'Loss' if no response)
    """
    packet = create_packet(host, ttl, protocol)
    if packet is None:
        raise ValueError("Unsupported protocol")

    start_time = datetime.now().timestamp()
    loop = asyncio.get_event_loop()
    try:
        reply = await loop.run_in_executor(None, lambda: sr1(packet, verbose=0, timeout=timeout))
    except Exception as e:
        print(f"Error sending probe: {e}")
        return "Error", "Loss"
    end_time = datetime.now().timestamp()
    rtt = round((end_time - start_time) * 1000, 1)

    return reply.src if reply else "Not responded", rtt if reply else "Loss"


async def traceroute(host, timeout, max_hops, protocol):
    """
    Performs traceroute to the specified host and returns the result.

    Parameters:
    host (str): The destination host.
    timeout (float): Timeout for waiting for a response.
    max_hops (int): Maximum number of hops.
    protocol (str): Protocol to use ('tcp', 'udp', 'icmp').

    Returns:
    dict: Mapping of TTL to response details (IP and RTT).
    """
    results = {}
    for ttl in range(1, max_hops + 1):
        ip, rtt = await send_probe(host, ttl, timeout, protocol)
        results[ttl] = {'ip': ip, 'rtt': rtt}
        if ip == host:
            break
    return results


def pad_string(string, width):
    """
    Pads string to ensure it has the correct width.

    Parameters:
    string (str): String to pad.
    width (int): Desired width of the string.

    Returns:
    str: Padded string.
    """
    return string + ' ' * (width - len(string))


def print_row(values, file=None):
    """
    Prints a row of the table.

    Parameters:
    values (list): List of values to print.
    file (file object, optional): File to write the output to. Defaults to None.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    row_line = " | ".join(
        pad_string(str(value).center(COLUMN_WIDTHS[min(i, len(COLUMN_WIDTHS) - 1)]),
                   COLUMN_WIDTHS[min(i, len(COLUMN_WIDTHS) - 1)]) for i, value in enumerate(values)
    )
    output = f"{timestamp} | {row_line}"
    if file:
        file.write(output + "\n")
        file.flush()
    else:
        print(output)


def remove_previous_duplicates(lst):
    """
    Removes previous duplicates, keeping only the last occurrence.

    Parameters:
    lst (list): List with potential duplicates.

    Returns:
    list: List with only the last occurrence of each item.
    """
    seen = set()
    result = []
    for item in reversed(lst):
        if item not in seen:
            result.append(item)
            seen.add(item)
    return list(reversed(result))


async def main(endpoint, interval, timeout, max_hops, count, protocol, output_file):
    """
    Main function to execute the traceroute and print the results in a table format.

    Parameters:
    endpoint (str): Target endpoint.
    interval (float): Interval between iterations in seconds.
    timeout (float): Timeout for probe in seconds.
    max_hops (int): Maximum number of hops.
    count (int): Number of iterations.
    protocol (str): Protocol to use.
    output_file (str, optional): File path to log the output instead of printing to the console.
    """
    # Resolve domain name to IP address if necessary
    try:
        endpoint_ip = socket.gethostbyname(endpoint)
    except socket.gaierror as e:
        print(f"Error resolving host {endpoint}: {e}")
        return

    prev_ips = []
    known_ips = {}

    iteration_count = 0
    file = None
    if output_file:
        try:
            file = open(output_file, 'a')
        except Exception as e:
            print(f"Error opening file {output_file}: {e}")
            return

    try:
        while count == 0 or iteration_count < count:
            try:
                results = await traceroute(endpoint_ip, timeout, max_hops, protocol)

                # Update known IPs and ensure columns are sorted by TTL
                for ttl, data in results.items():
                    if data['ip'] != "Not responded":
                        known_ips[ttl] = data['ip']

                sorted_ttls = sorted(known_ips.keys())
                sorted_ips = [known_ips[ttl] for ttl in sorted_ttls]

                # Remove previous duplicates, keeping only the last occurrence
                sorted_ips = remove_previous_duplicates(sorted_ips)

                # Only print header if it changed
                if sorted_ips != prev_ips:
                    prev_ips = sorted_ips
                    print_row(sorted_ips, file)

                # Prepare row values, using known IPs, and handle missing responses
                row_values = []
                for ip in sorted_ips:
                    # Find the TTL for this IP
                    ttl = next((t for t, known_ip in known_ips.items() if known_ip == ip), None)
                    if ttl is not None and ttl in results and results[ttl]['ip'] == ip:
                        row_values.append(results[ttl]['rtt'])
                    else:
                        row_values.append("Loss")

                print_row(row_values, file)

                iteration_count += 1
                await asyncio.sleep(interval)
            except Exception as e:
                print(f"Error during traceroute: {e}")
    finally:
        if file:
            file.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Traceroute tool")
    parser.add_argument("endpoint", type=str, help="Target endpoint")
    parser.add_argument("-i", "--interval", type=float, default=1.0, help="Interval between iterations in seconds (default: 1.0)")
    parser.add_argument("-t", "--timeout", type=float, default=1.0, help="Timeout for probe in seconds (default: 1.0)")
    parser.add_argument("-n", "--max_hops", type=int, default=32, help="Maximum number of hops (default: 32)")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of iterations (default: infinite)")
    parser.add_argument("-p", "--protocol", type=str, default='icmp', choices=['tcp', 'udp', 'icmp'], help="Protocol to use (tcp, udp, icmp)")
    parser.add_argument("-o", "--output", type=str, help="File path to log the output instead of printing to the console")

    args = parser.parse_args()

    asyncio.run(main(args.endpoint, args.interval, args.timeout, args.max_hops, args.count, args.protocol, args.output))

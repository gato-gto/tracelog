# Traceroute Logging Tool

Traceroute Logging Tool is a Python-based utility designed to perform traceroute operations to a specified host. It provides tabular results, highlights route changes, and logs output to a file if desired. The tool supports ICMP, TCP, and UDP protocols.

## Features

- Automatically selects the best network interface based on MAC and IP.
- Option to specify a network interface and gateway manually.
- Logs traceroute results with RTT \(Round Trip Time\) and packet loss details.
- Outputs changes in routes in a highlighted format using \`colorama\`.
- Supports ICMP, TCP, and UDP protocols.

## Requirements

- Python 3.6\+
- \[Scapy\]\(https://scapy.net/\) library
- \[colorama\]\(https://pypi.org/project/colorama/\)
- Python standard asynchronous libraries \(\`asyncio\`\)

## Installation

1. Clone the repository or download the source code:

    \```bash
    git clone https://github.com/yourusername/traceroute-logging-tool.git
    cd traceroute-logging-tool
    \```

2. Create and activate a virtual environment:

    \```bash
    python3 -m venv env
    source env/bin/activate  # On Windows: env\\Scripts\\activate
    \```

3. Install dependencies:

    \```bash
    pip install -r requirements.txt
    \```

## Usage

Run the script with the required arguments:

    python main.py <endpoint> [options]

### Arguments

- `<endpoint>`: Target host \(IP address or domain name\).

### Options

- `-i, --interval`: Interval between iterations in seconds \(default: 1.0\).
- `-t, --timeout`: Timeout for probe in seconds \(default: 1.0\).
- `-n, --max_hops`: Maximum number of hops \(default: 32\).
- `-c, --count`: Number of iterations \(default: infinite\).
- `-p, --protocol`: Protocol to use \(tcp, udp, icmp\) \(default: icmp\).
- `-o, --output`: File path to log the output \(default: print to console\).
- `--port`: Port to use for TCP/UDP \(optional\).
- `--packet_size`: Size of the packet in bytes \(default: 64\).
- `--interface`: Specify a network interface to use \(optional\). If not provided, the tool selects the default interface based on MAC and IP.

### Examples

1. Perform traceroute to `8.8.8.8` using ICMP:

    \```bash
    python main.py 8.8.8.8 -p icmp
    \```

2. Perform traceroute to `google.com` with a 2-second interval and log the results to a file:

    \```bash
    python main.py google.com -i 2 -o /var/log/tracelog
    \```

3. Perform traceroute to `example.com` using TCP protocol on port 80 with a maximum of 16 hops:

    \```bash
    python main.py example.com -p tcp --port 80 -n 16
    \```

4. Perform traceroute to `example.com` using UDP protocol with a packet size of 128 bytes and log the results to a file:

    \```bash
    python main.py example.com -p udp --packet_size 128 -o /var/log/tracelog
    \```

5. Perform traceroute to `example.com` with a 1-second interval, a timeout of 2 seconds, and log the results to a file:

    \```bash
    python main.py example.com -i 1 -t 2 -o /var/log/tracelog
    \```

6. Perform traceroute to `example.com` using a specific network interface:

    \```bash
    python main.py example.com --interface eth0
    \```

## Description

### Functions

1. `create_packet(host, ttl, protocol, port, packet_size)`: Creates a packet based on the protocol and IP version.
2. `send_probe(host, ttl, timeout, protocol, port, packet_size)`: Sends a packet with the specified TTL and returns the response.
3. `send_probe_with_semaphore(host, ttl, timeout, protocol, port, packet_size, semaphore)`: Sends a packet with a semaphore to limit concurrency.
4. `traceroute(host, timeout, max_hops, protocol, port, packet_size, semaphore)`: Performs traceroute to the specified host and returns the result.
5. `pad_string(string, width)`: Pads string to ensure it has the correct width, considering color codes.
6. `print_row(values, file=None)`: Prints a row of the table.
7. `remove_previous_duplicates(lst)`: Removes previous duplicates, keeping only the last occurrence.
8. `compare_routes(old_route, new_route)`: Compares the old route with the new route and highlights changes.
9. `main(endpoint, interval, timeout, max_hops, count, protocol, output_file, port, packet_size, interface)`: Main function to execute traceroute and print/log the results.

### Logic

1. The script resolves the domain name to an IP address.
2. It performs traceroute by sending packets with increasing TTL values.
3. It records the IP addresses and RTT \(Round Trip Time\) for each hop.
4. It outputs the results to the console or logs them to a file.
5. It highlights packet losses and changes in the route using the \`colorama\` library for console output.

## Example Output

Here is an example of the output produced by the script:

`python main.py 93.170.220.1`:

    2024-07-27 17:56:39 |    10.32.57.129    |    10.32.1.1    |    10.254.0.1   |    10.255.2.1   |   93.170.220.1
    2024-07-27 17:56:39 |        80.5        |       54.1      |       49.9      |       46.2      |       54.1
    2024-07-27 17:56:41 |        44.1        |      106.0      |       54.2      |       52.7      |       74.1
    2024-07-27 17:56:42 |        49.3        |       51.6      |       39.2      |       43.2      |       43.4
    2024-07-27 17:56:43 |        41.0        |       46.1      |       38.2      |       42.2      |       46.0
    2024-07-27 17:56:45 |        40.1        |      354.1      |       38.1      |       38.1      |       38.1
    2024-07-27 17:56:46 |        53.0        |       38.1      |       38.1      |       38.1      |       38.1
    2024-07-27 17:56:47 |        40.3        |       38.1      |       38.1      |       38.1      |       38.1
    2024-07-27 17:56:49 |        Loss        |      103.3      |       38.3      |       38.3      |       38.3
    2024-07-27 17:56:52 |        Loss        |      283.7      |       34.4      |       42.3      |       46.3
    2024-07-27 17:56:53 |        64.6        |      450.3      |       50.0      |       42.2      |       58.4
    2024-07-27 17:56:55 |        53.4        |       46.1      |       38.1      |       38.2      |       42.1
    2024-07-27 17:56:56 |        29.2        |       23.5      |       23.6      |       31.9      |       31.5
    2024-07-27 17:56:57 |        44.6        |       38.1      |       38.1      |       49.9      |       46.3
    2024-07-27 17:56:58 |        48.2        |       42.1      |       38.1      |       38.1      |       38.1

## Output Description

- The first row shows the IP addresses of each hop.
- The second row shows the RTT \(Round Trip Time\) in milliseconds for each corresponding hop.
- Each subsequent iteration adds a new set of measurements.
- "Loss" indicates a packet loss at that specific hop.

## License

This project is licensed under the \[MIT License\]\(MIT-LICENSE.txt\).

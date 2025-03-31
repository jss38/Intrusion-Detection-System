# P4-based Intrusion Detection System (IDS)

This repository contains implementations of both stateful and stateless Intrusion Detection Systems using the P4 programming language. The project demonstrates network traffic monitoring and attack detection using programmable data planes.

## Project Structure

The repository is organized into two main directories:

- `ids_stateful/`: Implementation of a stateful IDS that maintains flow state
- `ids_stateless/`: Implementation of a stateless IDS that performs pattern matching without maintaining state

Each directory contains the following components:

- `p4src/`: P4 source code for the IDS implementation
  - `program.p4`: Main P4 program defining packet processing logic
  - `program.json`: Compiled P4 program
  - `program.p4i`: Intermediate representation
- `controller.py`: Python script for packet handling and monitoring
- `network.py`: Network topology definition
- `send.py`: Script to generate and send test packets
- `reg_read.py`: Utility to read register values from the P4 switch
- `s1-commands.txt`, `s2-commands.txt`, `s3-commands.txt`: Switch configuration commands
- `Makefile`: Build automation
- `topology.json`: Network topology configuration
- `log/`: Directory for log files
- `pcap/`: Directory for packet capture files

## Stateful vs. Stateless IDS

### Stateful IDS
The stateful implementation (`ids_stateful/`) maintains information about network flows using registers in the P4 program. It can detect patterns across multiple packets in the same flow, making it more effective at detecting sophisticated attacks that span multiple packets.

### Stateless IDS
The stateless implementation (`ids_stateless/`) performs pattern matching on individual packets without maintaining state between packets. This approach is simpler but may miss attacks that are spread across multiple packets.

## Requirements

- P4 development environment
- Mininet for network emulation
- Python with Scapy library for packet generation and analysis

## Usage

1. Build the P4 program:
   ```
   cd ids_stateful  # or ids_stateless
   make
   ```

2. Run the controller to monitor traffic:
   ```
   python controller.py
   ```

3. Send test packets:
   ```
   python send.py <destination_ip>
   ```

4. Read register values:
   ```
   python reg_read.py
   ```

## Testing

The project includes scripts to generate test traffic with various patterns to evaluate the effectiveness of the IDS implementations. The `send.py` script creates packets with different payload patterns to test detection capabilities.
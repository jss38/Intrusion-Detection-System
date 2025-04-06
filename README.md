# P4-based Intrusion Detection System (IDS)

This repository contains implementations of both stateful and stateless Intrusion Detection Systems using the P4 programming language. The project demonstrates network traffic monitoring and attack detection using programmable data planes.

## Stateful vs. Stateless IDS

### Stateful IDS
The stateful implementation (`ids_stateful/`) maintains information about network flows using registers in the P4 program. It can detect patterns across multiple packets in the same flow, making it more effective at detecting sophisticated attacks that span multiple packets.

### Stateless IDS
The stateless implementation (`ids_stateless/`) performs pattern matching on individual packets without maintaining state between packets. This approach is simpler but may miss attacks that are spread across multiple packets.

## Requirements

- P4 development environment
- Mininet for network emulation
- Python with Scapy library for packet generation and analysis

## Testing

The project includes scripts to generate test traffic with various patterns to evaluate the effectiveness of the IDS implementations. The `send.py` script creates packets with different payload patterns to test detection capabilities.

#!/usr/bin/env python3
# Copyright (c) 2026 The FlowCoin Developers
# Distributed under the MIT software license.
#
# Generate hardcoded seed node list for FlowCoin.
#
# Reads a list of known nodes (from DNS seeds or manual list),
# tests connectivity, and outputs C++ source for seeds.h
#
# Usage:
#     python3 generate_seeds.py --dns seed1.flowcoin.org --output ../src/net/seeds_generated.h
#     python3 generate_seeds.py --input nodes.txt --output ../src/net/seeds_generated.h

import argparse
import ipaddress
import json
import os
import socket
import struct
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone


DEFAULT_PORT = 9333
CONNECT_TIMEOUT = 5.0
PROTOCOL_VERSION = 1
# FlowCoin wire magic: ASCII "FLOW" = 0x464C4F57
MAGIC_BYTES = b'\x46\x4C\x4F\x57'
HEADER_SIZE = 24
VERSION_CMD = b'version\x00\x00\x00\x00\x00'


def resolve_dns(hostname: str) -> list[str]:
    """Resolve a hostname to a list of IP addresses (IPv4 and IPv6)."""
    results = []
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            infos = socket.getaddrinfo(hostname, None, family, socket.SOCK_STREAM)
            for info in infos:
                addr = info[4][0]
                if addr not in results:
                    results.append(addr)
        except socket.gaierror:
            pass
    return results


def parse_ip_port(entry: str) -> tuple[str, int]:
    """Parse an IP:port string. Handles IPv6 bracket notation [::1]:9333."""
    entry = entry.strip()
    if not entry:
        raise ValueError("empty entry")
    if entry.startswith('['):
        # IPv6 bracket notation
        bracket_end = entry.find(']')
        if bracket_end < 0:
            raise ValueError(f"malformed IPv6 bracket notation: {entry}")
        ip_str = entry[1:bracket_end]
        rest = entry[bracket_end + 1:]
        if rest.startswith(':'):
            port = int(rest[1:])
        else:
            port = DEFAULT_PORT
    elif entry.count(':') == 1:
        # IPv4:port
        parts = entry.split(':')
        ip_str = parts[0]
        port = int(parts[1])
    elif entry.count(':') > 1:
        # Raw IPv6 without port
        ip_str = entry
        port = DEFAULT_PORT
    else:
        ip_str = entry
        port = DEFAULT_PORT
    return ip_str, port


def ip_to_bytes(ip_str: str) -> bytes:
    """Convert an IP address string to 16-byte representation.
    IPv4 addresses are stored as IPv4-mapped IPv6: ::ffff:x.x.x.x
    """
    addr = ipaddress.ip_address(ip_str)
    if isinstance(addr, ipaddress.IPv4Address):
        return b'\x00' * 10 + b'\xff\xff' + addr.packed
    return addr.packed


def bytes_to_ip(raw: bytes) -> str:
    """Convert 16-byte IP representation back to a human-readable string."""
    if raw[:12] == b'\x00' * 10 + b'\xff\xff':
        return str(ipaddress.IPv4Address(raw[12:]))
    return str(ipaddress.IPv6Address(raw))


def build_version_payload() -> bytes:
    """Build a minimal version message payload for protocol handshake."""
    version = struct.pack('<I', PROTOCOL_VERSION)
    services = struct.pack('<Q', 1)  # NODE_NETWORK
    timestamp = struct.pack('<q', int(time.time()))
    # addr_recv: 16 bytes IP + 2 bytes port
    addr_recv = b'\x00' * 16 + struct.pack('>H', DEFAULT_PORT)
    # addr_from
    addr_from = b'\x00' * 16 + struct.pack('>H', DEFAULT_PORT)
    nonce = struct.pack('<Q', 0)
    # user_agent as compact string
    user_agent = b'/flowcoin-seedgen:1.0/'
    ua_len = len(user_agent)
    ua_compact = bytes([ua_len]) + user_agent
    start_height = struct.pack('<Q', 0)
    return version + services + timestamp + addr_recv + addr_from + nonce + ua_compact + start_height


def compute_checksum(payload: bytes) -> bytes:
    """Compute the FlowCoin message checksum: first 4 bytes of keccak256(payload).
    Falls back to SHA-256 if keccak is not available.
    """
    try:
        from hashlib import sha3_256 as keccak_func
    except ImportError:
        from hashlib import sha256 as keccak_func
    h = keccak_func(payload).digest()
    return h[:4]


def build_message(command: bytes, payload: bytes) -> bytes:
    """Build a FlowCoin wire protocol message."""
    checksum = compute_checksum(payload)
    header = MAGIC_BYTES + command + struct.pack('<I', len(payload)) + checksum
    return header + payload


def test_node(ip_str: str, port: int) -> dict | None:
    """Test connectivity to a FlowCoin node.
    Performs a TCP connect and attempts a version handshake.
    Returns node info dict on success, None on failure.
    """
    family = socket.AF_INET6 if ':' in ip_str else socket.AF_INET
    sock = None
    try:
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(CONNECT_TIMEOUT)
        sock.connect((ip_str, port))

        # Send version message
        payload = build_version_payload()
        msg = build_message(VERSION_CMD, payload)
        sock.sendall(msg)

        # Wait for any response (version or verack)
        response = sock.recv(HEADER_SIZE + 512)
        if len(response) < HEADER_SIZE:
            return None

        # Check magic bytes
        if response[:4] != MAGIC_BYTES:
            return None

        # Parse command from response header
        resp_cmd = response[4:16].rstrip(b'\x00').decode('ascii', errors='replace')

        # Extract protocol version if we got a version response
        remote_version = 0
        if resp_cmd == 'version' and len(response) >= HEADER_SIZE + 4:
            payload_start = HEADER_SIZE
            remote_version = struct.unpack('<I', response[payload_start:payload_start + 4])[0]

        return {
            'ip': ip_str,
            'port': port,
            'protocol_version': remote_version,
            'response_cmd': resp_cmd,
            'family': 'ipv6' if family == socket.AF_INET6 else 'ipv4',
        }
    except (OSError, socket.timeout, ConnectionRefusedError, ConnectionResetError):
        return None
    finally:
        if sock:
            try:
                sock.close()
            except OSError:
                pass


def load_nodes_from_file(path: str) -> list[tuple[str, int]]:
    """Load node entries from a text file (one per line, IP:port or IP)."""
    nodes = []
    with open(path, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            try:
                ip, port = parse_ip_port(line)
                # Validate the IP address
                ipaddress.ip_address(ip)
                nodes.append((ip, port))
            except (ValueError, TypeError) as e:
                print(f"  warning: skipping invalid entry '{line}': {e}", file=sys.stderr)
    return nodes


def generate_cpp_header(good_nodes: list[dict], output_path: str) -> None:
    """Generate a C++ header file containing the tested seed addresses."""
    now = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    ipv4_nodes = [n for n in good_nodes if n['family'] == 'ipv4']
    ipv6_nodes = [n for n in good_nodes if n['family'] == 'ipv6']

    lines = []
    lines.append('// Copyright (c) 2026 The FlowCoin Developers')
    lines.append('// Distributed under the MIT software license.')
    lines.append('//')
    lines.append(f'// Auto-generated by contrib/seeds/generate_seeds.py on {now}')
    lines.append(f'// Total: {len(good_nodes)} nodes ({len(ipv4_nodes)} IPv4, {len(ipv6_nodes)} IPv6)')
    lines.append('//')
    lines.append('// Each entry is a 18-byte record: 16 bytes IPv6-mapped IP + 2 bytes port (BE)')
    lines.append('')
    lines.append('#pragma once')
    lines.append('')
    lines.append('#include <cstdint>')
    lines.append('#include <cstddef>')
    lines.append('')
    lines.append('namespace flow {')
    lines.append('')

    # IPv4 seeds
    lines.append(f'static const uint8_t SEED_NODES_IPV4[][18] = {{')
    for node in ipv4_nodes:
        raw = ip_to_bytes(node['ip'])
        port_bytes = struct.pack('>H', node['port'])
        hex_str = ', '.join(f'0x{b:02x}' for b in raw + port_bytes)
        lines.append(f'    {{{hex_str}}},  // {node["ip"]}:{node["port"]}')
    if not ipv4_nodes:
        lines.append('    {0}  // placeholder')
    lines.append('};')
    lines.append(f'static const size_t SEED_NODES_IPV4_COUNT = {len(ipv4_nodes)};')
    lines.append('')

    # IPv6 seeds
    lines.append(f'static const uint8_t SEED_NODES_IPV6[][18] = {{')
    for node in ipv6_nodes:
        raw = ip_to_bytes(node['ip'])
        port_bytes = struct.pack('>H', node['port'])
        hex_str = ', '.join(f'0x{b:02x}' for b in raw + port_bytes)
        lines.append(f'    {{{hex_str}}},  // [{node["ip"]}]:{node["port"]}')
    if not ipv6_nodes:
        lines.append('    {0}  // placeholder')
    lines.append('};')
    lines.append(f'static const size_t SEED_NODES_IPV6_COUNT = {len(ipv6_nodes)};')
    lines.append('')
    lines.append('} // namespace flow')
    lines.append('')

    with open(output_path, 'w') as f:
        f.write('\n'.join(lines))
    print(f"Wrote {output_path} with {len(good_nodes)} seed nodes")


def generate_json_report(good_nodes: list[dict], failed_count: int, output_path: str) -> None:
    """Write a JSON report of the scan results."""
    report = {
        'generated': datetime.now(timezone.utc).isoformat(),
        'total_tested': len(good_nodes) + failed_count,
        'reachable': len(good_nodes),
        'unreachable': failed_count,
        'nodes': good_nodes,
    }
    json_path = output_path.replace('.h', '.json')
    with open(json_path, 'w') as f:
        json.dump(report, f, indent=2)
    print(f"Wrote scan report to {json_path}")


def main():
    parser = argparse.ArgumentParser(
        description='Generate hardcoded seed node list for FlowCoin',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            'Examples:\n'
            '  python3 generate_seeds.py --dns seed1.flowcoin.org --output seeds_generated.h\n'
            '  python3 generate_seeds.py --input nodes.txt --output seeds_generated.h\n'
            '  python3 generate_seeds.py --dns seed1.flowcoin.org --dns seed2.flowcoin.org -j 32\n'
        )
    )
    parser.add_argument('--dns', action='append', default=[],
                        help='DNS seed hostname to resolve (can be specified multiple times)')
    parser.add_argument('--input', '-i', type=str, default=None,
                        help='Input file with IP:port entries (one per line)')
    parser.add_argument('--output', '-o', type=str, default='seeds_generated.h',
                        help='Output C++ header file path (default: seeds_generated.h)')
    parser.add_argument('--port', '-p', type=int, default=DEFAULT_PORT,
                        help=f'Default port if not specified per-node (default: {DEFAULT_PORT})')
    parser.add_argument('--jobs', '-j', type=int, default=16,
                        help='Number of parallel connection test threads (default: 16)')
    parser.add_argument('--timeout', '-t', type=float, default=CONNECT_TIMEOUT,
                        help=f'Connection timeout in seconds (default: {CONNECT_TIMEOUT})')
    parser.add_argument('--min-version', type=int, default=0,
                        help='Minimum protocol version to accept (default: 0 = any)')
    parser.add_argument('--no-test', action='store_true',
                        help='Skip connectivity testing (include all resolved IPs)')
    parser.add_argument('--json', action='store_true',
                        help='Also write a JSON scan report alongside the header')

    args = parser.parse_args()

    global CONNECT_TIMEOUT, DEFAULT_PORT
    CONNECT_TIMEOUT = args.timeout
    DEFAULT_PORT = args.port

    # Collect candidate nodes
    candidates: list[tuple[str, int]] = []

    for hostname in args.dns:
        print(f"Resolving DNS seed: {hostname}")
        ips = resolve_dns(hostname)
        if not ips:
            print(f"  warning: no addresses found for {hostname}", file=sys.stderr)
            continue
        print(f"  resolved {len(ips)} addresses")
        for ip in ips:
            candidates.append((ip, args.port))

    if args.input:
        print(f"Loading nodes from {args.input}")
        file_nodes = load_nodes_from_file(args.input)
        print(f"  loaded {len(file_nodes)} entries")
        candidates.extend(file_nodes)

    if not candidates:
        print("Error: no candidate nodes. Specify --dns or --input.", file=sys.stderr)
        sys.exit(1)

    # Deduplicate
    seen = set()
    unique = []
    for ip, port in candidates:
        key = (ip, port)
        if key not in seen:
            seen.add(key)
            unique.append((ip, port))
    candidates = unique
    print(f"\nTesting {len(candidates)} unique candidate nodes (timeout={args.timeout}s, threads={args.jobs})")

    if args.no_test:
        good_nodes = []
        for ip, port in candidates:
            family = 'ipv6' if ':' in ip else 'ipv4'
            good_nodes.append({
                'ip': ip,
                'port': port,
                'protocol_version': 0,
                'response_cmd': 'untested',
                'family': family,
            })
        failed_count = 0
    else:
        good_nodes = []
        failed_count = 0
        with ThreadPoolExecutor(max_workers=args.jobs) as executor:
            futures = {}
            for ip, port in candidates:
                fut = executor.submit(test_node, ip, port)
                futures[fut] = (ip, port)

            done = 0
            total = len(futures)
            for fut in as_completed(futures):
                done += 1
                ip, port = futures[fut]
                result = fut.result()
                status_char = '.'
                if result is not None:
                    if args.min_version > 0 and result['protocol_version'] < args.min_version:
                        status_char = 'v'
                        failed_count += 1
                    else:
                        good_nodes.append(result)
                        status_char = '+'
                else:
                    failed_count += 1
                    status_char = 'x'
                # Progress indicator
                if done % 10 == 0 or done == total:
                    print(f"  [{done}/{total}] {status_char}", end='\r')

    print(f"\n\nResults: {len(good_nodes)} reachable, {failed_count} unreachable")

    # Sort: IPv4 first, then IPv6, each sorted by IP
    good_nodes.sort(key=lambda n: (0 if n['family'] == 'ipv4' else 1, n['ip']))

    generate_cpp_header(good_nodes, args.output)

    if args.json:
        generate_json_report(good_nodes, failed_count, args.output)


if __name__ == '__main__':
    main()

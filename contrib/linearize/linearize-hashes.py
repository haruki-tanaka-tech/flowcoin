#!/usr/bin/env python3
# Copyright (c) 2026 The FlowCoin Developers
# Distributed under the MIT software license.
#
# Fetch block hashes from flowcoind via RPC.
# Output: one hash per line, from genesis to tip.
# Used as input for linearize-data.py
#
# Usage:
#     python3 linearize-hashes.py --rpcuser=flowcoin --rpcpassword=pass > hashes.txt
#     python3 linearize-hashes.py --config=/path/to/flowcoin.conf > hashes.txt

import argparse
import base64
import http.client
import json
import os
import re
import sys
import time


class RPCConnection:
    """JSON-RPC connection to flowcoind."""

    def __init__(self, host: str, port: int, user: str, password: str,
                 timeout: float = 30.0):
        self.host = host
        self.port = port
        self.auth = base64.b64encode(f'{user}:{password}'.encode()).decode()
        self.timeout = timeout
        self._conn = None
        self._id_counter = 0

    def _connect(self) -> None:
        """Establish HTTP connection."""
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception:
                pass
        self._conn = http.client.HTTPConnection(
            self.host, self.port, timeout=self.timeout)

    def call(self, method: str, params: list = None) -> dict:
        """Execute an RPC call and return the result."""
        if params is None:
            params = []
        self._id_counter += 1
        payload = json.dumps({
            'jsonrpc': '1.0',
            'id': self._id_counter,
            'method': method,
            'params': params,
        })
        headers = {
            'Authorization': f'Basic {self.auth}',
            'Content-Type': 'application/json',
        }
        for attempt in range(3):
            try:
                if self._conn is None:
                    self._connect()
                self._conn.request('POST', '/', payload, headers)
                response = self._conn.getresponse()
                body = response.read().decode()
                if response.status == 401:
                    raise RuntimeError('RPC authentication failed (401)')
                if response.status == 403:
                    raise RuntimeError('RPC access forbidden (403) - check rpcallowip')
                result = json.loads(body)
                if result.get('error') is not None:
                    err = result['error']
                    raise RuntimeError(
                        f'RPC error {err.get("code", "?")}: {err.get("message", "unknown")}')
                return result['result']
            except (http.client.HTTPException, ConnectionError, OSError) as e:
                self._conn = None
                if attempt == 2:
                    raise RuntimeError(f'RPC connection failed after 3 attempts: {e}')
                time.sleep(0.5 * (attempt + 1))
        raise RuntimeError('RPC call failed')

    def close(self) -> None:
        """Close the HTTP connection."""
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None


def parse_config_file(path: str) -> dict:
    """Parse a flowcoin.conf file and return key-value pairs."""
    config = {}
    if not os.path.exists(path):
        return config
    with open(path, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            match = re.match(r'^(\w+)\s*=\s*(.+)$', line)
            if match:
                config[match.group(1)] = match.group(2).strip()
    return config


def default_datadir() -> str:
    """Return the default FlowCoin data directory for the current platform."""
    home = os.path.expanduser('~')
    if sys.platform == 'darwin':
        return os.path.join(home, 'Library', 'Application Support', 'FlowCoin')
    elif sys.platform == 'win32':
        appdata = os.environ.get('APPDATA', home)
        return os.path.join(appdata, 'FlowCoin')
    return os.path.join(home, '.flowcoin')


def main():
    parser = argparse.ArgumentParser(
        description='Fetch block hashes from flowcoind via RPC')
    parser.add_argument('--config', type=str, default=None,
                        help='Path to flowcoin.conf (default: auto-detect)')
    parser.add_argument('--rpchost', type=str, default=None,
                        help='RPC host (default: 127.0.0.1)')
    parser.add_argument('--rpcport', type=int, default=None,
                        help='RPC port (default: 9334)')
    parser.add_argument('--rpcuser', type=str, default=None,
                        help='RPC username')
    parser.add_argument('--rpcpassword', type=str, default=None,
                        help='RPC password')
    parser.add_argument('--start', type=int, default=0,
                        help='Starting block height (default: 0)')
    parser.add_argument('--end', type=int, default=None,
                        help='Ending block height (default: chain tip)')
    parser.add_argument('--output', '-o', type=str, default=None,
                        help='Output file (default: stdout)')
    parser.add_argument('--progress', action='store_true', default=True,
                        help='Show progress on stderr (default: True)')
    parser.add_argument('--no-progress', action='store_false', dest='progress',
                        help='Suppress progress output')

    args = parser.parse_args()

    # Load config file if available
    config = {}
    if args.config:
        config = parse_config_file(args.config)
    else:
        default_conf = os.path.join(default_datadir(), 'flowcoin.conf')
        if os.path.exists(default_conf):
            config = parse_config_file(default_conf)
            if args.progress:
                print(f'Loaded config from {default_conf}', file=sys.stderr)

    # Merge command-line args over config file values
    host = args.rpchost or config.get('rpcbind', '127.0.0.1')
    port = args.rpcport or int(config.get('rpcport', '9334'))
    user = args.rpcuser or config.get('rpcuser', '')
    password = args.rpcpassword or config.get('rpcpassword', '')

    if not user or not password:
        print('Error: rpcuser and rpcpassword are required.', file=sys.stderr)
        print('Specify via --rpcuser/--rpcpassword or in flowcoin.conf', file=sys.stderr)
        sys.exit(1)

    rpc = RPCConnection(host, port, user, password)

    # Determine height range
    start_height = args.start
    if args.end is not None:
        end_height = args.end
    else:
        end_height = rpc.call('getblockcount')
        if args.progress:
            print(f'Chain height: {end_height}', file=sys.stderr)

    total = end_height - start_height + 1
    if total <= 0:
        print(f'Error: no blocks in range [{start_height}, {end_height}]', file=sys.stderr)
        sys.exit(1)

    # Open output
    out_file = sys.stdout
    if args.output:
        out_file = open(args.output, 'w')

    # Fetch hashes
    batch_size = 500
    fetched = 0
    t_start = time.monotonic()

    try:
        height = start_height
        while height <= end_height:
            block_hash = rpc.call('getblockhash', [height])
            out_file.write(block_hash + '\n')
            fetched += 1
            height += 1

            if args.progress and fetched % batch_size == 0:
                elapsed = time.monotonic() - t_start
                rate = fetched / elapsed if elapsed > 0 else 0
                pct = 100.0 * fetched / total
                eta = (total - fetched) / rate if rate > 0 else 0
                print(
                    f'\r  [{fetched}/{total}] {pct:.1f}% '
                    f'({rate:.0f} hashes/s, ETA {eta:.0f}s)',
                    end='', file=sys.stderr)

    except KeyboardInterrupt:
        if args.progress:
            print(f'\nInterrupted at height {height - 1}', file=sys.stderr)
    except RuntimeError as e:
        print(f'\nRPC error at height {height}: {e}', file=sys.stderr)
        sys.exit(1)
    finally:
        rpc.close()
        if args.output and out_file is not sys.stdout:
            out_file.close()

    if args.progress:
        elapsed = time.monotonic() - t_start
        print(f'\n  Done: {fetched} hashes in {elapsed:.1f}s', file=sys.stderr)


if __name__ == '__main__':
    main()

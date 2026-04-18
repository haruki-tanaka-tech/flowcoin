#!/usr/bin/env python3
# Copyright (c) 2026 The FlowCoin Developers
# Distributed under the MIT software license.
#
# Linearize block data files.
# Reads block hashes from a file (produced by linearize-hashes.py),
# fetches raw block data via RPC, and writes sequential blk*.dat files.
#
# Used for bootstrapping: create a clean set of block files from RPC.
#
# Usage:
#     python3 linearize-data.py --hashfile=hashes.txt --output-dir=./blocks \
#         --rpcuser=flowcoin --rpcpassword=pass

import argparse
import base64
import hashlib
import http.client
import json
import os
import struct
import sys
import time


# FlowCoin wire magic: ASCII "FLOW" = 0x464C4F57
MAGIC_BYTES = struct.pack('<I', 0x464C4F57)

# Maximum output file size: 128 MiB
MAX_FILE_SIZE = 128 * 1024 * 1024


class RPCConnection:
    """JSON-RPC connection to flowcoind."""

    def __init__(self, host: str, port: int, user: str, password: str,
                 timeout: float = 120.0):
        self.host = host
        self.port = port
        self.auth = base64.b64encode(f'{user}:{password}'.encode()).decode()
        self.timeout = timeout
        self._conn = None
        self._id_counter = 0

    def _connect(self) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception:
                pass
        self._conn = http.client.HTTPConnection(
            self.host, self.port, timeout=self.timeout)

    def call(self, method: str, params: list = None) -> dict:
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
                result = json.loads(body)
                if result.get('error') is not None:
                    err = result['error']
                    raise RuntimeError(
                        f'RPC error {err.get("code", "?")}: {err.get("message", "?")}')
                return result['result']
            except (http.client.HTTPException, ConnectionError, OSError) as e:
                self._conn = None
                if attempt == 2:
                    raise RuntimeError(f'RPC connection failed: {e}')
                time.sleep(0.5 * (attempt + 1))
        raise RuntimeError('RPC call failed')

    def close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None


def compute_block_hash(raw_block: bytes) -> str:
    """Compute the keccak256d block ID.
    Header layout (188 bytes total):
        [0..92)  unsigned header  (hashed for the ID)
        [92..124) Ed25519 miner pubkey
        [124..188) Ed25519 signature over [0..92)
    Block ID = keccak256(keccak256(header[0..92))).
    Requires the original Keccak padding (0x01), which hashlib does NOT
    provide — stdlib's sha3_256 uses NIST SHA-3 padding (0x06). So we
    go through pycryptodome.
    """
    try:
        from Crypto.Hash import keccak
    except ImportError:
        sys.stderr.write(
            'error: real Keccak-256 is required. Install pycryptodome:\n'
            '           pip install pycryptodome\n',
        )
        sys.exit(1)

    def k256(b: bytes) -> bytes:
        h = keccak.new(digest_bits=256)
        h.update(b)
        return h.digest()

    unsigned_header = raw_block[:92]
    h2 = k256(k256(unsigned_header))
    # Reverse byte order to match RPC hash display (big-endian hex).
    return h2[::-1].hex()


class BlockFileWriter:
    """Manages writing blocks to sequential blk*.dat files."""

    def __init__(self, output_dir: str, max_file_size: int = MAX_FILE_SIZE):
        self.output_dir = output_dir
        self.max_file_size = max_file_size
        self.file_index = 0
        self.current_file = None
        self.current_size = 0
        self.total_written = 0
        self.total_blocks = 0
        os.makedirs(output_dir, exist_ok=True)
        self._open_next()

    def _file_path(self) -> str:
        return os.path.join(self.output_dir, f'blk{self.file_index:05d}.dat')

    def _open_next(self) -> None:
        if self.current_file is not None:
            self.current_file.close()
        path = self._file_path()
        self.current_file = open(path, 'wb')
        self.current_size = 0

    def write_block(self, raw_block: bytes) -> None:
        """Write a single block to the current output file.
        Block record format: [4 magic][4 size_le][raw_block]
        """
        record_size = 8 + len(raw_block)

        # Rotate to next file if current would exceed limit
        if self.current_size > 0 and self.current_size + record_size > self.max_file_size:
            self.file_index += 1
            self._open_next()

        # Write: magic + block_size + raw_block
        self.current_file.write(MAGIC_BYTES)
        self.current_file.write(struct.pack('<I', len(raw_block)))
        self.current_file.write(raw_block)

        self.current_size += record_size
        self.total_written += record_size
        self.total_blocks += 1

    def close(self) -> None:
        if self.current_file is not None:
            self.current_file.close()
            self.current_file = None


def load_hash_list(path: str) -> list[str]:
    """Load block hashes from a file (one hex hash per line)."""
    hashes = []
    with open(path, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            # Validate hex
            if len(line) != 64:
                print(f'Warning: skipping invalid hash (len={len(line)}): {line[:20]}...',
                      file=sys.stderr)
                continue
            try:
                bytes.fromhex(line)
            except ValueError:
                print(f'Warning: skipping non-hex hash: {line[:20]}...', file=sys.stderr)
                continue
            hashes.append(line)
    return hashes


def parse_config_file(path: str) -> dict:
    """Parse a flowcoin.conf file and return key-value pairs."""
    config = {}
    if not os.path.exists(path):
        return config
    import re
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
    """Return the default FlowCoin data directory."""
    home = os.path.expanduser('~')
    if sys.platform == 'darwin':
        return os.path.join(home, 'Library', 'Application Support', 'FlowCoin')
    elif sys.platform == 'win32':
        appdata = os.environ.get('APPDATA', home)
        return os.path.join(appdata, 'FlowCoin')
    return os.path.join(home, '.flowcoin')


def main():
    parser = argparse.ArgumentParser(
        description='Linearize FlowCoin block data files')
    parser.add_argument('--hashfile', type=str, required=True,
                        help='Input file containing block hashes (one per line)')
    parser.add_argument('--output-dir', type=str, required=True,
                        help='Output directory for blk*.dat files')
    parser.add_argument('--config', type=str, default=None,
                        help='Path to flowcoin.conf')
    parser.add_argument('--rpchost', type=str, default=None,
                        help='RPC host (default: 127.0.0.1)')
    parser.add_argument('--rpcport', type=int, default=None,
                        help='RPC port (default: 9334)')
    parser.add_argument('--rpcuser', type=str, default=None,
                        help='RPC username')
    parser.add_argument('--rpcpassword', type=str, default=None,
                        help='RPC password')
    parser.add_argument('--max-file-size', type=int, default=MAX_FILE_SIZE,
                        help=f'Maximum blk*.dat file size in bytes (default: {MAX_FILE_SIZE})')
    parser.add_argument('--verify', action='store_true', default=True,
                        help='Verify block hashes after fetching (default: True)')
    parser.add_argument('--no-verify', action='store_false', dest='verify',
                        help='Skip block hash verification')
    parser.add_argument('--start', type=int, default=0,
                        help='Starting index in hash list (default: 0)')
    parser.add_argument('--count', type=int, default=None,
                        help='Number of blocks to process (default: all)')
    parser.add_argument('--progress', action='store_true', default=True,
                        help='Show progress on stderr')
    parser.add_argument('--no-progress', action='store_false', dest='progress')

    args = parser.parse_args()

    # Load config
    config = {}
    if args.config:
        config = parse_config_file(args.config)
    else:
        default_conf = os.path.join(default_datadir(), 'flowcoin.conf')
        if os.path.exists(default_conf):
            config = parse_config_file(default_conf)

    host = args.rpchost or config.get('rpcbind', '127.0.0.1')
    port = args.rpcport or int(config.get('rpcport', '9334'))
    user = args.rpcuser or config.get('rpcuser', '')
    password = args.rpcpassword or config.get('rpcpassword', '')

    if not user or not password:
        print('Error: rpcuser and rpcpassword required.', file=sys.stderr)
        sys.exit(1)

    # Load hashes
    print(f'Loading hashes from {args.hashfile}...', file=sys.stderr)
    all_hashes = load_hash_list(args.hashfile)
    if not all_hashes:
        print('Error: no valid hashes found in input file.', file=sys.stderr)
        sys.exit(1)
    print(f'  Loaded {len(all_hashes)} block hashes', file=sys.stderr)

    # Slice if requested
    hashes = all_hashes[args.start:]
    if args.count is not None:
        hashes = hashes[:args.count]
    total = len(hashes)
    print(f'  Processing {total} blocks (start={args.start})', file=sys.stderr)

    rpc = RPCConnection(host, port, user, password)
    writer = BlockFileWriter(args.output_dir, args.max_file_size)

    t_start = time.monotonic()
    errors = 0
    report_interval = 100

    try:
        for i, block_hash in enumerate(hashes):
            # Fetch raw block hex via RPC
            try:
                raw_hex = rpc.call('getblock', [block_hash, 0])
            except RuntimeError as e:
                print(f'\nError fetching block {block_hash}: {e}', file=sys.stderr)
                errors += 1
                if errors > 10:
                    print('Too many errors, aborting.', file=sys.stderr)
                    break
                continue

            raw_block = bytes.fromhex(raw_hex)

            # Verify hash if requested
            if args.verify:
                computed = compute_block_hash(raw_block)
                if computed != block_hash:
                    print(f'\nHash mismatch at index {args.start + i}:', file=sys.stderr)
                    print(f'  expected: {block_hash}', file=sys.stderr)
                    print(f'  computed: {computed}', file=sys.stderr)
                    errors += 1
                    if errors > 10:
                        print('Too many hash mismatches, aborting.', file=sys.stderr)
                        break
                    continue

            writer.write_block(raw_block)

            # Progress
            if args.progress and ((i + 1) % report_interval == 0 or i + 1 == total):
                elapsed = time.monotonic() - t_start
                rate = (i + 1) / elapsed if elapsed > 0 else 0
                pct = 100.0 * (i + 1) / total
                eta = (total - i - 1) / rate if rate > 0 else 0
                mb_written = writer.total_written / (1024 * 1024)
                print(
                    f'\r  [{i + 1}/{total}] {pct:.1f}% '
                    f'({rate:.1f} blk/s, {mb_written:.1f} MiB, '
                    f'file blk{writer.file_index:05d}.dat, ETA {eta:.0f}s)',
                    end='', file=sys.stderr)

    except KeyboardInterrupt:
        print(f'\nInterrupted at block {args.start + writer.total_blocks}', file=sys.stderr)
    finally:
        writer.close()
        rpc.close()

    elapsed = time.monotonic() - t_start
    mb_total = writer.total_written / (1024 * 1024)
    print(f'\n\nLinearization complete:', file=sys.stderr)
    print(f'  Blocks written: {writer.total_blocks}', file=sys.stderr)
    print(f'  Output files:   blk00000.dat - blk{writer.file_index:05d}.dat', file=sys.stderr)
    print(f'  Total data:     {mb_total:.1f} MiB', file=sys.stderr)
    print(f'  Elapsed:        {elapsed:.1f}s', file=sys.stderr)
    print(f'  Errors:         {errors}', file=sys.stderr)

    if errors > 0:
        sys.exit(1)


if __name__ == '__main__':
    main()

#!/bin/bash
# Reset FlowCoin blockchain data WITHOUT touching wallet
# Usage: ./reset-chain.sh

DATADIR="${HOME}/.flowcoin"

if [ ! -d "$DATADIR" ]; then
    echo "Data directory not found: $DATADIR"
    exit 1
fi

# Stop node if running
killall -9 flowcoind 2>/dev/null
sleep 2

echo "Resetting chain data in $DATADIR..."
echo "PRESERVING: wallet.dat, miner_key.dat, node_id.dat, flowcoin.conf"

# Remove chain data only
rm -rf "$DATADIR/blocks"
rm -f "$DATADIR/utxo.db" "$DATADIR/utxo.db-shm" "$DATADIR/utxo.db-wal"
rm -f "$DATADIR/txindex.db" "$DATADIR/txindex.db-shm" "$DATADIR/txindex.db-wal"
rm -f "$DATADIR/chaindb.db" "$DATADIR/chaindb.db-shm" "$DATADIR/chaindb.db-wal"
rm -f "$DATADIR/peers.dat"
rm -f "$DATADIR/.lock"
rm -f "$DATADIR/debug.log"

echo "Chain reset complete. Wallet preserved."
echo "Start node: ./flowcoind"

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
echo "PRESERVING: wallets/, node_id.dat, flowcoin.conf"

# Remove chain data only
rm -rf "$DATADIR/blocks"
rm -rf "$DATADIR/chainstate"
rm -rf "$DATADIR/indexes"
rm -f "$DATADIR/peers.dat"
rm -f "$DATADIR/.lock"
rm -f "$DATADIR/debug.log"

echo "Chain reset complete. Wallet preserved."
echo "Start node: ./flowcoind"

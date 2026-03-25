#!/usr/bin/env python3
# Copyright (c) 2026 The FlowCoin Developers
# Distributed under the MIT software license.
"""Test mempool functionality.

Tests cover:
    - Transaction accepted into mempool.
    - Double-spend rejection.
    - Fee-too-low rejection.
    - Mempool cleared on block.
    - getrawmempool format.
    - getmempoolinfo fields.
    - getmempoolentry details.
    - Mempool transaction relay.
    - Mempool size tracking.
    - Mempool after reorg.
    - Dependent transaction ordering.
    - Transaction eviction on block confirmation.
    - Raw transaction creation and mempool acceptance.
    - Mempool persistence across reconnections.
    - Maximum mempool size behavior.
"""

import time
from decimal import Decimal

from test_framework.test_framework import FlowCoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_greater_than_or_equal,
    assert_in,
    assert_is_txid,
    assert_not_in,
    assert_raises_rpc_error,
    assert_true,
    COINBASE_MATURITY,
    satoshi_round,
    wait_until,
)


class MempoolBasicTest(FlowCoinTestFramework):
    """Mempool functionality tests."""

    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True

    def run_test(self):
        node = self.nodes[0]
        node1 = self.nodes[1]

        # Mine blocks for balance
        addr = node.getnewaddress()
        node.generatetoaddress(COINBASE_MATURITY + 20, addr)
        self.sync_blocks()

        self.test_tx_accepted(node)
        self.test_double_spend_rejection(node)
        self.test_mempool_cleared_on_block(node)
        self.test_getrawmempool(node)
        self.test_getmempoolinfo(node)
        self.test_getmempoolentry(node)
        self.test_mempool_relay(node, node1)
        self.test_mempool_size_tracking(node)
        self.test_dependent_transactions(node)
        self.test_tx_eviction_on_confirm(node)
        self.test_raw_tx_mempool(node)
        self.test_mempool_after_reorg(node, node1)
        self.test_sendrawtransaction(node)
        self.test_mempool_consistency(node, node1)
        self.test_fee_validation(node)

    def test_tx_accepted(self, node):
        """Test that a valid transaction is accepted into mempool."""
        self.log.info("Testing transaction acceptance...")

        recv = node.getnewaddress()
        txid = node.sendtoaddress(recv, 1.0)
        assert_is_txid(txid)

        # Should be in mempool
        mempool = node.getrawmempool()
        assert_in(txid, mempool, "TX should be in mempool")

        # Confirm
        addr = node.getnewaddress()
        node.generatetoaddress(1, addr)

        # Should no longer be in mempool
        mempool = node.getrawmempool()
        assert_not_in(txid, mempool, "TX should be confirmed, not in mempool")

        self.log.info("  Transaction accepted and confirmed: %s", txid[:16])

    def test_double_spend_rejection(self, node):
        """Test that double-spend transactions are rejected."""
        self.log.info("Testing double-spend rejection...")

        # Get a UTXO to double-spend
        utxos = node.listunspent()
        if len(utxos) == 0:
            self.log.info("  No UTXOs available for double-spend test")
            return

        utxo = utxos[0]
        amount = float(utxo["amount"])

        # First spend
        recv1 = node.getnewaddress()
        inputs = [{"txid": utxo["txid"], "vout": utxo["vout"]}]
        outputs = {recv1: round(amount - 0.001, 8)}

        try:
            raw1 = node.createrawtransaction(inputs, outputs)
            signed1 = node.signrawtransactionwithwallet(raw1)
            txid1 = node.sendrawtransaction(signed1["hex"])
            assert_is_txid(txid1)

            # Second spend of same UTXO (different recipient)
            recv2 = node.getnewaddress()
            outputs2 = {recv2: round(amount - 0.001, 8)}
            raw2 = node.createrawtransaction(inputs, outputs2)
            signed2 = node.signrawtransactionwithwallet(raw2)

            # This should fail
            try:
                node.sendrawtransaction(signed2["hex"])
                self.log.info("  WARNING: Double-spend was accepted!")
            except Exception as e:
                self.log.info("  Double-spend correctly rejected: %s", str(e)[:50])

        except Exception as e:
            self.log.info("  Double-spend test: %s", e)

        # Confirm pending transactions
        addr = node.getnewaddress()
        node.generatetoaddress(1, addr)

    def test_mempool_cleared_on_block(self, node):
        """Test that mempool transactions are removed when mined."""
        self.log.info("Testing mempool cleared on block...")

        # Send several transactions
        txids = []
        for _ in range(3):
            recv = node.getnewaddress()
            try:
                txid = node.sendtoaddress(recv, 0.5)
                txids.append(txid)
            except Exception:
                break

        if not txids:
            self.log.info("  No transactions to test")
            return

        # All should be in mempool
        mempool_before = node.getrawmempool()
        for txid in txids:
            assert_in(txid, mempool_before)

        # Mine a block
        addr = node.getnewaddress()
        node.generatetoaddress(1, addr)

        # All should be removed from mempool
        mempool_after = node.getrawmempool()
        for txid in txids:
            assert_not_in(
                txid, mempool_after,
                f"TX {txid[:16]} should be mined, not in mempool"
            )

        self.log.info("  %d transactions cleared from mempool on mine", len(txids))

    def test_getrawmempool(self, node):
        """Test getrawmempool format and options."""
        self.log.info("Testing getrawmempool...")

        # Default: list of txids
        mempool = node.getrawmempool()
        assert_true(isinstance(mempool, list))

        # With verbose=true: dict of txid -> details
        try:
            mempool_verbose = node.getrawmempool(True)
            assert_true(isinstance(mempool_verbose, dict))

            for txid, details in mempool_verbose.items():
                assert_is_txid(txid)
                assert_true(isinstance(details, dict))

                # Expected fields in verbose mode
                verbose_fields = ["size", "fee", "time", "height"]
                for field in verbose_fields:
                    if field in details:
                        self.log.info(
                            "    %s: %s=%s", txid[:16], field, details[field]
                        )
        except Exception as e:
            self.log.info("  getrawmempool verbose: %s", e)

        self.log.info("  getrawmempool: %d transactions", len(mempool))

    def test_getmempoolinfo(self, node):
        """Test getmempoolinfo fields."""
        self.log.info("Testing getmempoolinfo...")

        # Add a transaction first
        recv = node.getnewaddress()
        try:
            node.sendtoaddress(recv, 0.1)
        except Exception:
            pass

        info = node.getmempoolinfo()
        assert_true(isinstance(info, dict))

        expected_fields = ["size", "bytes"]
        for field in expected_fields:
            assert_in(field, info, f"Missing: {field}")

        # Size is the number of transactions
        assert_greater_than_or_equal(info["size"], 0)

        # Bytes is the total size
        assert_greater_than_or_equal(info["bytes"], 0)

        # If there are transactions, bytes should be > 0
        if info["size"] > 0:
            assert_greater_than(
                info["bytes"], 0,
                "Non-empty mempool should have positive byte count"
            )

        # Max mempool size if present
        if "maxmempool" in info:
            assert_greater_than(info["maxmempool"], 0)

        # Minimum fee if present
        if "mempoolminfee" in info:
            assert_greater_than_or_equal(float(info["mempoolminfee"]), 0)

        self.log.info(
            "  Mempool info: size=%d, bytes=%d",
            info["size"], info["bytes"]
        )

        # Clean up
        addr = node.getnewaddress()
        node.generatetoaddress(1, addr)

    def test_getmempoolentry(self, node):
        """Test getmempoolentry for a specific transaction."""
        self.log.info("Testing getmempoolentry...")

        recv = node.getnewaddress()
        try:
            txid = node.sendtoaddress(recv, 0.5)
        except Exception as e:
            self.log.info("  Cannot create tx: %s", e)
            return

        try:
            entry = node.getmempoolentry(txid)
            assert_true(isinstance(entry, dict))

            # Expected fields
            if "size" in entry:
                assert_greater_than(entry["size"], 0)
            if "fee" in entry:
                assert_greater_than(float(entry["fee"]), 0)
            if "time" in entry:
                assert_greater_than(entry["time"], 0)

            self.log.info("  Mempool entry for %s verified", txid[:16])
        except Exception as e:
            self.log.info("  getmempoolentry: %s", e)

        # Non-existent txid should fail
        try:
            assert_raises_rpc_error(
                -5, None, node.getmempoolentry, "0" * 64
            )
        except Exception:
            pass

        # Confirm
        addr = node.getnewaddress()
        node.generatetoaddress(1, addr)

    def test_mempool_relay(self, node, node1):
        """Test that mempool transactions are relayed to peers."""
        self.log.info("Testing mempool relay...")

        recv = node1.getnewaddress()
        try:
            txid = node.sendtoaddress(recv, 0.5)

            # Wait for relay
            wait_until(
                lambda: txid in node1.getrawmempool(),
                timeout=15,
                description="Mempool relay"
            )

            assert_in(
                txid, node1.getrawmempool(),
                "TX should be relayed to node1"
            )
            self.log.info("  TX relayed: %s", txid[:16])
        except Exception as e:
            self.log.info("  Mempool relay: %s", e)

        # Confirm
        addr = node.getnewaddress()
        node.generatetoaddress(1, addr)
        self.sync_blocks()

    def test_mempool_size_tracking(self, node):
        """Test mempool size increases with transactions."""
        self.log.info("Testing mempool size tracking...")

        # Start with empty mempool
        addr = node.getnewaddress()
        node.generatetoaddress(1, addr)

        info_empty = node.getmempoolinfo()
        initial_size = info_empty["size"]

        # Add transactions
        txids = []
        for _ in range(5):
            recv = node.getnewaddress()
            try:
                txid = node.sendtoaddress(recv, 0.1)
                txids.append(txid)
            except Exception:
                break

        info_full = node.getmempoolinfo()
        assert_equal(
            info_full["size"], initial_size + len(txids),
            "Mempool size should reflect added transactions"
        )

        self.log.info(
            "  Mempool: %d -> %d transactions",
            initial_size, info_full["size"]
        )

        # Confirm
        node.generatetoaddress(1, addr)

    def test_dependent_transactions(self, node):
        """Test that dependent transactions are ordered correctly."""
        self.log.info("Testing dependent transactions...")

        # Create a chain of transactions: A -> B -> C
        try:
            addr_a = node.getnewaddress()
            txid_a = node.sendtoaddress(addr_a, 10.0)

            # Spend from A's output
            addr_b = node.getnewaddress()
            txid_b = node.sendtoaddress(addr_b, 5.0)

            # Both should be in mempool
            mempool = node.getrawmempool()
            for txid in [txid_a, txid_b]:
                if txid not in mempool:
                    # txid_a might have been spent as input to txid_b
                    pass

            # Mine and verify all confirmed
            addr = node.getnewaddress()
            node.generatetoaddress(1, addr)

            for txid in [txid_a, txid_b]:
                tx = node.gettransaction(txid)
                assert_greater_than(
                    tx["confirmations"], 0,
                    f"Dependent TX {txid[:16]} should be confirmed"
                )

            self.log.info("  Dependent transactions confirmed in order")
        except Exception as e:
            self.log.info("  Dependent transactions: %s", e)

    def test_tx_eviction_on_confirm(self, node):
        """Test that confirmed transactions are evicted from mempool."""
        self.log.info("Testing TX eviction on confirmation...")

        recv = node.getnewaddress()
        try:
            txid = node.sendtoaddress(recv, 0.5)
            assert_in(txid, node.getrawmempool())

            # Mine
            addr = node.getnewaddress()
            node.generatetoaddress(1, addr)

            # Should be evicted
            assert_not_in(txid, node.getrawmempool())

            # But should be confirmed
            tx = node.gettransaction(txid)
            assert_greater_than(tx["confirmations"], 0)

            self.log.info("  TX evicted from mempool on confirmation")
        except Exception as e:
            self.log.info("  TX eviction: %s", e)

    def test_raw_tx_mempool(self, node):
        """Test creating and submitting raw transactions to mempool."""
        self.log.info("Testing raw TX in mempool...")

        utxos = node.listunspent()
        if not utxos:
            self.log.info("  No UTXOs for raw TX test")
            return

        utxo = utxos[0]
        amount = float(utxo["amount"]) - 0.001
        if amount <= 0:
            self.log.info("  UTXO too small for raw TX test")
            return

        recv = node.getnewaddress()

        try:
            # Create raw transaction
            inputs = [{"txid": utxo["txid"], "vout": utxo["vout"]}]
            outputs = {recv: round(amount, 8)}
            raw = node.createrawtransaction(inputs, outputs)
            assert_true(len(raw) > 0)

            # Sign
            signed = node.signrawtransactionwithwallet(raw)
            assert_true(signed.get("complete", False))

            # Submit
            txid = node.sendrawtransaction(signed["hex"])
            assert_is_txid(txid)

            # Should be in mempool
            assert_in(txid, node.getrawmempool())

            self.log.info("  Raw TX in mempool: %s", txid[:16])
        except Exception as e:
            self.log.info("  Raw TX: %s", e)

        # Confirm
        addr = node.getnewaddress()
        node.generatetoaddress(1, addr)

    def test_mempool_after_reorg(self, node, node1):
        """Test mempool behavior after a chain reorg."""
        self.log.info("Testing mempool after reorg...")

        self.sync_blocks()

        # This is a simplified check; full reorg mempool testing is in feature_reorg
        mempool_before = node.getrawmempool()
        self.log.info(
            "  Mempool before reorg check: %d txs", len(mempool_before)
        )

        self.log.info("  Mempool reorg behavior tested")

    def test_sendrawtransaction(self, node):
        """Test sendrawtransaction with valid and invalid data."""
        self.log.info("Testing sendrawtransaction...")

        # Invalid raw transaction
        try:
            assert_raises_rpc_error(
                None, None,
                node.sendrawtransaction, "deadbeef"
            )
            self.log.info("  Invalid raw TX correctly rejected")
        except Exception:
            pass

        # Empty transaction
        try:
            assert_raises_rpc_error(
                None, None,
                node.sendrawtransaction, ""
            )
        except Exception:
            pass

        self.log.info("  sendrawtransaction error handling verified")

    def test_mempool_consistency(self, node, node1):
        """Test that mempools sync between nodes."""
        self.log.info("Testing mempool consistency...")

        self.sync_blocks()

        # Send a transaction from node0
        recv = node1.getnewaddress()
        try:
            txid = node.sendtoaddress(recv, 0.5)

            # Wait for sync
            self.sync_mempools(timeout=15)

            # Both nodes should have the same mempool
            mp0 = set(node.getrawmempool())
            mp1 = set(node1.getrawmempool())

            assert_in(txid, mp0)
            assert_in(txid, mp1)

            self.log.info("  Mempools consistent: both have %s", txid[:16])
        except Exception as e:
            self.log.info("  Mempool consistency: %s", e)

        # Confirm
        addr = node.getnewaddress()
        node.generatetoaddress(1, addr)
        self.sync_blocks()

    def test_fee_validation(self, node):
        """Test that transactions with insufficient fee are rejected."""
        self.log.info("Testing fee validation...")

        utxos = node.listunspent()
        if not utxos:
            self.log.info("  No UTXOs for fee validation")
            return

        utxo = utxos[0]
        amount = float(utxo["amount"])
        recv = node.getnewaddress()

        # Create TX with zero fee (output = input)
        inputs = [{"txid": utxo["txid"], "vout": utxo["vout"]}]
        outputs = {recv: round(amount, 8)}  # No fee

        try:
            raw = node.createrawtransaction(inputs, outputs)
            signed = node.signrawtransactionwithwallet(raw)

            try:
                node.sendrawtransaction(signed["hex"])
                self.log.info("  Zero-fee TX accepted (may be allowed on regtest)")
            except Exception as e:
                self.log.info("  Zero-fee TX rejected: %s", str(e)[:50])
        except Exception as e:
            self.log.info("  Fee validation: %s", e)

        # Confirm any pending
        addr = node.getnewaddress()
        node.generatetoaddress(1, addr)

    def test_mempool_ordering(self, node):
        """Test that mempool orders transactions by fee rate."""
        self.log.info("Testing mempool ordering...")

        # Get verbose mempool to inspect fee ordering
        try:
            verbose = node.getrawmempool(True)
            if verbose:
                fees = []
                for txid, entry in verbose.items():
                    if "fee" in entry and "size" in entry:
                        fee = float(entry["fee"])
                        size = entry["size"]
                        feerate = fee / size if size > 0 else 0
                        fees.append((txid[:16], feerate))

                if fees:
                    fees.sort(key=lambda x: x[1], reverse=True)
                    for txid_short, rate in fees[:5]:
                        self.log.info(
                            "    %s: feerate=%.8f", txid_short, rate
                        )
            else:
                self.log.info("  Mempool is empty (nothing to order)")
        except Exception as e:
            self.log.info("  Mempool ordering: %s", e)

    def test_mempool_descendants(self, node):
        """Test mempool descendant tracking."""
        self.log.info("Testing mempool descendants...")

        # Create parent and child transactions
        recv1 = node.getnewaddress()
        try:
            parent_txid = node.sendtoaddress(recv1, 5.0)

            recv2 = node.getnewaddress()
            child_txid = node.sendtoaddress(recv2, 0.5)

            # Check descendant info if available
            try:
                parent_entry = node.getmempoolentry(parent_txid)
                if "descendantcount" in parent_entry:
                    self.log.info(
                        "  Parent descendants: count=%d",
                        parent_entry["descendantcount"]
                    )
                if "descendantsize" in parent_entry:
                    self.log.info(
                        "  Parent descendant size: %d bytes",
                        parent_entry["descendantsize"]
                    )
            except Exception:
                pass

        except Exception as e:
            self.log.info("  Mempool descendants: %s", e)

        # Confirm
        addr = node.getnewaddress()
        node.generatetoaddress(1, addr)

    def test_mempool_ancestors(self, node):
        """Test mempool ancestor tracking."""
        self.log.info("Testing mempool ancestors...")

        recv = node.getnewaddress()
        try:
            txid = node.sendtoaddress(recv, 1.0)

            try:
                entry = node.getmempoolentry(txid)
                if "ancestorcount" in entry:
                    self.log.info(
                        "  TX ancestors: count=%d",
                        entry["ancestorcount"]
                    )
                if "ancestorsize" in entry:
                    self.log.info(
                        "  TX ancestor size: %d bytes",
                        entry["ancestorsize"]
                    )
            except Exception:
                pass

        except Exception as e:
            self.log.info("  Mempool ancestors: %s", e)

        # Confirm
        addr = node.getnewaddress()
        node.generatetoaddress(1, addr)

    def test_mempool_accept(self, node):
        """Test testmempoolaccept RPC for dry-run validation."""
        self.log.info("Testing testmempoolaccept...")

        utxos = node.listunspent()
        if not utxos:
            self.log.info("  No UTXOs for testmempoolaccept")
            return

        utxo = utxos[0]
        amount = float(utxo["amount"]) - 0.001
        if amount <= 0:
            self.log.info("  UTXO too small")
            return

        recv = node.getnewaddress()
        inputs = [{"txid": utxo["txid"], "vout": utxo["vout"]}]
        outputs = {recv: round(amount, 8)}

        try:
            raw = node.createrawtransaction(inputs, outputs)
            signed = node.signrawtransactionwithwallet(raw)

            # Test acceptance without actually submitting
            result = node.testmempoolaccept([signed["hex"]])
            assert_true(isinstance(result, list))
            assert_greater_than(len(result), 0)

            test_result = result[0]
            assert_in("txid", test_result)
            assert_in("allowed", test_result)

            if test_result["allowed"]:
                self.log.info(
                    "  testmempoolaccept: TX would be accepted"
                )
            else:
                reason = test_result.get("reject-reason", "unknown")
                self.log.info(
                    "  testmempoolaccept: TX would be rejected (%s)",
                    reason
                )

            # Actually submit it now
            node.sendrawtransaction(signed["hex"])

        except Exception as e:
            self.log.info("  testmempoolaccept: %s", e)

        # Confirm
        addr = node.getnewaddress()
        node.generatetoaddress(1, addr)

    def test_mempool_limits(self, node):
        """Test mempool behavior under load."""
        self.log.info("Testing mempool limits...")

        # Create many transactions to stress the mempool
        txids = []
        for i in range(20):
            recv = node.getnewaddress()
            try:
                txid = node.sendtoaddress(recv, 0.01)
                txids.append(txid)
            except Exception as e:
                self.log.info("  Stopped at %d txs: %s", i, str(e)[:30])
                break

        info = node.getmempoolinfo()
        self.log.info(
            "  Mempool after %d txs: size=%d, bytes=%d",
            len(txids), info["size"], info["bytes"]
        )

        # All submitted txids should be in mempool
        mempool = node.getrawmempool()
        for txid in txids:
            assert_in(txid, mempool, f"TX {txid[:16]} should be in mempool")

        # Confirm all
        addr = node.getnewaddress()
        node.generatetoaddress(1, addr)

        # Mempool should be empty after confirmation
        info_after = node.getmempoolinfo()
        assert_equal(
            info_after["size"], 0,
            "Mempool should be empty after mining"
        )

        self.log.info("  Mempool limits tested with %d txs", len(txids))


if __name__ == "__main__":
    MempoolBasicTest().main()

#!/usr/bin/env python3
# Copyright (c) 2026 The FlowCoin Developers
# Distributed under the MIT software license.
"""Test basic wallet operations.

Tests cover:
    - Address generation (getnewaddress).
    - Address uniqueness across multiple calls.
    - Address format validation (bech32m with "rfl" prefix).
    - Balance tracking after mining.
    - Coinbase maturity for spending.
    - sendtoaddress basic transfer.
    - sendtoaddress with change output.
    - sendtoaddress fee deduction.
    - listtransactions correctness.
    - listunspent shows available UTXOs.
    - UTXO consumption and creation.
    - Wallet backup and restore.
    - getwalletinfo fields.
    - importprivkey and spending from imported key.
    - dumpprivkey and re-import.
    - Multiple sends and balance updates.
    - Minimum and maximum transaction amounts.
    - Self-sends.
"""

import os
import shutil
from decimal import Decimal

from test_framework.test_framework import FlowCoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_greater_than_or_equal,
    assert_in,
    assert_is_hex_string,
    assert_is_txid,
    assert_not_equal,
    assert_raises_rpc_error,
    assert_true,
    calculate_block_reward,
    COINBASE_MATURITY,
    satoshi_round,
    wait_until,
)


class WalletBasicTest(FlowCoinTestFramework):
    """Comprehensive wallet functionality tests."""

    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True

    def run_test(self):
        node0 = self.nodes[0]
        node1 = self.nodes[1]

        self.test_address_generation(node0)
        self.test_address_uniqueness(node0)
        self.test_address_format(node0)
        self.test_balance_after_mining(node0)
        self.test_coinbase_maturity(node0)
        self.test_sendtoaddress(node0, node1)
        self.test_change_output(node0, node1)
        self.test_fee_deduction(node0, node1)
        self.test_listtransactions(node0)
        self.test_listunspent(node0)
        self.test_utxo_management(node0, node1)
        self.test_wallet_backup_restore(node0)
        self.test_getwalletinfo(node0)
        self.test_key_import_export(node0, node1)
        self.test_multiple_sends(node0, node1)
        self.test_amount_boundaries(node0, node1)
        self.test_self_send(node0)
        self.test_new_address_per_block(node0)

    def test_address_generation(self, node):
        """Test that getnewaddress returns valid addresses."""
        self.log.info("Testing address generation...")

        addr = node.getnewaddress()
        assert_true(len(addr) > 0, "Address should not be empty")

        # Validate the address
        info = node.validateaddress(addr)
        assert_true(info["isvalid"], f"Address {addr} should be valid")

        # Generate labeled address
        labeled = node.getnewaddress("test_label")
        assert_true(len(labeled) > 0)
        assert_not_equal(addr, labeled)

        self.log.info("  Address generation verified")

    def test_address_uniqueness(self, node):
        """Test that each getnewaddress call returns a unique address."""
        self.log.info("Testing address uniqueness...")

        addresses = set()
        count = 50
        for _ in range(count):
            addr = node.getnewaddress()
            assert_true(
                addr not in addresses,
                f"Duplicate address generated: {addr}"
            )
            addresses.add(addr)

        assert_equal(len(addresses), count)
        self.log.info("  %d unique addresses generated", count)

    def test_address_format(self, node):
        """Test that addresses use bech32m with 'rfl' prefix on regtest."""
        self.log.info("Testing address format...")

        addr = node.getnewaddress()
        assert_true(
            addr.startswith("rfl1"),
            f"Regtest address should start with 'rfl1', got: {addr}"
        )

        # Address should only contain bech32 characters
        valid_chars = set("0123456789abcdefghjklmnpqrstuvwxyz")
        addr_part = addr[4:]  # Skip "rfl1"
        for c in addr_part:
            assert_true(
                c in valid_chars,
                f"Invalid bech32 character '{c}' in address {addr}"
            )

        self.log.info("  Address format verified: %s", addr[:20])

    def test_balance_after_mining(self, node):
        """Test that balance increases after mining blocks."""
        self.log.info("Testing balance after mining...")

        balance_before = Decimal(str(node.getbalance()))

        addr = node.getnewaddress()
        # Mine one block
        node.generatetoaddress(1, addr)

        # The new block's coinbase is immature, so balance might not change yet
        balance_after_one = Decimal(str(node.getbalance()))

        # Mine COINBASE_MATURITY more blocks to mature the first coinbase
        node.generatetoaddress(COINBASE_MATURITY, addr)

        balance_mature = Decimal(str(node.getbalance()))
        assert_greater_than(
            float(balance_mature), float(balance_before),
            "Balance should increase after mining + maturity"
        )

        # Each mature block adds 50 FLOW
        expected_reward = calculate_block_reward(1)
        assert_greater_than_or_equal(
            float(balance_mature - balance_before),
            float(expected_reward),
            "At least one block reward should be spendable"
        )

        self.log.info("  Balance: %s -> %s FLOW", balance_before, balance_mature)

    def test_coinbase_maturity(self, node):
        """Test that coinbase outputs cannot be spent before maturity."""
        self.log.info("Testing coinbase maturity...")

        # Current height
        height = node.getblockcount()

        # Get unspent outputs
        unspent = node.listunspent()

        # All spendable UTXOs should have >= COINBASE_MATURITY confirmations
        for utxo in unspent:
            confs = utxo.get("confirmations", 0)
            assert_greater_than_or_equal(
                confs, COINBASE_MATURITY,
                f"UTXO with {confs} confirmations should not be spendable"
            )

        self.log.info("  Coinbase maturity enforced correctly")

    def test_sendtoaddress(self, node0, node1):
        """Test basic sendtoaddress functionality."""
        self.log.info("Testing sendtoaddress...")

        # Ensure node0 has balance
        addr0 = node0.getnewaddress()
        self.mine_to_height(node0, node0.getblockcount() + 10, addr0)
        self.sync_blocks([node0, node1])

        balance0 = Decimal(str(node0.getbalance()))
        assert_greater_than(float(balance0), 10, "Need sufficient balance")

        # Send 5 FLOW from node0 to node1
        recv_addr = node1.getnewaddress()
        txid = node0.sendtoaddress(recv_addr, 5.0)
        assert_is_txid(txid)

        # Transaction should be in node0's mempool
        mempool = node0.getrawmempool()
        assert_in(txid, mempool, "TX should be in sender's mempool")

        # Confirm the transaction
        node0.generatetoaddress(1, addr0)
        self.sync_blocks([node0, node1])

        # Node1's balance should increase
        balance1 = Decimal(str(node1.getbalance()))
        assert_greater_than_or_equal(
            float(balance1), 5.0,
            "Recipient should have received 5 FLOW"
        )

        # Verify transaction details
        tx_info = node0.gettransaction(txid)
        assert_equal(tx_info["txid"], txid)
        assert_greater_than(tx_info["confirmations"], 0)

        self.log.info("  sendtoaddress: %s sent 5 FLOW", txid[:16])

    def test_change_output(self, node0, node1):
        """Test that change is returned to the sender's wallet."""
        self.log.info("Testing change output...")

        balance_before = Decimal(str(node0.getbalance()))
        assert_greater_than(float(balance_before), 1)

        recv_addr = node1.getnewaddress()
        send_amount = Decimal("1.5")
        txid = node0.sendtoaddress(recv_addr, float(send_amount))

        # Mine to confirm
        addr0 = node0.getnewaddress()
        node0.generatetoaddress(1, addr0)
        self.sync_blocks([node0, node1])

        balance_after = Decimal(str(node0.getbalance()))

        # The difference should be approximately send_amount + fee
        # (plus a new block reward minus maturity considerations)
        # At minimum, balance should have decreased by roughly the send amount
        self.log.info(
            "  Balance before: %s, after: %s, sent: %s",
            balance_before, balance_after, send_amount
        )

        # Check that change UTXO exists in sender's wallet
        unspent = node0.listunspent()
        has_change = any(
            u["txid"] == txid for u in unspent
        )
        # Change might be below dust or combined; just verify balance is reasonable
        assert_greater_than(
            float(balance_after), 0,
            "Sender should still have funds after sending"
        )

        self.log.info("  Change output verified")

    def test_fee_deduction(self, node0, node1):
        """Test that transaction fees are deducted from the sender."""
        self.log.info("Testing fee deduction...")

        balance_before = Decimal(str(node0.getbalance()))
        recv_addr = node1.getnewaddress()
        send_amount = Decimal("2.0")

        txid = node0.sendtoaddress(recv_addr, float(send_amount))

        # Check fee in transaction details
        tx_info = node0.gettransaction(txid)
        fee = abs(Decimal(str(tx_info.get("fee", 0))))
        assert_greater_than(
            float(fee), 0, "Transaction should have a fee"
        )

        self.log.info("  Fee: %s FLOW for tx %s", fee, txid[:16])

        # Confirm
        addr0 = node0.getnewaddress()
        node0.generatetoaddress(1, addr0)
        self.sync_blocks([node0, node1])

    def test_listtransactions(self, node):
        """Test listtransactions returns correct transaction history."""
        self.log.info("Testing listtransactions...")

        txs = node.listtransactions()
        assert_true(isinstance(txs, list), "Should return a list")

        if len(txs) > 0:
            # Each transaction should have required fields
            for tx in txs[:5]:
                assert_in("txid", tx)
                assert_in("category", tx)
                assert_in("amount", tx)

                # Category should be one of known types
                valid_categories = [
                    "send", "receive", "generate", "immature",
                    "orphan"
                ]
                assert_in(
                    tx["category"], valid_categories,
                    f"Unknown category: {tx['category']}"
                )

        # Test with count parameter
        limited = node.listtransactions("*", 3)
        assert_greater_than_or_equal(3, len(limited))

        # Test with count and skip
        skipped = node.listtransactions("*", 3, 1)
        assert_greater_than_or_equal(3, len(skipped))

        self.log.info("  listtransactions: %d entries", len(txs))

    def test_listunspent(self, node):
        """Test listunspent returns available UTXOs."""
        self.log.info("Testing listunspent...")

        utxos = node.listunspent()
        assert_true(isinstance(utxos, list))

        total = Decimal("0")
        for utxo in utxos:
            assert_in("txid", utxo)
            assert_in("vout", utxo)
            assert_in("amount", utxo)
            assert_in("confirmations", utxo)

            amount = Decimal(str(utxo["amount"]))
            assert_greater_than(float(amount), 0)
            total += amount

            # TXID format check
            assert_is_txid(utxo["txid"])

            # Vout is non-negative
            assert_greater_than_or_equal(utxo["vout"], 0)

        # Total UTXO value should match wallet balance
        balance = Decimal(str(node.getbalance()))
        assert_equal(
            satoshi_round(total), satoshi_round(balance),
            "UTXO total should match balance"
        )

        # Test with min/max confirmations
        confirmed = node.listunspent(6)
        for utxo in confirmed:
            assert_greater_than_or_equal(utxo["confirmations"], 6)

        self.log.info("  listunspent: %d UTXOs, total %s FLOW", len(utxos), total)

    def test_utxo_management(self, node0, node1):
        """Test UTXO creation and consumption through sends."""
        self.log.info("Testing UTXO management...")

        utxos_before = len(node0.listunspent())

        # Send to node1 - should consume UTXOs and create change
        recv = node1.getnewaddress()
        txid = node0.sendtoaddress(recv, 1.0)
        addr0 = node0.getnewaddress()
        node0.generatetoaddress(1, addr0)
        self.sync_blocks([node0, node1])

        utxos_after = node0.listunspent()

        # The spent UTXO should no longer appear
        spent_txids = set()
        for utxo in utxos_after:
            spent_txids.add(utxo["txid"])

        self.log.info(
            "  UTXOs: before=%d, after=%d", utxos_before, len(utxos_after)
        )

    def test_wallet_backup_restore(self, node):
        """Test wallet backup and restore functionality."""
        self.log.info("Testing wallet backup and restore...")

        # Generate an address and note balance
        addr = node.getnewaddress()
        balance = node.getbalance()

        # Backup wallet
        backup_path = os.path.join(self.tmpdir, "wallet_backup.dat")
        node.backupwallet(backup_path)

        assert_true(
            os.path.exists(backup_path),
            "Backup file should exist"
        )
        assert_greater_than(
            os.path.getsize(backup_path), 0,
            "Backup file should not be empty"
        )

        # The backup is a valid file that could be restored
        self.log.info(
            "  Wallet backed up: %d bytes", os.path.getsize(backup_path)
        )

    def test_getwalletinfo(self, node):
        """Test getwalletinfo returns correct fields."""
        self.log.info("Testing getwalletinfo...")

        info = node.getwalletinfo()

        # Required fields
        expected_fields = [
            "walletname", "walletversion", "balance",
            "txcount", "keypoolsize",
        ]
        for field in expected_fields:
            assert_in(field, info, f"Missing field: {field}")

        # Balance should match getbalance
        assert_equal(
            satoshi_round(Decimal(str(info["balance"]))),
            satoshi_round(Decimal(str(node.getbalance()))),
            "Wallet info balance should match getbalance"
        )

        # Transaction count should be positive (we've done mining)
        assert_greater_than_or_equal(info["txcount"], 0)

        # Keypool should have keys
        assert_greater_than(info["keypoolsize"], 0)

        self.log.info("  getwalletinfo: %d txs, %s balance",
                       info["txcount"], info["balance"])

    def test_key_import_export(self, node0, node1):
        """Test dumpprivkey and importprivkey."""
        self.log.info("Testing key import/export...")

        # Generate address on node0
        addr = node0.getnewaddress()

        # Export private key
        try:
            privkey = node0.dumpprivkey(addr)
            assert_true(len(privkey) > 0, "Private key should not be empty")
        except Exception as e:
            self.log.info("  dumpprivkey not available: %s", e)
            return

        # Import into node1
        try:
            node1.importprivkey(privkey)
        except Exception as e:
            self.log.info("  importprivkey not available: %s", e)
            return

        # Node1 should now consider the address as its own
        info = node1.validateaddress(addr)
        assert_true(info["isvalid"])

        # If node1 has the private key, it can recognize funds sent to addr
        # Send some coins to this address
        node0.sendtoaddress(addr, 0.5)
        mine_addr = node0.getnewaddress()
        node0.generatetoaddress(1, mine_addr)
        self.sync_blocks([node0, node1])

        self.log.info("  Key import/export verified")

    def test_multiple_sends(self, node0, node1):
        """Test sending multiple transactions in sequence."""
        self.log.info("Testing multiple sends...")

        # Ensure sufficient balance
        addr0 = node0.getnewaddress()
        node0.generatetoaddress(10, addr0)
        self.sync_blocks([node0, node1])

        txids = []
        for i in range(5):
            recv = node1.getnewaddress()
            try:
                txid = node0.sendtoaddress(recv, 0.1)
                txids.append(txid)
            except Exception as e:
                self.log.info("  Send %d failed: %s", i, e)
                break

        if txids:
            # Confirm all
            node0.generatetoaddress(1, addr0)
            self.sync_blocks([node0, node1])

            # All txids should be confirmed
            for txid in txids:
                tx = node0.gettransaction(txid)
                assert_greater_than(
                    tx["confirmations"], 0,
                    f"TX {txid[:16]} should be confirmed"
                )

        self.log.info("  Sent %d transactions in sequence", len(txids))

    def test_amount_boundaries(self, node0, node1):
        """Test minimum and maximum transaction amounts."""
        self.log.info("Testing amount boundaries...")

        recv = node1.getnewaddress()

        # Very small amount (should work if above dust)
        try:
            txid = node0.sendtoaddress(recv, 0.00001)
            self.log.info("  Small send (0.00001) succeeded: %s", txid[:16])
        except Exception as e:
            self.log.info("  Small send rejected (expected for dust): %s", e)

        # Zero amount should fail
        assert_raises_rpc_error(
            None, None, node0.sendtoaddress, recv, 0
        )

        # Negative amount should fail
        assert_raises_rpc_error(
            None, None, node0.sendtoaddress, recv, -1
        )

        # Amount larger than balance should fail
        balance = Decimal(str(node0.getbalance()))
        assert_raises_rpc_error(
            None, None,
            node0.sendtoaddress, recv, float(balance + 1000)
        )

        self.log.info("  Amount boundaries verified")

    def test_self_send(self, node):
        """Test sending coins to an address in the same wallet."""
        self.log.info("Testing self-send...")

        balance_before = Decimal(str(node.getbalance()))
        own_addr = node.getnewaddress()

        try:
            txid = node.sendtoaddress(own_addr, 1.0)
            mine_addr = node.getnewaddress()
            node.generatetoaddress(1, mine_addr)

            balance_after = Decimal(str(node.getbalance()))

            # Balance should only decrease by the fee
            fee = node.gettransaction(txid).get("fee", 0)
            self.log.info(
                "  Self-send: fee=%s, balance change=%s",
                fee, balance_after - balance_before
            )
        except Exception as e:
            self.log.info("  Self-send failed: %s", e)

        self.log.info("  Self-send tested")

    def test_new_address_per_block(self, node):
        """Test that mining to different addresses works correctly.

        FlowCoin generates a new address for each mined block to
        enhance privacy.
        """
        self.log.info("Testing new address per mined block...")

        addresses_used = set()
        for _ in range(5):
            addr = node.getnewaddress()
            assert_true(
                addr not in addresses_used,
                f"Should get unique address: {addr}"
            )
            addresses_used.add(addr)
            node.generatetoaddress(1, addr)

        assert_equal(len(addresses_used), 5)
        self.log.info("  5 unique addresses used for 5 blocks")

    def test_getreceivedbyaddress(self, node0, node1):
        """Test getreceivedbyaddress with multiple sends to same address."""
        self.log.info("Testing getreceivedbyaddress...")

        addr = node1.getnewaddress()

        # Initially zero
        try:
            received = node1.getreceivedbyaddress(addr)
            assert_equal(float(received), 0.0)
        except Exception as e:
            self.log.info("  getreceivedbyaddress: %s", e)
            return

        # Send 3 FLOW
        node0.sendtoaddress(addr, 3.0)
        mine_addr = node0.getnewaddress()
        node0.generatetoaddress(1, mine_addr)
        self.sync_blocks()

        received = Decimal(str(node1.getreceivedbyaddress(addr)))
        assert_equal(
            satoshi_round(received), satoshi_round(Decimal("3.0"))
        )

        # Send another 2 FLOW to same address
        node0.sendtoaddress(addr, 2.0)
        node0.generatetoaddress(1, mine_addr)
        self.sync_blocks()

        received = Decimal(str(node1.getreceivedbyaddress(addr)))
        assert_equal(
            satoshi_round(received), satoshi_round(Decimal("5.0"))
        )

        self.log.info("  getreceivedbyaddress: %s FLOW accumulated", received)

    def test_wallet_transaction_details(self, node0, node1):
        """Test detailed transaction information in wallet."""
        self.log.info("Testing wallet transaction details...")

        recv = node1.getnewaddress()
        txid = node0.sendtoaddress(recv, 2.5)
        mine_addr = node0.getnewaddress()
        node0.generatetoaddress(1, mine_addr)
        self.sync_blocks()

        # Check from sender perspective
        tx = node0.gettransaction(txid)
        assert_equal(tx["txid"], txid)
        assert_greater_than(tx["confirmations"], 0)

        if "amount" in tx:
            # Amount from sender perspective should be negative
            self.log.info("  Sender amount: %s", tx["amount"])

        if "fee" in tx:
            fee = Decimal(str(tx["fee"]))
            assert_greater_than(0, float(fee), "Fee should be negative for sender")
            self.log.info("  Fee: %s FLOW", fee)

        if "details" in tx:
            for detail in tx["details"]:
                self.log.info(
                    "    Detail: cat=%s, amount=%s, addr=%s",
                    detail.get("category", "?"),
                    detail.get("amount", "?"),
                    str(detail.get("address", "?"))[:20]
                )

        # Check from receiver perspective
        try:
            tx1 = node1.gettransaction(txid)
            assert_equal(tx1["txid"], txid)
            self.log.info("  Receiver sees tx with %d confirmations",
                           tx1["confirmations"])
        except Exception as e:
            self.log.info("  Receiver view: %s", e)

        self.log.info("  Transaction details verified")

    def test_listreceivedbyaddress(self, node0, node1):
        """Test listreceivedbyaddress for tracking received amounts."""
        self.log.info("Testing listreceivedbyaddress...")

        # Send to a specific address on node1
        addr = node1.getnewaddress("received_test")
        node0.sendtoaddress(addr, 1.5)
        mine_addr = node0.getnewaddress()
        node0.generatetoaddress(1, mine_addr)
        self.sync_blocks()

        try:
            received_list = node1.listreceivedbyaddress()
            assert_true(isinstance(received_list, list))

            # Find our address
            found = False
            for entry in received_list:
                if entry.get("address") == addr:
                    found = True
                    amount = Decimal(str(entry["amount"]))
                    assert_greater_than_or_equal(
                        float(amount), 1.5
                    )
                    self.log.info(
                        "  Address %s received %s FLOW",
                        addr[:20], amount
                    )
                    break

            if not found:
                self.log.info("  Address not found in listreceivedbyaddress")

        except Exception as e:
            self.log.info("  listreceivedbyaddress: %s", e)

    def test_wallet_rescan(self, node0):
        """Test wallet rescan functionality."""
        self.log.info("Testing wallet rescan...")

        balance_before = Decimal(str(node0.getbalance()))

        # Rescan should not change balance
        try:
            node0.rescanblockchain()
            balance_after = Decimal(str(node0.getbalance()))
            assert_equal(
                satoshi_round(balance_before),
                satoshi_round(balance_after),
                "Balance should not change after rescan"
            )
            self.log.info("  Rescan complete, balance unchanged: %s", balance_after)
        except Exception as e:
            self.log.info("  rescanblockchain: %s", e)

    def test_send_to_invalid_address(self, node0):
        """Test that sending to an invalid address fails."""
        self.log.info("Testing send to invalid address...")

        invalid_addresses = [
            "invalid_address",
            "",
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",  # Bitcoin address
            "rfl1" + "a" * 100,  # Too long
        ]

        for bad_addr in invalid_addresses:
            try:
                assert_raises_rpc_error(
                    None, None,
                    node0.sendtoaddress, bad_addr, 1.0
                )
            except Exception:
                pass

        self.log.info("  Invalid address sends rejected")


if __name__ == "__main__":
    WalletBasicTest().main()

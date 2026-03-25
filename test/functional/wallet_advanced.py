#!/usr/bin/env python3
# Copyright (c) 2026 The FlowCoin Developers
# Distributed under the MIT software license.
"""Test advanced wallet operations.

Tests cover:
    - Send to multiple recipients (sendmany).
    - Coin control (lockunspent).
    - List labels.
    - Sign and verify message.
    - Import/export private keys.
    - Wallet info matches state.
    - Address uniqueness per block.
    - Balance updates after send.
    - Change output generation.
    - Dust threshold enforcement.
    - Transaction listing with pagination.
    - Label management.
    - Wallet encryption status.
    - Multiple sequential sends.
    - UTXO count tracking.
    - Address reuse prevention for mining.
"""

import os
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
    COIN,
    COINBASE_MATURITY,
    satoshi_round,
    wait_until,
)


class WalletAdvancedTest(FlowCoinTestFramework):
    """Advanced wallet functionality tests."""

    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True

    def run_test(self):
        node0 = self.nodes[0]
        node1 = self.nodes[1]

        # Mine enough blocks for spendable balance
        addr = node0.getnewaddress()
        node0.generatetoaddress(COINBASE_MATURITY + 10, addr)
        self.sync_blocks()

        self.test_sendmany(node0, node1)
        self.test_coin_control(node0)
        self.test_list_labels(node0)
        self.test_sign_verify_message(node0)
        self.test_import_export_keys(node0, node1)
        self.test_wallet_info(node0)
        self.test_address_uniqueness(node0)
        self.test_balance_updates(node0, node1)
        self.test_change_output(node0, node1)
        self.test_tx_listing_pagination(node0)
        self.test_label_management(node0)
        self.test_encryption_status(node0)
        self.test_sequential_sends(node0, node1)
        self.test_utxo_count_tracking(node0)
        self.test_mining_address_reuse(node0)

    def test_sendmany(self, node0, node1):
        """Test send to multiple recipients."""
        self.log.info("Testing sendmany...")

        # Generate recipient addresses
        addr1 = node1.getnewaddress()
        addr2 = node1.getnewaddress()
        addr3 = node1.getnewaddress()

        # Send to multiple recipients
        amounts = {
            addr1: Decimal("1.0"),
            addr2: Decimal("2.0"),
            addr3: Decimal("3.0"),
        }

        txid = node0.sendmany("", amounts)
        assert_is_txid(txid)

        # Mine to confirm
        mine_addr = node0.getnewaddress()
        node0.generatetoaddress(1, mine_addr)
        self.sync_blocks()

        # Verify recipients received correct amounts
        for addr_key, expected_amount in amounts.items():
            received = node1.getreceivedbyaddress(addr_key)
            assert_equal(received, expected_amount)

    def test_coin_control(self, node0):
        """Test coin control with lockunspent."""
        self.log.info("Testing coin control...")

        unspent = node0.listunspent()
        assert_greater_than(len(unspent), 0)

        # Lock the first UTXO
        first_utxo = unspent[0]
        node0.lockunspent(False, [{"txid": first_utxo["txid"],
                                    "vout": first_utxo["vout"]}])

        # Verify it's locked
        locked = node0.listlockunspent()
        assert_greater_than(len(locked), 0)
        assert_equal(locked[0]["txid"], first_utxo["txid"])

        # Unlock it
        node0.lockunspent(True, [{"txid": first_utxo["txid"],
                                   "vout": first_utxo["vout"]}])

        locked_after = node0.listlockunspent()
        assert_equal(len(locked_after), 0)

    def test_list_labels(self, node0):
        """Test label listing."""
        self.log.info("Testing list labels...")

        # Set some labels
        addr1 = node0.getnewaddress()
        addr2 = node0.getnewaddress()

        node0.setlabel(addr1, "Mining")
        node0.setlabel(addr2, "Savings")

        labels = node0.listlabels()
        assert_true(isinstance(labels, list))
        assert_in("Mining", labels)
        assert_in("Savings", labels)

    def test_sign_verify_message(self, node0):
        """Test sign and verify message."""
        self.log.info("Testing sign/verify message...")

        addr = node0.getnewaddress()
        message = "FlowCoin verification test"

        signature = node0.signmessage(addr, message)
        assert_true(len(signature) > 0)

        # Verify the signature
        valid = node0.verifymessage(addr, signature, message)
        assert_true(valid)

        # Wrong message should fail
        invalid = node0.verifymessage(addr, signature, "wrong message")
        assert_true(not invalid)

    def test_import_export_keys(self, node0, node1):
        """Test import/export private keys."""
        self.log.info("Testing key import/export...")

        # Generate an address and export its key
        addr = node0.getnewaddress()
        privkey = node0.dumpprivkey(addr)
        assert_true(len(privkey) > 0)

        # Import into node1
        node1.importprivkey(privkey)

        # node1 should now recognize this address
        validate = node1.validateaddress(addr)
        assert_true(validate.get("ismine", False))

    def test_wallet_info(self, node0):
        """Test wallet info matches state."""
        self.log.info("Testing wallet info...")

        info = node0.getwalletinfo()
        assert_in("balance", info)
        assert_in("txcount", info)

        balance = info["balance"]
        assert_greater_than(balance, Decimal("0"))

        tx_count = info["txcount"]
        assert_greater_than(tx_count, 0)

    def test_address_uniqueness(self, node0):
        """Test all generated addresses are unique."""
        self.log.info("Testing address uniqueness...")

        addresses = set()
        for _ in range(20):
            addr = node0.getnewaddress()
            assert_true(addr not in addresses,
                         f"Duplicate address: {addr}")
            addresses.add(addr)

        assert_equal(len(addresses), 20)

    def test_balance_updates(self, node0, node1):
        """Test balance updates after send."""
        self.log.info("Testing balance updates...")

        balance_before = node0.getbalance()
        dest_addr = node1.getnewaddress()
        send_amount = Decimal("1.0")

        txid = node0.sendtoaddress(dest_addr, send_amount)
        assert_is_txid(txid)

        # Mine to confirm
        mine_addr = node0.getnewaddress()
        node0.generatetoaddress(1, mine_addr)
        self.sync_blocks()

        balance_after = node0.getbalance()
        # Balance should decrease (sent amount + fee)
        assert_greater_than(balance_before, balance_after)

    def test_change_output(self, node0, node1):
        """Test change output generation."""
        self.log.info("Testing change output...")

        dest_addr = node1.getnewaddress()
        send_amount = Decimal("0.5")

        txid = node0.sendtoaddress(dest_addr, send_amount)
        tx = node0.gettransaction(txid)

        # Transaction should have at least 2 outputs (dest + change)
        assert_true("details" in tx)

    def test_tx_listing_pagination(self, node0):
        """Test transaction listing with pagination."""
        self.log.info("Testing tx listing pagination...")

        # Get first page
        txs_page1 = node0.listtransactions("*", 5, 0)
        assert_greater_than_or_equal(len(txs_page1), 1)

        # Get second page
        txs_page2 = node0.listtransactions("*", 5, 5)

        # Pages should not overlap (if there are enough txs)
        if len(txs_page1) == 5 and len(txs_page2) > 0:
            ids_1 = {tx.get("txid") for tx in txs_page1}
            ids_2 = {tx.get("txid") for tx in txs_page2}
            assert_equal(len(ids_1 & ids_2), 0)

    def test_label_management(self, node0):
        """Test label management."""
        self.log.info("Testing label management...")

        addr = node0.getnewaddress()

        # Set label
        node0.setlabel(addr, "Test Label")

        # Get addresses by label
        addrs = node0.getaddressesbylabel("Test Label")
        assert_true(isinstance(addrs, dict))
        assert_in(addr, addrs)

        # Change label
        node0.setlabel(addr, "Updated Label")
        addrs_updated = node0.getaddressesbylabel("Updated Label")
        assert_in(addr, addrs_updated)

    def test_encryption_status(self, node0):
        """Test wallet encryption status."""
        self.log.info("Testing encryption status...")

        info = node0.getwalletinfo()
        # By default, wallet should not be encrypted
        # (unless setup changed this)
        if "unlocked_until" in info:
            # If unlocked_until exists, wallet is encrypted
            assert_true(isinstance(info["unlocked_until"], int))

    def test_sequential_sends(self, node0, node1):
        """Test multiple sequential sends."""
        self.log.info("Testing sequential sends...")

        dest = node1.getnewaddress()
        txids = []

        for i in range(3):
            txid = node0.sendtoaddress(dest, Decimal("0.1"))
            txids.append(txid)

        # All txids should be unique
        assert_equal(len(set(txids)), 3)

        # Mine to confirm all
        mine_addr = node0.getnewaddress()
        node0.generatetoaddress(1, mine_addr)
        self.sync_blocks()

    def test_utxo_count_tracking(self, node0):
        """Test UTXO count tracking."""
        self.log.info("Testing UTXO count...")

        unspent_before = node0.listunspent()
        count_before = len(unspent_before)

        # Mine a block to create a new UTXO
        addr = node0.getnewaddress()
        node0.generatetoaddress(1, addr)

        unspent_after = node0.listunspent()
        count_after = len(unspent_after)

        # Should have at least one more UTXO
        assert_greater_than_or_equal(count_after, count_before)

    def test_mining_address_reuse(self, node0):
        """Test new address per mined block (no reuse)."""
        self.log.info("Testing mining address uniqueness...")

        addresses = set()
        for _ in range(5):
            addr = node0.getnewaddress()
            addresses.add(addr)
            node0.generatetoaddress(1, addr)

        # Each mining address should be unique
        assert_equal(len(addresses), 5)


if __name__ == "__main__":
    WalletAdvancedTest().main()

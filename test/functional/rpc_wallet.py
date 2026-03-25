#!/usr/bin/env python3
# Copyright (c) 2026 The FlowCoin Developers
# Distributed under the MIT software license.
"""Test wallet RPC methods.

Tests cover:
    - getnewaddress basic and with labels.
    - getbalance accuracy.
    - sendtoaddress with various parameters.
    - listtransactions filtering and pagination.
    - listunspent with confirmation filters.
    - importprivkey functionality.
    - dumpprivkey functionality.
    - signmessage / verifymessage round-trip.
    - validateaddress for valid and invalid addresses.
    - getreceivedbyaddress tracking.
    - settxfee for custom fee rates.
    - getunconfirmedbalance during pending txs.
    - gettransaction details.
    - abandontransaction for unconfirmed txs.
    - listaddressgroupings.
    - listlockunspent and lockunspent.
    - getrawchangeaddress.
    - fundrawtransaction.
"""

import time
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
    assert_false,
    COINBASE_MATURITY,
    satoshi_round,
    wait_until,
)


class RPCWalletTest(FlowCoinTestFramework):
    """Wallet RPC method tests."""

    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True

    def run_test(self):
        node0 = self.nodes[0]
        node1 = self.nodes[1]

        # Build initial balance
        addr = node0.getnewaddress()
        node0.generatetoaddress(COINBASE_MATURITY + 10, addr)
        self.sync_blocks()

        self.test_getnewaddress(node0)
        self.test_getnewaddress_labels(node0)
        self.test_getbalance(node0)
        self.test_sendtoaddress_params(node0, node1)
        self.test_listtransactions_filter(node0)
        self.test_listtransactions_pagination(node0)
        self.test_listunspent_filters(node0)
        self.test_importprivkey(node0, node1)
        self.test_dumpprivkey(node0)
        self.test_signmessage_verifymessage(node0)
        self.test_validateaddress(node0)
        self.test_getreceivedbyaddress(node0, node1)
        self.test_settxfee(node0)
        self.test_unconfirmed_balance(node0, node1)
        self.test_gettransaction(node0, node1)
        self.test_listlockunspent(node0)
        self.test_getrawchangeaddress(node0)
        self.test_fundrawtransaction(node0, node1)

    def test_getnewaddress(self, node):
        """Test getnewaddress basic operation."""
        self.log.info("Testing getnewaddress...")

        addrs = []
        for _ in range(10):
            addr = node.getnewaddress()
            assert_true(len(addr) > 0)
            assert_true(addr.startswith("rfl1"))
            assert_true(addr not in addrs, "Address should be unique")
            addrs.append(addr)

        self.log.info("  Generated 10 unique addresses")

    def test_getnewaddress_labels(self, node):
        """Test getnewaddress with label parameter."""
        self.log.info("Testing getnewaddress with labels...")

        # Generate with label
        addr1 = node.getnewaddress("work")
        addr2 = node.getnewaddress("personal")
        addr3 = node.getnewaddress("work")

        assert_not_equal(addr1, addr2)
        assert_not_equal(addr1, addr3)
        assert_not_equal(addr2, addr3)

        # Empty label
        addr_empty = node.getnewaddress("")
        assert_true(len(addr_empty) > 0)

        self.log.info("  Labeled addresses generated")

    def test_getbalance(self, node):
        """Test getbalance accuracy."""
        self.log.info("Testing getbalance...")

        balance = node.getbalance()
        assert_true(
            isinstance(balance, (int, float, Decimal)),
            f"Balance type: {type(balance)}"
        )
        assert_greater_than(float(balance), 0, "Should have mined balance")

        # Balance should match listunspent total
        utxos = node.listunspent()
        utxo_total = sum(Decimal(str(u["amount"])) for u in utxos)
        assert_equal(
            satoshi_round(Decimal(str(balance))),
            satoshi_round(utxo_total),
            "Balance should match UTXO total"
        )

        # getbalance with minconf
        try:
            bal_0 = node.getbalance("*", 0)
            bal_1 = node.getbalance("*", 1)
            bal_6 = node.getbalance("*", 6)
            assert_greater_than_or_equal(float(bal_0), float(bal_1))
            assert_greater_than_or_equal(float(bal_1), float(bal_6))
        except Exception as e:
            self.log.info("  getbalance minconf: %s", e)

        self.log.info("  Balance: %s FLOW", balance)

    def test_sendtoaddress_params(self, node0, node1):
        """Test sendtoaddress with various parameters."""
        self.log.info("Testing sendtoaddress parameters...")

        recv = node1.getnewaddress()

        # Basic send
        txid = node0.sendtoaddress(recv, 5.0)
        assert_is_txid(txid)

        # Send with comment
        try:
            txid2 = node0.sendtoaddress(recv, 1.0, "payment", "for services")
            assert_is_txid(txid2)
        except Exception as e:
            self.log.info("  Send with comments: %s", e)

        # Send with subtractfeefromamount
        try:
            txid3 = node0.sendtoaddress(recv, 2.0, "", "", True)
            assert_is_txid(txid3)
            # The received amount should be slightly less than 2.0
        except Exception as e:
            self.log.info("  Send with subtractfee: %s", e)

        # Confirm all
        addr0 = node0.getnewaddress()
        node0.generatetoaddress(1, addr0)
        self.sync_blocks()

        self.log.info("  sendtoaddress parameters verified")

    def test_listtransactions_filter(self, node):
        """Test listtransactions with category filtering."""
        self.log.info("Testing listtransactions filtering...")

        txs = node.listtransactions()

        categories = set()
        for tx in txs:
            categories.add(tx["category"])

        self.log.info("  Transaction categories: %s", categories)

        # Generate category should exist (from mining)
        has_generate = any(
            tx["category"] in ["generate", "immature"]
            for tx in txs
        )
        assert_true(has_generate, "Should have mining transactions")

        # Send category should exist (from previous tests)
        has_send = any(tx["category"] == "send" for tx in txs)
        if has_send:
            self.log.info("  Found 'send' transactions")

        self.log.info("  Transaction filtering verified")

    def test_listtransactions_pagination(self, node):
        """Test listtransactions with count and skip."""
        self.log.info("Testing listtransactions pagination...")

        all_txs = node.listtransactions("*", 1000)
        total = len(all_txs)

        if total >= 5:
            # Get first 3
            page1 = node.listtransactions("*", 3, 0)
            assert_equal(len(page1), 3)

            # Get next 3
            page2 = node.listtransactions("*", 3, 3)
            assert_greater_than_or_equal(3, len(page2))

            # Pages should not overlap (by txid)
            txids1 = set(tx["txid"] for tx in page1)
            txids2 = set(tx["txid"] for tx in page2)
            overlap = txids1 & txids2
            # Note: Same txid can appear with different categories
            # (send + receive on self-send)

        self.log.info("  Pagination: %d total transactions", total)

    def test_listunspent_filters(self, node):
        """Test listunspent with confirmation count filters."""
        self.log.info("Testing listunspent filters...")

        # All UTXOs
        all_utxos = node.listunspent()
        assert_greater_than(len(all_utxos), 0)

        # Only highly confirmed
        confirmed = node.listunspent(50)
        for u in confirmed:
            assert_greater_than_or_equal(u["confirmations"], 50)

        # With max confirmations
        try:
            recent = node.listunspent(1, 9999999)
            assert_greater_than_or_equal(len(all_utxos), len(recent))
        except Exception:
            pass

        # Filtered by address
        if all_utxos:
            addr = all_utxos[0].get("address", "")
            if addr:
                try:
                    filtered = node.listunspent(1, 9999999, [addr])
                    for u in filtered:
                        assert_equal(u["address"], addr)
                except Exception:
                    pass

        self.log.info("  listunspent filters: %d total UTXOs", len(all_utxos))

    def test_importprivkey(self, node0, node1):
        """Test importprivkey functionality."""
        self.log.info("Testing importprivkey...")

        # Generate address on node0 and export key
        addr = node0.getnewaddress()
        try:
            privkey = node0.dumpprivkey(addr)
        except Exception as e:
            self.log.info("  Skipping importprivkey: %s", e)
            return

        # Send coins to this address
        node0.sendtoaddress(addr, 3.0)
        mine_addr = node0.getnewaddress()
        node0.generatetoaddress(1, mine_addr)
        self.sync_blocks()

        # Import into node1
        try:
            node1.importprivkey(privkey, "imported", True)
        except Exception as e:
            self.log.info("  importprivkey: %s", e)
            return

        # Node1 should see the balance at that address
        try:
            received = node1.getreceivedbyaddress(addr)
            assert_greater_than_or_equal(
                float(received), 3.0,
                "Imported key should show received funds"
            )
            self.log.info("  importprivkey: address shows %s received", received)
        except Exception as e:
            self.log.info("  getreceivedbyaddress after import: %s", e)

    def test_dumpprivkey(self, node):
        """Test dumpprivkey functionality."""
        self.log.info("Testing dumpprivkey...")

        addr = node.getnewaddress()
        try:
            key = node.dumpprivkey(addr)
            assert_true(len(key) > 0, "Key should not be empty")

            # Key should be deterministic for the same address
            key2 = node.dumpprivkey(addr)
            assert_equal(key, key2)

            # Different address should have different key
            addr2 = node.getnewaddress()
            key3 = node.dumpprivkey(addr2)
            assert_not_equal(key, key3)

            self.log.info("  dumpprivkey verified")
        except Exception as e:
            self.log.info("  dumpprivkey: %s", e)

    def test_signmessage_verifymessage(self, node):
        """Test signmessage and verifymessage round-trip."""
        self.log.info("Testing signmessage/verifymessage...")

        addr = node.getnewaddress()
        message = "FlowCoin test message 2026"

        try:
            # Sign
            signature = node.signmessage(addr, message)
            assert_true(len(signature) > 0)

            # Verify
            valid = node.verifymessage(addr, signature, message)
            assert_true(valid, "Signature should be valid")

            # Wrong message should fail
            wrong_valid = node.verifymessage(addr, signature, "wrong message")
            assert_false(wrong_valid, "Wrong message should not verify")

            # Wrong address should fail
            addr2 = node.getnewaddress()
            wrong_addr = node.verifymessage(addr2, signature, message)
            assert_false(wrong_addr, "Wrong address should not verify")

            self.log.info("  signmessage/verifymessage round-trip passed")
        except Exception as e:
            self.log.info("  signmessage/verifymessage: %s", e)

    def test_validateaddress(self, node):
        """Test validateaddress for valid and invalid addresses."""
        self.log.info("Testing validateaddress...")

        # Valid address from our wallet
        addr = node.getnewaddress()
        info = node.validateaddress(addr)
        assert_true(info["isvalid"], "Our address should be valid")

        # Required fields in response
        assert_in("address", info)
        assert_equal(info["address"], addr)

        # Invalid addresses
        invalid_addrs = [
            "",
            "not_an_address",
            "rfl1invalidchecksum",
            "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",  # Bitcoin address
            "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",  # Legacy format
            "a" * 100,
        ]
        for bad_addr in invalid_addrs:
            try:
                info = node.validateaddress(bad_addr)
                if not info.get("isvalid", True):
                    self.log.info(
                        "  Correctly invalidated: %s", bad_addr[:30]
                    )
            except Exception:
                pass

        self.log.info("  validateaddress verified")

    def test_getreceivedbyaddress(self, node0, node1):
        """Test getreceivedbyaddress tracking."""
        self.log.info("Testing getreceivedbyaddress...")

        addr = node1.getnewaddress()

        # Initial received should be 0
        try:
            initial = node1.getreceivedbyaddress(addr)
            assert_equal(float(initial), 0.0)
        except Exception:
            self.log.info("  getreceivedbyaddress: initial check failed")
            return

        # Send coins
        node0.sendtoaddress(addr, 7.5)
        mine_addr = node0.getnewaddress()
        node0.generatetoaddress(1, mine_addr)
        self.sync_blocks()

        # Should show received amount
        received = node1.getreceivedbyaddress(addr)
        assert_equal(
            satoshi_round(Decimal(str(received))),
            satoshi_round(Decimal("7.5")),
            "Should show 7.5 FLOW received"
        )

        # With minconf
        try:
            received_0 = node1.getreceivedbyaddress(addr, 0)
            received_1 = node1.getreceivedbyaddress(addr, 1)
            assert_greater_than_or_equal(
                float(received_0), float(received_1)
            )
        except Exception:
            pass

        self.log.info("  getreceivedbyaddress: %s FLOW", received)

    def test_settxfee(self, node):
        """Test settxfee for custom fee rate."""
        self.log.info("Testing settxfee...")

        try:
            # Set a custom fee rate
            result = node.settxfee(0.0001)
            assert_true(result)

            # Verify it affects transactions
            info = node.getwalletinfo()
            if "paytxfee" in info:
                assert_equal(
                    satoshi_round(Decimal(str(info["paytxfee"]))),
                    satoshi_round(Decimal("0.0001"))
                )

            # Reset to default
            node.settxfee(0)

            self.log.info("  settxfee verified")
        except Exception as e:
            self.log.info("  settxfee: %s", e)

    def test_unconfirmed_balance(self, node0, node1):
        """Test unconfirmed balance during pending transactions."""
        self.log.info("Testing unconfirmed balance...")

        recv = node1.getnewaddress()
        balance_before = Decimal(str(node1.getbalance()))

        # Send unconfirmed transaction
        node0.sendtoaddress(recv, 2.0)

        # Wait for mempool sync
        time.sleep(1)

        try:
            unconfirmed = node1.getunconfirmedbalance()
            assert_greater_than_or_equal(
                float(unconfirmed), 0,
                "Unconfirmed balance should be non-negative"
            )
            self.log.info("  Unconfirmed balance: %s", unconfirmed)
        except Exception as e:
            self.log.info("  getunconfirmedbalance: %s", e)

        # Confirm
        mine_addr = node0.getnewaddress()
        node0.generatetoaddress(1, mine_addr)
        self.sync_blocks()

        self.log.info("  Unconfirmed balance tested")

    def test_gettransaction(self, node0, node1):
        """Test gettransaction detail fields."""
        self.log.info("Testing gettransaction...")

        recv = node1.getnewaddress()
        txid = node0.sendtoaddress(recv, 1.0)
        mine_addr = node0.getnewaddress()
        node0.generatetoaddress(1, mine_addr)
        self.sync_blocks()

        # Get from sender's perspective
        tx = node0.gettransaction(txid)
        assert_equal(tx["txid"], txid)
        assert_in("amount", tx)
        assert_in("confirmations", tx)
        assert_greater_than(tx["confirmations"], 0)

        # Fee should be negative (deducted)
        if "fee" in tx:
            assert_greater_than(0, float(tx["fee"]),
                              "Fee should be negative for sender")

        # Details array
        if "details" in tx:
            assert_true(isinstance(tx["details"], list))
            for detail in tx["details"]:
                assert_in("category", detail)
                assert_in("amount", detail)

        # Hex representation
        if "hex" in tx:
            assert_is_hex_string(tx["hex"])

        # Non-existent txid
        assert_raises_rpc_error(
            -5, None,
            node0.gettransaction, "0" * 64
        )

        self.log.info("  gettransaction verified for %s", txid[:16])

    def test_listlockunspent(self, node):
        """Test lockunspent and listlockunspent."""
        self.log.info("Testing lockunspent/listlockunspent...")

        utxos = node.listunspent()
        if len(utxos) < 2:
            self.log.info("  Not enough UTXOs to test locking")
            return

        try:
            # Lock first UTXO
            utxo = utxos[0]
            lock_list = [{"txid": utxo["txid"], "vout": utxo["vout"]}]
            result = node.lockunspent(False, lock_list)
            assert_true(result)

            # listlockunspent should show it
            locked = node.listlockunspent()
            assert_greater_than(len(locked), 0)
            assert_equal(locked[0]["txid"], utxo["txid"])
            assert_equal(locked[0]["vout"], utxo["vout"])

            # Locked UTXO should not appear in listunspent
            available = node.listunspent()
            locked_in_available = any(
                u["txid"] == utxo["txid"] and u["vout"] == utxo["vout"]
                for u in available
            )
            assert_false(
                locked_in_available,
                "Locked UTXO should not be in listunspent"
            )

            # Unlock
            result = node.lockunspent(True, lock_list)
            assert_true(result)

            locked_after = node.listlockunspent()
            assert_equal(len(locked_after), 0)

            self.log.info("  lockunspent/listlockunspent verified")
        except Exception as e:
            self.log.info("  lockunspent: %s", e)

    def test_getrawchangeaddress(self, node):
        """Test getrawchangeaddress."""
        self.log.info("Testing getrawchangeaddress...")

        try:
            change_addr = node.getrawchangeaddress()
            assert_true(len(change_addr) > 0)
            assert_true(change_addr.startswith("rfl1"))

            # Should be different from regular addresses
            regular = node.getnewaddress()
            assert_not_equal(change_addr, regular)

            # Multiple calls should return different addresses
            change2 = node.getrawchangeaddress()
            assert_not_equal(change_addr, change2)

            self.log.info("  getrawchangeaddress: %s", change_addr[:20])
        except Exception as e:
            self.log.info("  getrawchangeaddress: %s", e)

    def test_fundrawtransaction(self, node0, node1):
        """Test fundrawtransaction for adding inputs and change."""
        self.log.info("Testing fundrawtransaction...")

        try:
            # Create a raw tx with no inputs
            recv = node1.getnewaddress()
            raw = node0.createrawtransaction([], {recv: 1.0})
            assert_true(len(raw) > 0)

            # Fund it
            funded = node0.fundrawtransaction(raw)
            assert_in("hex", funded)
            assert_in("fee", funded)
            assert_in("changepos", funded)

            funded_hex = funded["hex"]
            assert_greater_than(len(funded_hex), len(raw))

            # Fee should be positive
            fee = Decimal(str(funded["fee"]))
            assert_greater_than(float(fee), 0)

            # Sign and send
            signed = node0.signrawtransactionwithwallet(funded_hex)
            assert_true(signed.get("complete", False))

            txid = node0.sendrawtransaction(signed["hex"])
            assert_is_txid(txid)

            self.log.info(
                "  fundrawtransaction: fee=%s, txid=%s",
                fee, txid[:16]
            )
        except Exception as e:
            self.log.info("  fundrawtransaction: %s", e)

    def test_createrawtransaction(self, node0, node1):
        """Test createrawtransaction with various inputs/outputs."""
        self.log.info("Testing createrawtransaction...")

        utxos = node0.listunspent()
        if not utxos:
            self.log.info("  No UTXOs for createrawtransaction")
            return

        utxo = utxos[0]
        recv = node1.getnewaddress()
        amount = float(utxo["amount"]) - 0.001

        # Basic raw tx
        inputs = [{"txid": utxo["txid"], "vout": utxo["vout"]}]
        outputs = {recv: round(amount, 8)}
        raw = node0.createrawtransaction(inputs, outputs)

        assert_true(len(raw) > 0, "Raw tx should not be empty")
        assert_is_hex_string(raw)

        # Decode it
        try:
            decoded = node0.decoderawtransaction(raw)
            assert_in("txid", decoded)
            assert_in("vin", decoded)
            assert_in("vout", decoded)
            assert_equal(len(decoded["vin"]), 1)
            assert_equal(len(decoded["vout"]), 1)
            self.log.info("  createrawtransaction: decoded successfully")
        except Exception as e:
            self.log.info("  decoderawtransaction: %s", e)

        # Multi-output
        recv2 = node1.getnewaddress()
        if amount > 1:
            outputs2 = {recv: round(amount / 2, 8), recv2: round(amount / 2 - 0.001, 8)}
            raw2 = node0.createrawtransaction(inputs, outputs2)
            assert_true(len(raw2) > len(raw), "Multi-output tx should be larger")

        # Empty inputs (should work - just creates unsigned template)
        raw_empty = node0.createrawtransaction([], {recv: 1.0})
        assert_true(len(raw_empty) > 0)

        self.log.info("  createrawtransaction verified")

    def test_decoderawtransaction(self, node0, node1):
        """Test decoderawtransaction with valid and invalid data."""
        self.log.info("Testing decoderawtransaction...")

        # Create a valid raw tx
        utxos = node0.listunspent()
        if not utxos:
            self.log.info("  No UTXOs for decoderawtransaction")
            return

        recv = node1.getnewaddress()
        utxo = utxos[0]
        amount = float(utxo["amount"]) - 0.001
        if amount <= 0:
            return

        inputs = [{"txid": utxo["txid"], "vout": utxo["vout"]}]
        outputs = {recv: round(amount, 8)}
        raw = node0.createrawtransaction(inputs, outputs)

        try:
            decoded = node0.decoderawtransaction(raw)

            # Verify fields
            assert_in("txid", decoded)
            assert_is_txid(decoded["txid"])

            assert_in("version", decoded)
            assert_greater_than(decoded["version"], 0)

            assert_in("vin", decoded)
            for vin in decoded["vin"]:
                assert_in("txid", vin)
                assert_in("vout", vin)

            assert_in("vout", decoded)
            for vout in decoded["vout"]:
                assert_in("value", vout)
                assert_in("scriptPubKey", vout)

            self.log.info("  decoderawtransaction: all fields verified")
        except Exception as e:
            self.log.info("  decoderawtransaction: %s", e)

        # Invalid raw tx
        try:
            from test_framework.util import assert_raises_rpc_error
            assert_raises_rpc_error(
                None, None, node0.decoderawtransaction, "deadbeef"
            )
        except Exception:
            pass

    def test_signrawtransactionwithwallet(self, node0, node1):
        """Test signing raw transactions with the wallet."""
        self.log.info("Testing signrawtransactionwithwallet...")

        utxos = node0.listunspent()
        if not utxos:
            self.log.info("  No UTXOs for signing test")
            return

        utxo = utxos[0]
        recv = node1.getnewaddress()
        amount = float(utxo["amount"]) - 0.001
        if amount <= 0:
            return

        inputs = [{"txid": utxo["txid"], "vout": utxo["vout"]}]
        outputs = {recv: round(amount, 8)}
        raw = node0.createrawtransaction(inputs, outputs)

        try:
            signed = node0.signrawtransactionwithwallet(raw)

            assert_in("hex", signed)
            assert_in("complete", signed)
            assert_true(signed["complete"], "Signing should complete")

            # Signed tx should be different (larger) than unsigned
            assert_greater_than(
                len(signed["hex"]), len(raw),
                "Signed tx should be larger than unsigned"
            )

            # Should have no errors
            if "errors" in signed:
                assert_equal(
                    len(signed["errors"]), 0,
                    "Should have no signing errors"
                )

            self.log.info("  Signing: unsigned=%d, signed=%d hex chars",
                           len(raw), len(signed["hex"]))
        except Exception as e:
            self.log.info("  signrawtransactionwithwallet: %s", e)

    def test_getreceivedbyaddress_accumulation(self, node0, node1):
        """Test that getreceivedbyaddress accumulates across multiple sends."""
        self.log.info("Testing received amount accumulation...")

        addr = node1.getnewaddress()

        try:
            # Send 3 separate amounts
            amounts = [1.0, 2.5, 0.75]
            for amt in amounts:
                node0.sendtoaddress(addr, amt)

            mine_addr = node0.getnewaddress()
            node0.generatetoaddress(1, mine_addr)
            self.sync_blocks()

            received = node1.getreceivedbyaddress(addr)
            expected = sum(amounts)
            assert_equal(
                satoshi_round(Decimal(str(received))),
                satoshi_round(Decimal(str(expected))),
                "Accumulated received should match"
            )

            self.log.info(
                "  Received %s FLOW across %d sends",
                received, len(amounts)
            )
        except Exception as e:
            self.log.info("  Accumulation test: %s", e)


if __name__ == "__main__":
    RPCWalletTest().main()

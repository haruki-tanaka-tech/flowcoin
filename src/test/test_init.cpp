// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// Tests for command-line argument parsing (init.h / init.cpp).

#include "init.h"
#include "consensus/params.h"

#include <cassert>
#include <cstring>
#include <string>
#include <vector>

// Helper: build an argv array from a list of strings
struct ArgvBuilder {
    std::vector<std::string> args;
    std::vector<char*> ptrs;

    void add(const std::string& arg) {
        args.push_back(arg);
    }

    int argc() { return static_cast<int>(args.size()); }

    char** argv() {
        ptrs.clear();
        for (auto& s : args) {
            ptrs.push_back(const_cast<char*>(s.c_str()));
        }
        ptrs.push_back(nullptr);
        return ptrs.data();
    }
};

void test_init() {
    // -----------------------------------------------------------------------
    // Test 1: parse_args with no args returns defaults
    // -----------------------------------------------------------------------
    {
        ArgvBuilder ab;
        ab.add("flowcoind");

        flow::AppArgs cfg = flow::parse_args(ab.argc(), ab.argv());
        assert(cfg.testnet == false);
        assert(cfg.regtest == false);
        assert(cfg.daemon == false);
    }

    // -----------------------------------------------------------------------
    // Test 2: parse_args with --testnet
    // -----------------------------------------------------------------------
    {
        ArgvBuilder ab;
        ab.add("flowcoind");
        ab.add("--testnet");

        flow::AppArgs cfg = flow::parse_args(ab.argc(), ab.argv());
        assert(cfg.testnet == true);
        assert(cfg.regtest == false);
    }

    // -----------------------------------------------------------------------
    // Test 3: parse_args with --regtest
    // -----------------------------------------------------------------------
    {
        ArgvBuilder ab;
        ab.add("flowcoind");
        ab.add("--regtest");

        flow::AppArgs cfg = flow::parse_args(ab.argc(), ab.argv());
        assert(cfg.regtest == true);
        assert(cfg.testnet == false);
    }

    // -----------------------------------------------------------------------
    // Test 4: parse_args with --datadir=/tmp/test
    // -----------------------------------------------------------------------
    {
        ArgvBuilder ab;
        ab.add("flowcoind");
        ab.add("--datadir=/tmp/test");

        flow::AppArgs cfg = flow::parse_args(ab.argc(), ab.argv());
        assert(cfg.datadir == "/tmp/test");
    }

    // -----------------------------------------------------------------------
    // Test 5: parse_args with --datadir as separate arg
    // -----------------------------------------------------------------------
    {
        ArgvBuilder ab;
        ab.add("flowcoind");
        ab.add("--datadir");
        ab.add("/tmp/test2");

        flow::AppArgs cfg = flow::parse_args(ab.argc(), ab.argv());
        assert(cfg.datadir == "/tmp/test2");
    }

    // -----------------------------------------------------------------------
    // Test 6: parse_args with --rpcuser/--rpcpassword (= form)
    // -----------------------------------------------------------------------
    {
        ArgvBuilder ab;
        ab.add("flowcoind");
        ab.add("--rpcuser=admin");
        ab.add("--rpcpassword=hunter2");

        flow::AppArgs cfg = flow::parse_args(ab.argc(), ab.argv());
        assert(cfg.rpc_user == "admin");
        assert(cfg.rpc_password == "hunter2");
    }

    // -----------------------------------------------------------------------
    // Test 7: parse_args with --rpcuser/--rpcpassword (space form)
    // -----------------------------------------------------------------------
    {
        ArgvBuilder ab;
        ab.add("flowcoind");
        ab.add("--rpcuser");
        ab.add("admin2");
        ab.add("--rpcpassword");
        ab.add("pass2");

        flow::AppArgs cfg = flow::parse_args(ab.argc(), ab.argv());
        assert(cfg.rpc_user == "admin2");
        assert(cfg.rpc_password == "pass2");
    }

    // -----------------------------------------------------------------------
    // Test 8: parse_args with --port and --rpcport
    // -----------------------------------------------------------------------
    {
        ArgvBuilder ab;
        ab.add("flowcoind");
        ab.add("--port=8888");
        ab.add("--rpcport=9999");

        flow::AppArgs cfg = flow::parse_args(ab.argc(), ab.argv());
        assert(cfg.port == 8888);
        assert(cfg.rpc_port == 9999);
    }

    // -----------------------------------------------------------------------
    // Test 9: parse_args with --port and --rpcport (space form)
    // -----------------------------------------------------------------------
    {
        ArgvBuilder ab;
        ab.add("flowcoind");
        ab.add("--port");
        ab.add("7777");
        ab.add("--rpcport");
        ab.add("6666");

        flow::AppArgs cfg = flow::parse_args(ab.argc(), ab.argv());
        assert(cfg.port == 7777);
        assert(cfg.rpc_port == 6666);
    }

    // -----------------------------------------------------------------------
    // Test 10: parse_args with --daemon flag
    // -----------------------------------------------------------------------
    {
        ArgvBuilder ab;
        ab.add("flowcoind");
        ab.add("--daemon");

        flow::AppArgs cfg = flow::parse_args(ab.argc(), ab.argv());
        assert(cfg.daemon == true);
    }

    // -----------------------------------------------------------------------
    // Test 11: parse_args with unknown arg (ignored, does not crash)
    // -----------------------------------------------------------------------
    {
        ArgvBuilder ab;
        ab.add("flowcoind");
        ab.add("--unknown-option");
        ab.add("--anotherthing=foo");

        flow::AppArgs cfg = flow::parse_args(ab.argc(), ab.argv());
        // Unknown args are silently ignored; defaults preserved
        assert(!cfg.testnet);
        assert(!cfg.regtest);
    }

    // -----------------------------------------------------------------------
    // Test 12: parse_args with multiple flags combined
    // -----------------------------------------------------------------------
    {
        ArgvBuilder ab;
        ab.add("flowcoind");
        ab.add("--testnet");
        ab.add("--daemon");
        ab.add("--datadir=/custom");
        ab.add("--rpcuser=admin");
        ab.add("--rpcpassword=pass");
        ab.add("--port=12345");
        ab.add("--rpcport=12346");

        flow::AppArgs cfg = flow::parse_args(ab.argc(), ab.argv());
        assert(cfg.testnet == true);
        assert(cfg.daemon == true);
        assert(cfg.datadir == "/custom");
        assert(cfg.rpc_user == "admin");
        assert(cfg.rpc_password == "pass");
        assert(cfg.port == 12345);
        assert(cfg.rpc_port == 12346);
    }

    // -----------------------------------------------------------------------
    // Test 13: NodeConfig defaults are correct
    // -----------------------------------------------------------------------
    {
        flow::NodeConfig cfg;
        assert(cfg.datadir == "data");
        assert(cfg.port == 9333);
        assert(cfg.rpc_port == 9334);
        assert(cfg.rpc_user == "flowcoin");
        assert(cfg.rpc_password == "flowcoin");
        assert(cfg.testnet == false);
        assert(cfg.regtest == false);
        assert(cfg.daemon == false);
    }

    // -----------------------------------------------------------------------
    // Test 14: parse_args with empty datadir value
    // -----------------------------------------------------------------------
    {
        ArgvBuilder ab;
        ab.add("flowcoind");
        ab.add("--datadir=");

        flow::AppArgs cfg = flow::parse_args(ab.argc(), ab.argv());
        assert(cfg.datadir.empty());
    }

    // -----------------------------------------------------------------------
    // Test 15: Testnet and regtest ports
    // -----------------------------------------------------------------------
    {
        assert(flow::consensus::MAINNET_PORT == 9333);
        assert(flow::consensus::MAINNET_RPC_PORT == 9334);
        assert(flow::consensus::TESTNET_PORT == 19333);
        assert(flow::consensus::TESTNET_RPC_PORT == 19334);
        assert(flow::consensus::REGTEST_PORT == 29333);
        assert(flow::consensus::REGTEST_RPC_PORT == 29334);
    }

    // -----------------------------------------------------------------------
    // Test 16: parse_args only program name
    // -----------------------------------------------------------------------
    {
        ArgvBuilder ab;
        ab.add("flowcoind");

        flow::AppArgs cfg = flow::parse_args(ab.argc(), ab.argv());
        // All defaults
        assert(!cfg.testnet);
        assert(!cfg.regtest);
        assert(!cfg.daemon);
    }
}

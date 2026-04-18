// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// flowcoind: Main daemon entry point for the FlowCoin full node.
// Parses arguments, initializes all subsystems via the 12-step init
// sequence, installs signal handlers, and runs the event loop until
// shutdown. Supports daemonization (--daemon), testnet/regtest modes,
// and full configuration via command-line args and flowcoin.conf.

#include "init.h"
#include "logging.h"
#include "net/net.h"
#include "node/context.h"
#include "version.h"

#include <uv.h>

#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <thread>

#ifdef _WIN32
#include <io.h>
#include <process.h>
#else
#include <unistd.h>
#endif

// ============================================================================
// Global state for signal handling
// ============================================================================

static flow::NodeContext* g_node = nullptr;
static volatile sig_atomic_t g_signal_count = 0;

static void signal_handler(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
        g_signal_count++;

        if (g_signal_count == 1) {
            const char* msg = "\nShutting down...\n";
#ifdef _WIN32
            if (::_write(_fileno(stderr), msg, (unsigned)strlen(msg)) < 0) {}
#else
            if (::write(STDERR_FILENO, msg, strlen(msg)) < 0) {}
#endif
            if (g_node) g_node->interrupt();
            flow::get_shutdown_state().request_shutdown();
        } else {
            // Second signal: force exit
            const char* msg = "Forced exit.\n";
#ifdef _WIN32
            if (::_write(_fileno(stderr), msg, (unsigned)strlen(msg)) < 0) {}
            ::_exit(0);
#else
            if (::write(STDERR_FILENO, msg, strlen(msg)) < 0) {}
            _exit(0);
#endif
        }
    }
}

static void install_signal_handlers() {
#ifdef _WIN32
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
#else
    struct sigaction sa;
    std::memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);

    // Ignore SIGPIPE (broken pipe from network writes)
    signal(SIGPIPE, SIG_IGN);

    // Ignore SIGHUP in daemon mode (terminal hangup)
    signal(SIGHUP, SIG_IGN);
#endif
}

// ============================================================================
// Main entry point
// ============================================================================

int main(int argc, char* argv[]) {
    // ---- Parse command-line arguments ----
    flow::AppArgs args = flow::parse_args(argc, argv);

    if (args.print_help) {
        flow::print_help();
        return EXIT_SUCCESS;
    }

    if (args.print_version) {
        flow::print_version();
        return EXIT_SUCCESS;
    }

    // ---- Daemonize if requested ----
    if (args.daemon) {

        if (!flow::sys::daemonize()) {
            std::cerr << "Error: daemonization failed" << std::endl;
            return EXIT_FAILURE;
        }
        // After daemonize(), stdout/stderr are redirected to /dev/null.
        // All further output goes to the log file.
    }

    // ---- Install signal handlers ----
    install_signal_handlers();

    // ---- Create node context ----
    flow::NodeContext node;
    g_node = &node;

    // ---- Run the 12-step initialization ----
    if (!flow::init::app_init(node, args)) {
        // Error messages have already been logged by app_init
        std::cerr << "Error: initialization failed. "
                  << "Check debug.log for details." << std::endl;
        g_node = nullptr;
        return EXIT_FAILURE;
    }

    // ---- Log startup info ----
    LogInfo("main", "FlowCoin daemon started successfully (pid=%d)",
                  flow::sys::get_pid());
    LogInfo("main", "Network: %s | P2P port: %u | RPC port: %u",
                  node.get_network_name(),
                  static_cast<unsigned>(node.config.get_int("port", node.get_port())),
                  static_cast<unsigned>(node.config.get_int("rpcport", node.get_rpc_port())));
    LogInfo("main", "Data directory: %s", node.datadir.c_str());

    // ---- Run the event loop ----
    // The RPC server runs on the main thread's libuv loop.
    // The P2P network runs on its own thread (started in step11).
    // We also run the P2P net loop in a separate thread.
    std::thread net_thread;
    if (node.net) {
        net_thread = std::thread([&node]() {
            node.net->run();
        });
    }

    // Run the main libuv event loop (blocks until uv_stop is called)
    if (node.loop) {
        LogInfo("main", "Entering main event loop");
        uv_run(node.loop, UV_RUN_DEFAULT);
    } else {
        // No libuv loop (RPC disabled) — wait for shutdown signal
        LogInfo("main", "Waiting for shutdown signal (no RPC server)");
        flow::get_shutdown_state().wait_for_shutdown();
    }

    // ---- Graceful shutdown ----
    LogInfo("main", "Main loop exited, beginning shutdown...");

    // Stop the network thread
    if (node.net) {
        node.net->stop();
    }
    if (net_thread.joinable()) {
        net_thread.join();
    }

    // Run full shutdown sequence
    flow::init::app_shutdown(node);

    LogInfo("main", "Shutdown complete. Goodbye.");

    g_node = nullptr;
    return EXIT_SUCCESS;
}

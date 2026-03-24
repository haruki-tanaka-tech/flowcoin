// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// flowcoind: Main daemon entry point for the FlowCoin full node.
// Parses arguments, initializes all subsystems, installs signal handlers,
// and runs the event loop until shutdown.

#include "init.h"
#include "logging.h"
#include "version.h"

#include <csignal>
#include <cstdlib>
#include <iostream>

static flow::Node* g_node = nullptr;

static void signal_handler(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
        std::cerr << "\nReceived signal " << signum << ", shutting down...\n";
        if (g_node) {
            g_node->shutdown();
        }
    }
}

int main(int argc, char* argv[]) {
    std::cout << CLIENT_NAME << " v" << CLIENT_VERSION_STRING << std::endl;

    // Parse command-line arguments
    flow::NodeConfig config = flow::parse_args(argc, argv);

    // Create the node
    flow::Node node(config);
    g_node = &node;

    // Install signal handlers for graceful shutdown
    struct sigaction sa;
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);

    // Ignore SIGPIPE (broken pipe from network writes)
    signal(SIGPIPE, SIG_IGN);

    // Initialize all subsystems
    if (!node.init()) {
        std::cerr << "Initialization failed. Check debug.log for details." << std::endl;
        return EXIT_FAILURE;
    }

    // Run the node (blocks until shutdown)
    node.run();

    g_node = nullptr;
    return EXIT_SUCCESS;
}

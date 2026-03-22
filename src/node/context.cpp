// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license

#include "context.h"
#include "consensus/difficulty.h"
#include "consensus/growth.h"
#include "consensus/reward.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "crypto/keys.h"
#include "crypto/sign.h"
#include "core/hash.h"
#include "core/serialize.h"
#include "net/protocol.h"

#include <fstream>
#include <sys/random.h>

#include <spdlog/spdlog.h>

namespace flow {

// Genesis coinbase message (like Bitcoin's "Chancellor on brink of second bailout for banks")
static const char* GENESIS_COINBASE_MSG =
    "White House calls for federal AI law to preempt states "
    "21/Mar/2026 - FlowCoin: AI that no government controls.";

static CBlock create_genesis_block(const consensus::ChainParams& params) {
    // Genesis key: deterministic from fixed seed. Publicly known.
    static const uint8_t genesis_seed[] = "flowcoin genesis key v0.1";
    Hash256 seed_hash = keccak256(genesis_seed, sizeof(genesis_seed) - 1);
    PrivKey genesis_privkey(seed_hash.bytes());
    PubKey genesis_pubkey = crypto::derive_pubkey(genesis_privkey);

    Hash256 pk_hash = keccak256d(genesis_pubkey.bytes(), 32);
    Blob<20> genesis_pkh;
    std::memcpy(genesis_pkh.bytes(), pk_hash.bytes(), 20);

    CBlock genesis;
    auto& h = genesis.header;
    h.prev_hash = Hash256::ZERO;
    h.height = 0;
    h.timestamp = consensus::GENESIS_TIMESTAMP;  // 21 Mar 2026 00:00:00 UTC
    h.val_loss = consensus::GENESIS_VAL_LOSS;
    h.prev_val_loss = consensus::GENESIS_VAL_LOSS;
    h.nbits = params.initial_nbits;
    h.d_model = consensus::GENESIS_D_MODEL;
    h.n_layers = consensus::GENESIS_N_LAYERS;
    h.d_ff = consensus::GENESIS_D_FF;
    h.n_experts = consensus::GENESIS_N_EXPERTS;
    h.n_heads = consensus::GENESIS_N_HEADS;
    h.rank = consensus::GENESIS_RANK;

    // Coinbase with genesis message
    CTransaction coinbase_tx;
    coinbase_tx.version = CTransaction::CURRENT_VERSION;

    CTxIn coinbase_in;
    coinbase_in.prevout.txid.set_zero();
    coinbase_in.prevout.vout = 0xFFFFFFFF;
    // Encode genesis message in the signature field of coinbase input
    const auto* msg = reinterpret_cast<const uint8_t*>(GENESIS_COINBASE_MSG);
    size_t msg_len = std::min(strlen(GENESIS_COINBASE_MSG), size_t(64));
    std::memcpy(coinbase_in.sig.bytes(), msg, msg_len);
    coinbase_tx.vin.push_back(coinbase_in);

    CTxOut coinbase_out;
    coinbase_out.amount = consensus::get_block_subsidy(0);
    coinbase_out.pubkey_hash = genesis_pkh;
    coinbase_tx.vout.push_back(coinbase_out);

    genesis.vtx.push_back(coinbase_tx);
    h.merkle_root = genesis.compute_merkle_root();

    // Sign genesis block
    h.miner_pubkey = genesis_pubkey;
    auto ub = h.unsigned_bytes();
    h.miner_sig = crypto::sign(genesis_privkey, genesis_pubkey, ub.data(), ub.size());

    return genesis;
}

void NodeContext::init(const std::string& data_dir,
                        consensus::Network network,
                        const std::string& wallet_seed) {
    params = &consensus::ChainParams::get(network);

    spdlog::info("Network: {} (magic=0x{:08x}, P2P:{}, RPC:{})",
        params->name, params->magic, params->p2p_port, params->rpc_port);

    chain = std::make_unique<ChainState>(data_dir);
    mempool = std::make_unique<Mempool>();
    rpc_server = std::make_unique<rpc::RpcServer>();

    auto genesis = create_genesis_block(*params);
    chain->init_genesis(genesis);

    // Verify genesis block hash matches hardcoded value
    Hash256 actual_genesis = genesis.get_hash();
    if (!params->genesis_hash.empty()) {
        Hash256 expected = Hash256::from_hex(params->genesis_hash);
        if (actual_genesis != expected) {
            spdlog::error("Genesis hash mismatch!");
            spdlog::error("  Expected: {}", expected.to_hex());
            spdlog::error("  Got:      {}", actual_genesis.to_hex());
            throw std::runtime_error("genesis hash mismatch — corrupted binary");
        }
    }
    spdlog::info("Genesis: {} (verified)", actual_genesis.to_hex().substr(0, 16));

    rpc::register_blockchain_rpcs(*rpc_server, *chain);
    rpc::register_mempool_rpcs(*rpc_server, *mempool);

    // Wallet: auto-create on first run, load existing on restart
    {
        std::string wallet_path = data_dir + "/wallet.dat";
        std::string seed = wallet_seed;

        if (seed.empty()) {
            std::string seed_file = data_dir + "/wallet_seed";
            std::ifstream sf(seed_file);
            if (sf) {
                // Load existing seed
                std::getline(sf, seed);
            } else {
                // First run: generate new seed from system random
                uint8_t seed_bytes[32];
                getrandom(seed_bytes, 32, 0);
                for (int i = 0; i < 32; ++i) {
                    char hex[3];
                    snprintf(hex, sizeof(hex), "%02x", seed_bytes[i]);
                    seed += hex;
                }
                // Save seed to file
                std::ofstream of(seed_file);
                of << seed;
                spdlog::info("New wallet created: {}", wallet_path);
            }
        }

        wallet = std::make_unique<Wallet>(wallet_path, seed);
        rpc::register_wallet_rpcs(*rpc_server, *wallet, *chain);
    }

    // Network info RPCs
    rpc_server->register_method("getnetworkinfo", [this](const rpc::json&) -> rpc::json {
        return rpc::json{
            {"network", params->name},
            {"protocol_version", consensus::PROTOCOL_VERSION},
            {"p2p_port", params->p2p_port},
            {"rpc_port", params->rpc_port},
            {"connections", net_manager ? static_cast<int64_t>(net_manager->peer_count()) : 0},
        };
    });

    rpc_server->register_method("getpeerinfo", [this](const rpc::json&) -> rpc::json {
        if (!net_manager) return rpc::json::array();
        auto peers = net_manager->get_peer_info();
        rpc::json result = rpc::json::array();
        for (const auto& p : peers) {
            result.push_back(rpc::json{
                {"id", p.id},
                {"addr", p.address + ":" + std::to_string(p.port)},
                {"inbound", p.inbound},
                {"height", p.best_height},
                {"version", p.protocol_version},
            });
        }
        return result;
    });

    rpc_server->register_method("getconnectioncount", [this](const rpc::json&) -> rpc::json {
        return net_manager ? static_cast<int64_t>(net_manager->peer_count()) : 0;
    });

    rpc_server->register_method("addnode", [this](const rpc::json& p) -> rpc::json {
        if (!net_manager || p.empty() || !p[0].is_string()) {
            throw std::runtime_error("addnode requires ip:port");
        }
        std::string addr = p[0];
        auto colon = addr.find(':');
        std::string host = (colon != std::string::npos) ? addr.substr(0, colon) : addr;
        uint16_t port = (colon != std::string::npos)
            ? static_cast<uint16_t>(std::stoi(addr.substr(colon + 1)))
            : params->p2p_port;
        net_manager->connect_to(host, port);
        return nullptr;
    });

    // Mining RPCs
    rpc_server->register_method("getblocktemplate", [this](const rpc::json&) -> rpc::json {
        auto tip = chain->tip();
        if (!tip) return rpc::json{{"error", "no chain"}};

        auto dims = consensus::compute_growth(tip->height + 1, tip->improving_blocks);

        return rpc::json{
            {"height", tip->height + 1},
            {"prev_hash", tip->hash.to_hex()},
            {"prev_val_loss", tip->val_loss},
            {"nbits", tip->nbits},
            {"timestamp_min", tip->timestamp + consensus::MIN_BLOCK_INTERVAL},
            {"d_model", dims.d_model},
            {"n_layers", dims.n_layers},
            {"d_ff", dims.d_ff},
            {"n_experts", dims.n_experts},
            {"n_heads", dims.n_heads},
            {"rank", dims.rank},
            {"reward", consensus::get_block_subsidy(tip->height + 1).value},
        };
    });

    rpc_server->register_method("submitblock", [this](const rpc::json& p) -> rpc::json {
        if (p.empty()) {
            throw std::runtime_error("submitblock requires block data");
        }
        if (!wallet) {
            throw std::runtime_error("no wallet loaded");
        }

        auto& b = p[0];
        CBlock block;
        auto& h = block.header;

        h.prev_hash = Hash256::from_hex(b.value("prev_hash", std::string("")));
        h.height = b.value("height", uint64_t(0));
        h.timestamp = b.value("timestamp", int64_t(0));
        h.val_loss = b.value("val_loss", 0.0f);
        h.prev_val_loss = b.value("prev_val_loss", 0.0f);
        h.nbits = b.value("nbits", uint32_t(0));
        h.train_steps = b.value("train_steps", uint32_t(0));
        h.dataset_hash = Hash256::from_hex(b.value("dataset_hash", std::string("")));
        h.delta_hash = Hash256::from_hex(b.value("delta_hash", std::string("")));
        h.d_model = b.value("d_model", uint32_t(0));
        h.n_layers = b.value("n_layers", uint32_t(0));
        h.d_ff = b.value("d_ff", uint32_t(0));
        h.n_experts = b.value("n_experts", uint32_t(0));
        h.n_heads = b.value("n_heads", uint32_t(0));
        h.rank = b.value("rank", uint32_t(0));
        h.stagnation_count = b.value("stagnation_count", uint32_t(0));

        // Quick check: does training_hash meet difficulty target?
        // H = Keccak256(delta_hash || dataset_hash)
        Keccak256Hasher hasher;
        hasher.update(h.delta_hash.bytes(), 32);
        hasher.update(h.dataset_hash.bytes(), 32);
        Hash256 training_hash = hasher.finalize();

        if (!consensus::meets_target(training_hash, h.nbits)) {
            return rpc::json{{"accepted", false}, {"reason", "high-hash"}};
        }

        // Pre-check timestamp before generating address
        auto* parent = chain->block_tree().find(h.prev_hash);
        if (parent) {
            if (h.timestamp <= parent->timestamp) {
                return rpc::json{{"accepted", false}, {"reason", "time-too-old"}};
            }
            if (h.timestamp < parent->timestamp + consensus::MIN_BLOCK_INTERVAL) {
                return rpc::json{{"accepted", false}, {"reason", "time-too-soon"}};
            }
        }

        // All pre-checks passed — generate fresh address and sign
        std::string addr = wallet->get_mining_address();
        auto keys = wallet->get_all_keys();
        const WalletKey* miner_key = nullptr;
        for (const auto& wk : keys) {
            if (wk.address == addr) { miner_key = &wk; break; }
        }
        if (!miner_key) {
            throw std::runtime_error("failed to get mining key");
        }

        h.miner_pubkey = miner_key->keypair.pubkey;

        auto reward = consensus::get_block_subsidy(h.height);
        block.vtx.push_back(make_coinbase(reward, miner_key->pubkey_hash, h.height));
        h.merkle_root = block.compute_merkle_root();

        // Sign
        auto ub = h.unsigned_bytes();
        h.miner_sig = crypto::sign(miner_key->keypair.privkey, miner_key->keypair.pubkey,
                                    ub.data(), ub.size());

        // Accept block
        auto state = chain->accept_block(block);
        if (!state.valid) {
            return rpc::json{{"accepted", false}, {"reason", state.reject_reason}};
        }

        spdlog::info("Block {} accepted via submitblock, hash={}",
            h.height, block.get_hash().to_hex().substr(0, 16));

        // Broadcast to peers
        if (net_manager && net_manager->peer_count() > 0) {
            VectorWriter inv_msg;
            inv_msg.write_compact_size(1);
            inv_msg.write_u32(static_cast<uint32_t>(net::InvType::BLOCK));
            auto hash = block.get_hash();
            inv_msg.write_bytes(std::span<const uint8_t>(hash.bytes(), 32));
            net_manager->broadcast(net::cmd::INV, inv_msg.release());
        }

        return rpc::json{
            {"accepted", true},
            {"hash", block.get_hash().to_hex()},
            {"height", h.height},
        };
    });
}

void NodeContext::start_rpc(const std::string& bind_addr, uint16_t port) {
    uint16_t rpc_port = (port != 0) ? port : params->rpc_port;
    http_server = std::make_unique<rpc::HttpServer>(*rpc_server, bind_addr, rpc_port);
    http_server->start();
}

void NodeContext::start_p2p(const net::NetConfig& config) {
    net::NetConfig cfg = config;
    if (cfg.port == consensus::MAINNET_PORT && params->network != consensus::Network::MAINNET) {
        cfg.port = params->p2p_port;
    }

    // DNS seeds first, IP fallbacks added separately after connection attempt
    if (cfg.seed_nodes.empty()) {
        cfg.seed_nodes = params->seed_nodes;
        // Append fallback IPs — NetManager deduplicates resolved addresses
        for (const auto& fb : params->fallback_nodes) {
            cfg.seed_nodes.push_back(fb);
        }
    }

    net_manager = std::make_unique<net::NetManager>(cfg);
    msg_handler = std::make_unique<net::MessageHandler>(*net_manager, *chain, *mempool);

    net_manager->set_on_message([this](uint64_t peer_id, const std::string& cmd,
                                       const std::vector<uint8_t>& payload) {
        msg_handler->handle(peer_id, cmd, payload);
    });

    net_manager->set_on_peer_event([this](uint64_t peer_id, bool connected) {
        if (connected) msg_handler->on_peer_connected(peer_id);
        else msg_handler->on_peer_disconnected(peer_id);
    });

    net_manager->start();
}

void NodeContext::shutdown() {
    if (net_manager) { net_manager->stop(); net_manager.reset(); }
    msg_handler.reset();
    if (http_server) { http_server->stop(); http_server.reset(); }
    rpc_server.reset();
    wallet.reset();
    mempool.reset();
    chain.reset();
}

} // namespace flow

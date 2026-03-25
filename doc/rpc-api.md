# FlowCoin RPC API Reference

FlowCoin exposes a JSON-RPC 2.0 interface over HTTP. All requests require
HTTP Basic authentication using the `rpcuser` and `rpcpassword` configured
in `flowcoin.conf` or passed via command-line flags.

**Default endpoint:** `http://127.0.0.1:9334`
(testnet: 19334, regtest: 29334)

## Request Format

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "getblockcount",
  "params": []
}
```

## Response Format

Success:
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": 12345
}
```

Error:
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": -1,
    "message": "Error description"
  }
}
```

## Using curl

```bash
curl -u user:pass -X POST http://127.0.0.1:9334 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"METHOD","params":[ARGS]}'
```

## Using flowcoin-cli

```bash
flowcoin-cli --rpcuser=user --rpcpassword=pass METHOD [ARGS...]
```

---

## Blockchain Methods

### getblockcount

Returns the height of the most-work fully-validated chain.

**Parameters:** none

**Returns:** `integer` -- current block height

**Example:**
```bash
flowcoin-cli getblockcount
# 1250
```

### getbestblockhash

Returns the hash of the current best (tip) block.

**Parameters:** none

**Returns:** `string` -- hex-encoded 256-bit block hash

**Example:**
```bash
flowcoin-cli getbestblockhash
# "a3f1...7b2c"
```

### getblockhash

Returns the hash of the block at the given height.

**Parameters:**
| # | Name | Type | Description |
|---|---|---|---|
| 1 | height | integer | Block height |

**Returns:** `string` -- hex-encoded block hash

**Example:**
```bash
flowcoin-cli getblockhash 0
```

### getblock

Returns detailed information about a block.

**Parameters:**
| # | Name | Type | Description |
|---|---|---|---|
| 1 | blockhash | string | The block hash |
| 2 | verbosity | integer | 0=hex, 1=JSON (default), 2=JSON+tx |

**Returns:** block object with fields:
- `hash` -- block hash
- `height` -- block height
- `timestamp` -- Unix timestamp
- `nbits` -- compact difficulty target
- `val_loss` -- validation loss achieved
- `prev_val_loss` -- parent validation loss
- `d_model`, `n_layers`, `d_ff`, `n_heads`, `n_slots`, `gru_dim` -- model architecture

- `stagnation` -- consecutive non-improving blocks
- `merkle_root` -- transaction merkle root
- `miner_pubkey` -- miner's Ed25519 public key
- `n_tx` -- transaction count
- `previousblockhash` -- parent block hash
- `tx` -- transaction array (verbosity >= 2)

### getblockheader

Returns the header of a block.

**Parameters:**
| # | Name | Type | Description |
|---|---|---|---|
| 1 | blockhash | string | The block hash |

**Returns:** header JSON object (same fields as getblock without transactions)

### getblockchaininfo

Returns an object containing various state info about blockchain processing.

**Parameters:** none

**Returns:**
- `chain` -- "main", "test", or "regtest"
- `blocks` -- current height
- `bestblockhash` -- tip hash
- `difficulty` -- current difficulty
- `initialblockdownload` -- true if in IBD mode

### gettxout

Returns details about an unspent transaction output.

**Parameters:**
| # | Name | Type | Description |
|---|---|---|---|
| 1 | txid | string | Transaction ID |
| 2 | vout | integer | Output index |

**Returns:**
- `value` -- output value in FLOW
- `pubkey_hash` -- recipient hash
- `height` -- block height where created
- `coinbase` -- true if from coinbase
- `confirmations` -- number of confirmations

Returns null if the output has been spent or does not exist.

### gettxoutsetinfo

Returns statistics about the unspent transaction output set.

**Parameters:** none

**Returns:**
- `height` -- chain height
- `total_amount` -- total value of all UTXOs
- `txouts` -- number of unspent outputs

### verifychain

Verifies the blockchain database.

**Parameters:**
| # | Name | Type | Description |
|---|---|---|---|
| 1 | checklevel | integer | Verification depth (0-4, default 3) |
| 2 | nblocks | integer | Number of blocks to check (0=all) |

**Returns:** `boolean` -- true if verification passed

### getdifficulty

Returns the proof-of-training difficulty as a multiple of the minimum difficulty.

**Parameters:** none

**Returns:** `number` -- current difficulty (1.0 = minimum)

### getchaintips

Returns information about all known chain tips.

**Parameters:** none

**Returns:** array of tip objects with `height`, `hash`, `status`

### getblockstats

Returns per-block statistics for a given height.

**Parameters:**
| # | Name | Type | Description |
|---|---|---|---|
| 1 | height | integer | Block height |

**Returns:** statistics object with block metrics

### getchainwork

Returns the total cumulative proof-of-training work.

**Parameters:** none

**Returns:** hex-encoded 256-bit chainwork value

---

## Wallet Methods

### getnewaddress

Generates a new bech32m receiving address from the HD keychain.

**Parameters:** none

**Returns:** `string` -- bech32m address (prefix: `fl1` mainnet, `tfl1` testnet)

**Example:**
```bash
flowcoin-cli getnewaddress
# "fl1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"
```

### getbalance

Returns the total confirmed wallet balance.

**Parameters:** none

**Returns:** `number` -- balance in FLOW

### listunspent

Returns array of unspent transaction outputs owned by the wallet.

**Parameters:** none

**Returns:** array of UTXO objects:
- `txid` -- transaction ID
- `vout` -- output index
- `amount` -- value in FLOW
- `pubkey` -- owning public key
- `height` -- creation height
- `coinbase` -- true if from coinbase
- `confirmations` -- number of confirmations
- `spendable` -- true if mature and unlocked

### sendtoaddress

Send FLOW to a given address.

**Parameters:**
| # | Name | Type | Description |
|---|---|---|---|
| 1 | address | string | Recipient bech32m address |
| 2 | amount | number | Amount in FLOW |

**Returns:** `string` -- transaction ID of the sent transaction

**Example:**
```bash
flowcoin-cli sendtoaddress "fl1q..." 10.5
```

### listtransactions

Returns recent wallet transactions.

**Parameters:**
| # | Name | Type | Description |
|---|---|---|---|
| 1 | count | integer | Number of transactions (default 10) |
| 2 | skip | integer | Number to skip (default 0) |

**Returns:** array of transaction records

### validateaddress

Validates a FlowCoin address and returns information about it.

**Parameters:**
| # | Name | Type | Description |
|---|---|---|---|
| 1 | address | string | Address to validate |

**Returns:**
- `isvalid` -- boolean
- `ismine` -- true if the wallet owns this address
- `address` -- the validated address

### importprivkey

Imports a private key into the wallet.

**Parameters:**
| # | Name | Type | Description |
|---|---|---|---|
| 1 | privkey | string | Hex-encoded 32-byte Ed25519 private key seed |

**Returns:** `string` -- the corresponding address

### dumpprivkey

Reveals the private key corresponding to an address.

**Parameters:**
| # | Name | Type | Description |
|---|---|---|---|
| 1 | address | string | Address to dump |

**Returns:** `string` -- hex-encoded private key

### dumpwallet

Exports all wallet keys to a file.

**Parameters:**
| # | Name | Type | Description |
|---|---|---|---|
| 1 | filename | string | Output file path |

**Returns:** confirmation object

### importwallet

Imports keys from a previously exported wallet file.

**Parameters:**
| # | Name | Type | Description |
|---|---|---|---|
| 1 | filename | string | Input file path |

**Returns:** confirmation object

### backupwallet

Creates a backup copy of the wallet database.

**Parameters:**
| # | Name | Type | Description |
|---|---|---|---|
| 1 | destination | string | Backup file path |

**Returns:** `boolean` -- true on success

### encryptwallet

Encrypts the wallet with a passphrase.

**Parameters:**
| # | Name | Type | Description |
|---|---|---|---|
| 1 | passphrase | string | Encryption passphrase |

**Returns:** confirmation message

### walletpassphrase

Unlocks an encrypted wallet for a specified duration.

**Parameters:**
| # | Name | Type | Description |
|---|---|---|---|
| 1 | passphrase | string | Wallet passphrase |
| 2 | timeout | integer | Seconds to remain unlocked |

**Returns:** confirmation message

### walletlock

Locks the wallet immediately.

**Parameters:** none

**Returns:** confirmation message

### signmessage

Signs a message with the private key of an address.

**Parameters:**
| # | Name | Type | Description |
|---|---|---|---|
| 1 | address | string | Signing address |
| 2 | message | string | Message to sign |

**Returns:** `string` -- hex-encoded Ed25519 signature

### verifymessage

Verifies a signed message.

**Parameters:**
| # | Name | Type | Description |
|---|---|---|---|
| 1 | address | string | Claimed signing address |
| 2 | signature | string | Hex signature |
| 3 | message | string | Original message |

**Returns:** `boolean` -- true if signature is valid

### getaddressinfo

Returns detailed information about an address.

**Parameters:**
| # | Name | Type | Description |
|---|---|---|---|
| 1 | address | string | Address to query |

**Returns:** address details including key derivation path and labels

### listaddresses

Returns all addresses in the wallet.

**Parameters:** none

**Returns:** array of address strings

### getwalletinfo

Returns an object containing various wallet state info.

**Parameters:** none

**Returns:**
- `walletname` -- wallet identifier
- `balance` -- confirmed balance
- `txcount` -- total transaction count
- `keypoolsize` -- number of pre-generated keys
- `unlocked_until` -- unlock expiry time (0 if locked)

### keypoolrefill

Fills the keypool with pre-generated keys.

**Parameters:**
| # | Name | Type | Description |
|---|---|---|---|
| 1 | size | integer | Target keypool size (default 100) |

**Returns:** confirmation

### settxfee

Sets the transaction fee rate.

**Parameters:**
| # | Name | Type | Description |
|---|---|---|---|
| 1 | amount | number | Fee rate in FLOW per KB |

**Returns:** `boolean` -- true on success

### setlabel

Sets a label for an address.

**Parameters:**
| # | Name | Type | Description |
|---|---|---|---|
| 1 | address | string | Address |
| 2 | label | string | Label text |

**Returns:** confirmation

### listlabels

Returns all labels used in the wallet.

**Parameters:** none

**Returns:** array of label strings

---

## Mining Methods

### getblocktemplate

Returns a block template for mining.

**Parameters:**
| # | Name | Type | Description |
|---|---|---|---|
| 1 | coinbase_address | string | (optional) Address for coinbase reward |

**Returns:**
- `height` -- next block height
- `previousblockhash` -- parent hash
- `nbits` -- compact difficulty target
- `target` -- full 256-bit target (hex)
- `coinbase_value` -- block reward in atomic units
- (min_train_steps removed from consensus)
- `dims` -- model architecture dimensions:
  - `d_model`, `n_layers`, `d_ff`, `n_heads`, `gru_dim`, `n_slots`, `vocab`, `seq_len`
- `timestamp` -- suggested timestamp
- `stagnation` -- current stagnation count

### submitblock

Submits a completed block to the network.

**Parameters:**
| # | Name | Type | Description |
|---|---|---|---|
| 1 | hexdata | string | Hex-encoded serialized block |

**Returns:** null on success, or error string on rejection

Rejection reasons:
- `bad-prevblk` -- unknown parent block
- `bad-height` -- height mismatch
- `high-hash` -- hash does not meet target
- `bad-signature` -- invalid miner signature
- `bad-growth` -- model dimensions mismatch

### getmininginfo

Returns current mining-related information.

**Parameters:** none

**Returns:**
- `blocks` -- current height
- `difficulty` -- current difficulty
- `networkhashps` -- estimated network training rate
- `pooledtx` -- mempool transaction count

---

## Network Methods

### getpeerinfo

Returns data about each connected network node.

**Parameters:** none

**Returns:** array of peer objects:
- `addr` -- IP address and port
- `version` -- protocol version
- `subver` -- user agent string
- `inbound` -- true if inbound connection
- `startingheight` -- peer's chain height at connection time
- `synced_headers` -- last header height synced
- `synced_blocks` -- last block height synced
- `conntime` -- connection duration in seconds

### getconnectioncount

Returns the number of active connections.

**Parameters:** none

**Returns:** `integer` -- connection count

### addnode

Attempts to add or remove a peer.

**Parameters:**
| # | Name | Type | Description |
|---|---|---|---|
| 1 | node | string | IP:port of the peer |
| 2 | command | string | "add", "remove", or "onetry" |

**Returns:** confirmation message

**Example:**
```bash
flowcoin-cli addnode "192.168.1.100:9333" "add"
```

### getnetworkinfo

Returns information about the P2P networking state.

**Parameters:** none

**Returns:**
- `version` -- protocol version
- `connections` -- active connection count
- `connections_in` -- inbound connections
- `connections_out` -- outbound connections
- `networkactive` -- true if networking is enabled

---

## Training Methods

### gettraininginfo

Returns information about the current model training state.

**Parameters:** none

**Returns:**
- `height` -- current chain height
- `val_loss` -- current validation loss
- `prev_val_loss` -- previous validation loss
- `d_model`, `n_layers`, `d_ff`, `n_heads`, `n_slots`, `gru_dim` -- model dims
- (train_steps removed from consensus)
- `stagnation` -- consecutive non-improving blocks
- `phase` -- growth phase description
- `param_count` -- estimated total model parameters

### getmodelweights

Returns the model checkpoint data for a given block.

**Parameters:**
| # | Name | Type | Description |
|---|---|---|---|
| 1 | blockhash | string | (optional) Block hash (default: tip) |

**Returns:** model checkpoint metadata

### getmodelhash

Returns the hash of the current consensus model state.

**Parameters:**
| # | Name | Type | Description |
|---|---|---|---|
| 1 | blockhash | string | (optional) Block hash (default: tip) |

**Returns:** `string` -- hex-encoded model state hash

### getdeltapayload

Returns the compressed delta payload for a block.

**Parameters:**
| # | Name | Type | Description |
|---|---|---|---|
| 1 | blockhash | string | Block hash |

**Returns:** hex-encoded compressed delta bytes

### getgrowthschedule

Returns the complete model growth schedule.

**Parameters:** none

**Returns:** array of plateau descriptions with dimensions and height ranges

### getvalidationdata

Returns the evaluation dataset information used for validation.

**Parameters:** none

**Returns:** validation dataset metadata

---

## Utility Methods

### getinfo

Returns general information about the node.

**Parameters:** none

**Returns:**
- `version` -- software version string
- `blocks` -- current chain height
- `connections` -- active peer count
- `testnet` -- true if testnet
- `regtest` -- true if regtest
- `balance` -- wallet balance

### help

Lists all available RPC methods.

**Parameters:** none

**Returns:** array of method names with brief parameter descriptions

### stop

Gracefully shuts down the node.

**Parameters:** none

**Returns:** "FlowCoin server stopping"

### uptime

Returns the node uptime in seconds.

**Parameters:** none

**Returns:** `integer` -- uptime in seconds

### echo

Echoes back the provided parameters. Useful for testing connectivity.

**Parameters:** any JSON value

**Returns:** the same JSON value

### getmemoryinfo

Returns memory usage statistics.

**Parameters:** none

**Returns:** memory usage breakdown by subsystem

### logging

Gets or sets log categories.

**Parameters:**
| # | Name | Type | Description |
|---|---|---|---|
| 1 | include | array | Categories to enable |
| 2 | exclude | array | Categories to disable |

**Returns:** current logging configuration

---

## Raw Transaction Methods

### getrawtransaction

Returns raw transaction data.

**Parameters:**
| # | Name | Type | Description |
|---|---|---|---|
| 1 | txid | string | Transaction ID |
| 2 | verbose | boolean | true for JSON, false for hex |

**Returns:** hex string or decoded transaction object

### createrawtransaction

Creates an unsigned raw transaction.

**Parameters:**
| # | Name | Type | Description |
|---|---|---|---|
| 1 | inputs | array | Array of `{"txid":"hex","vout":n}` |
| 2 | outputs | object | `{"address": amount, ...}` |

**Returns:** `string` -- hex-encoded unsigned transaction

### decoderawtransaction

Decodes a hex-encoded transaction.

**Parameters:**
| # | Name | Type | Description |
|---|---|---|---|
| 1 | hexstring | string | Hex-encoded transaction |

**Returns:** decoded transaction object

### sendrawtransaction

Submits a signed raw transaction to the network.

**Parameters:**
| # | Name | Type | Description |
|---|---|---|---|
| 1 | hexstring | string | Hex-encoded signed transaction |

**Returns:** `string` -- transaction ID

---

## Error Codes

| Code | Description |
|---|---|
| -1 | General error |
| -2 | Method not found |
| -3 | Invalid parameters |
| -5 | Invalid address |
| -6 | Insufficient funds |
| -8 | Invalid parameter type |
| -13 | Wallet is locked |
| -25 | Transaction rejected |
| -26 | Transaction already in chain |
| -28 | Initial block download in progress |

<h1 align="center">Toolbox For Poly</h1>

## Introduction

Toolbox is a helper for governance of poly network. To Poly consensus node, you can finish management work by toolbox. Like making a proposal to register a new consensus node for next round consensus, etc.

## Build From Source

### Prerequisites

- [Golang](https://golang.org/doc/install) version 1.14 or later

### Build

```shell
git clone https://github.com/zouxyan/poly_toolbox.git
cd poly_toolbox
go build -o toolbox cmd/run.go
```

After building the source code successfully,  you should see the executable program `toolbox`. 

You can see some guide information by running `toolbox -h`.

## Usage

### Register Relayer

If you want to send transaciton to Poly, you need to be a relayer account first. Do as follow:

```
./toolbox poly relayer_manager register_relayer [address_to_register] --rpc_addr="http://poly_rpc:port" --signer_wallet_path=/path/to/wallet.dat
```

The `signer` must be a relayer. You will  find the ID of this registration proposal in the result. Remember it will be useful during `approve` part.

You can set password by flag `--signer_wallet_pwd`. But we suggest you **not using** it. And toolbox will require you to input password when running.

### Approve Relayer Registration

Consensus account can approve registration of relayer with the registration **ID**. 

```
./toolbox poly relayer_manager approve_register_relayer [ID] --rpc_addr="http://poly_rpc:port" --signer_wallet_path=/path/to/wallet.dat
```

You can find the transaction hash in result.

### Register Side Chain

Register a side chain to Poly cross-chain system.

```
./toolbox poly side_chain_manager register_side_chain --chain_id=[number] --router=[number] --name=[name] --blocks_to_wait=1 --CMCC="hex" --rpc_addr="http://poly_rpc:port" --signer_wallet_path=/path/to/wallet.dat
```

### Approve Side Chain Registration 

Consensus account can approve registration of a side chain with the chain-id.

```
./toolbox poly side_chain_manager approve_register_side_chain --chain_id=[number] --rpc_addr="http://poly_rpc:port" --signer_wallet_path=/path/to/wallet.dat 
```

### Create Transaction To Sync Ontology Genesis Header

Create a raw transaction to sync Ontology genesis header to Poly. Noted, you must set all public keys of multisig address.

```
./toolbox poly header_sync create_sync_ont_genesis_hdr_tx [chain-id] [height] --consensus_public_keys=pub1,pub2,pub3 --ont_rpc="http://ontology:20336" --rpc_addr="http://poly_rpc_addr" --signer_wallet_path=/path/to/wallet.dat
```

### Sign Multisig Transacion of Poly

Using your wallet to sign a raw multisig-transaction. Return with the raw transacion signed by your account. Pass the raw transaction to next one of the multisig-address. 

```
./toolbox poly header_sync sign_poly_multisig_tx [raw_tx] --rpc_addr="http://poly_rpc_addr" --signer_wallet_path=/path/to/wallet.dat
```


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
./toolbox poly relayer_manager register_relayer [address_to_register] --rpc_addr="http://poly_rpc:port" --signer_wallet_path=/path/to/wallet.dat --signer_wallet_pwd=pwd
```

The `signer` must be a relayer. You will  find the ID of this registration proposal in the result. Remember it will be useful during `approve` part.

### Approve Relayer Registration

Consensus account can approve registration of relayer with the registration **ID**. 

```
./toolbox poly relayer_manager approve_register_relayer [ID] --rpc_addr="http://poly_rpc:port" --signer_wallet_path=/path/to/wallet.dat --signer_wallet_pwd=pwd
```

You can find the transaction hash in result.

### Register Side Chain

Register a side chain to Poly cross-chain system.

```
./toolbox poly side_chain_manager register_side_chain --chain_id=[number] --router=[number] --name=[name] --blocks_to_wait=1 --CMCC="hex" --rpc_addr="http://poly_rpc:port" --signer_wallet_path=/path/to/wallet.dat --signer_wallet_pwd=pwd
```

### Approve Side Chain Registration 

Consensus account can approve registration of a side chain with the chain-id.

```
poly side_chain_manager approve_register_side_chain --chain_id=[number] --rpc_addr="http://poly_rpc:port" --signer_wallet_path=/path/to/wallet.dat --signer_wallet_pwd=pwd
```

 


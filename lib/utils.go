/*
* Copyright (C) 2020 The poly network Authors
* This file is part of The poly network library.
*
* The poly network is free software: you can redistribute it and/or modify
* it under the terms of the GNU Lesser General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* The poly network is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Lesser General Public License for more details.
* You should have received a copy of the GNU Lesser General Public License
* along with The poly network . If not, see <http://www.gnu.org/licenses/>.
*/
package lib

import (
	"fmt"
	"github.com/polynetwork/poly-go-sdk"
	"github.com/polynetwork/poly/common"
	"github.com/polynetwork/poly/common/password"
	"github.com/spf13/cobra"
	"time"
)

const (
	SignerWalletPath = "signer_wallet_path"
	SignerWalletPwd  = "signer_wallet_pwd"
	PolyRpcAddr      = "rpc_addr"
	ConsensusPubKeys = "consensus_public_keys"
	ChainId          = "chain_id"
	Router           = "router"
	Name             = "name"
	BlkToWait        = "blocks_to_wait"
	CMCC             = "CMCC"
)

func GetPolyAccountByPassword(asdk *poly_go_sdk.PolySdk, path, pwdStr string) (*poly_go_sdk.Account, error) {
	wallet, err := asdk.OpenWallet(path)
	if err != nil {
		return nil, fmt.Errorf("open wallet error:", err)
	}
	var pwd []byte
	if pwdStr != "" {
		pwd = []byte(pwdStr)
	} else {
		fmt.Println("Pleasae input your poly wallet password...")
		pwd, err = password.GetPassword()
		if err != nil {
			return nil, fmt.Errorf("getPassword error:", err)
		}
	}
	user, err := wallet.GetDefaultAccount(pwd)
	if err != nil {
		return nil, fmt.Errorf("getDefaultAccount error:", err)
	}
	return user, nil
}

func setUpPoly(poly *poly_go_sdk.PolySdk, rpc string) error {
	poly.NewRpcClient().SetAddress(rpc)
	hdr, err := poly.GetHeaderByHeight(0)
	if err != nil {
		return err
	}
	poly.SetChainId(hdr.ChainID)
	return nil
}

func WaitPolyTx(txhash common.Uint256, poly *poly_go_sdk.PolySdk) {
	fmt.Printf("waiting poly transaction %s confirmed...\n", txhash.ToHexString())
	tick := time.NewTicker(100 * time.Millisecond)
	var h uint32
	startTime := time.Now()
	for range tick.C {
		h, _ = poly.GetBlockHeightByTxHash(txhash.ToHexString())
		curr, _ := poly.GetCurrentBlockHeight()
		if h > 0 && curr > h {
			break
		}

		if startTime.Add(100 * time.Millisecond); startTime.Second() > 300 {
			panic(fmt.Errorf("tx( %s ) is not confirm for a long time ( over %d sec )",
				txhash.ToHexString(), 300))
		}
	}
}

func GetPolyAndAccByCmd(cmd *cobra.Command) (*poly_go_sdk.PolySdk, *poly_go_sdk.Account, error) {
	poly := poly_go_sdk.NewPolySdk()
	rpcAddr, err := cmd.Flags().GetString(PolyRpcAddr)
	if err != nil {
		return nil, nil, err
	}
	wallet, err := cmd.Flags().GetString(SignerWalletPath)
	if err := setUpPoly(poly, rpcAddr); err != nil {
		return nil, nil, err
	}
	pwd, err := cmd.Flags().GetString(SignerWalletPwd)
	if err != nil {
		return nil, nil, err
	}
	acc, err := GetPolyAccountByPassword(poly, wallet, pwd)
	if err != nil {
		return nil, nil, err
	}
	return poly, acc, nil
}

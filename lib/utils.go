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
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/cosmos/cosmos-sdk/codec"
	types3 "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/x/auth"
	"github.com/cosmos/cosmos-sdk/x/bank"
	"github.com/cosmos/cosmos-sdk/x/staking"
	common2 "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/polynetwork/cosmos-poly-module/btcx"
	"github.com/polynetwork/cosmos-poly-module/ccm"
	"github.com/polynetwork/cosmos-poly-module/ft"
	"github.com/polynetwork/cosmos-poly-module/headersync"
	"github.com/polynetwork/cosmos-poly-module/lockproxy"
	"github.com/polynetwork/poly-go-sdk"
	"github.com/polynetwork/poly/common"
	"github.com/polynetwork/poly/common/password"
	"github.com/spf13/cobra"
	"github.com/tendermint/tendermint/rpc/client"
	types2 "github.com/tendermint/tendermint/types"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
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
	OntRpcAddr       = "ont_rpc"
	EthRpcAddr       = "eth_rpc"
	SwitcheoRpcAddr  = "switcheo_rpc"
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

type ETHTools struct {
	restclient *RestClient
	ethclient  *ethclient.Client
}

type LockEvent struct {
	Method   string
	TxHash   string
	Txid     []byte
	Saddress string
	Tchain   uint32
	Taddress string
	Height   uint64
	Value    []byte
}
type UnlockEvent struct {
	Method   string
	Txid     string
	RTxid    string
	FromTxId string
	Height   uint64
	Token    string
}

type heightReq struct {
	JsonRpc string   `json:"jsonrpc"`
	Method  string   `json:"method"`
	Params  []string `json:"params"`
	Id      uint     `json:"id"`
}

type heightRep struct {
	JsonRpc string `json:"jsonrpc"`
	Result  string `json:"result"`
	Id      uint   `json:"id"`
}

type BlockReq struct {
	JsonRpc string        `json:"jsonrpc"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
	Id      uint          `json:"id"`
}

type BlockRep struct {
	JsonRPC string        `json:"jsonrpc"`
	Result  *types.Header `json:"result"`
	Id      uint          `json:"id"`
}

func NewEthTools(url string) *ETHTools {
	ethclient, err := ethclient.Dial(url)
	if err != nil {
		return nil
	}
	restclient := NewRestClient()
	restclient.SetAddr(url)
	tool := &ETHTools{
		restclient: restclient,
		ethclient:  ethclient,
	}
	return tool
}

func (self *ETHTools) GetEthClient() *ethclient.Client {
	return self.ethclient
}

func (self *ETHTools) GetNodeHeight() (uint64, error) {
	req := &heightReq{
		JsonRpc: "2.0",
		Method:  "eth_blockNumber",
		Params:  make([]string, 0),
		Id:      1,
	}
	data, err := json.Marshal(req)
	if err != nil {
		return 0, fmt.Errorf("GetNodeHeight: marshal req err: %s", err)
	}
	resp, err := self.restclient.SendRestRequest(data)
	if err != nil {
		return 0, fmt.Errorf("GetNodeHeight err: %s", err)
	}
	rep := &heightRep{}
	err = json.Unmarshal(resp, rep)
	if err != nil {
		return 0, fmt.Errorf("GetNodeHeight, unmarshal resp err: %s", err)
	}
	height, err := strconv.ParseUint(rep.Result, 0, 64)
	if err != nil {
		return 0, fmt.Errorf("GetNodeHeight, parse resp height %s failed", rep.Result)
	} else {
		return height, nil
	}
}

func (self *ETHTools) GetBlockHeader(height uint64) (*types.Header, error) {
	params := []interface{}{fmt.Sprintf("0x%x", height), true}
	req := &BlockReq{
		JsonRpc: "2.0",
		Method:  "eth_getBlockByNumber",
		Params:  params,
		Id:      1,
	}
	data, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("GetNodeHeight: marshal req err: %s", err)
	}
	resp, err := self.restclient.SendRestRequest(data)
	if err != nil {
		return nil, fmt.Errorf("GetNodeHeight err: %s", err)
	}
	rsp := &BlockRep{}
	err = json.Unmarshal(resp, rsp)
	if err != nil {
		return nil, fmt.Errorf("GetNodeHeight, unmarshal resp err: %s", err)
	}

	return rsp.Result, nil
}

func (self *ETHTools) WaitTransactionsConfirm(hashs []common2.Hash) {
	hasPending := true
	for hasPending {
		time.Sleep(time.Second * 1)
		hasPending = false
		for _, hash := range hashs {
			_, ispending, err := self.ethclient.TransactionByHash(context.Background(), hash)
			if err != nil {
				hasPending = true
				continue
			}
			if ispending == true {
				hasPending = true
			} else {
			}
		}
	}
}

func (self *ETHTools) WaitTransactionConfirm(hash common2.Hash) {
	for {
		time.Sleep(time.Second * 1)
		_, ispending, err := self.ethclient.TransactionByHash(context.Background(), hash)
		if err != nil {
			continue
		}
		if ispending == true {
			continue
		} else {
			break
		}
	}

}

type RestClient struct {
	addr       string
	restClient *http.Client
	user       string
	passwd     string
}

func NewRestClient() *RestClient {
	return &RestClient{
		restClient: &http.Client{
			Transport: &http.Transport{
				MaxIdleConnsPerHost:   5,
				DisableKeepAlives:     false,
				IdleConnTimeout:       time.Second * 300,
				ResponseHeaderTimeout: time.Second * 300,
				TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
			},
			Timeout: time.Second * 300,
		},
	}
}

func (self *RestClient) SetAddr(addr string) *RestClient {
	self.addr = addr
	return self
}

func (self *RestClient) SetAuth(user string, passwd string) *RestClient {
	self.user = user
	self.passwd = passwd
	return self
}

func (self *RestClient) SetRestClient(restClient *http.Client) *RestClient {
	self.restClient = restClient
	return self
}

func (self *RestClient) SendRestRequest(data []byte) ([]byte, error) {
	resp, err := self.restClient.Post(self.addr, "application/json", strings.NewReader(string(data)))
	if err != nil {
		return nil, fmt.Errorf("http post request:%s error:%s", data, err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read rest response body error:%s", err)
	}
	return body, nil
}

func (self *RestClient) SendRestRequestWithAuth(data []byte) ([]byte, error) {
	url := self.addr
	bodyReader := bytes.NewReader(data)
	httpReq, err := http.NewRequest("POST", url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("SendRestRequestWithAuth - build http request error:%s", err)
	}
	httpReq.Close = true
	httpReq.Header.Set("Content-Type", "application/json")

	httpReq.SetBasicAuth(self.user, self.passwd)

	rsp, err := self.restClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("SendRestRequestWithAuth - http post error:%s", err)
	}
	defer rsp.Body.Close()
	body, err := ioutil.ReadAll(rsp.Body)
	if err != nil || len(body) == 0 {
		return nil, fmt.Errorf("SendRestRequestWithAuth - read rest response body error:%s", err)
	}
	return body, nil
}

func getValidators(rpc *client.HTTP, h int64) ([]*types2.Validator, error) {
	p := 1
	vSet := make([]*types2.Validator, 0)
	for {
		res, err := rpc.Validators(&h, p, 100)
		if err != nil {
			if strings.Contains(err.Error(), "page should be within") {
				return vSet, nil
			}
			return nil, err
		}
		// In case tendermint don't give relayer the right error
		if len(res.Validators) == 0 {
			return vSet, nil
		}
		vSet = append(vSet, res.Validators...)
		p++
	}
}

func NewCodec() *codec.Codec {
	cdc := codec.New()
	bank.RegisterCodec(cdc)
	types3.RegisterCodec(cdc)
	codec.RegisterCrypto(cdc)
	auth.RegisterCodec(cdc)
	staking.RegisterCodec(cdc)
	btcx.RegisterCodec(cdc)
	ccm.RegisterCodec(cdc)
	ft.RegisterCodec(cdc)
	headersync.RegisterCodec(cdc)
	lockproxy.RegisterCodec(cdc)
	return cdc
}

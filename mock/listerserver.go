// Copyright © 2020, 2021 Weald Technology Trading.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package dirk

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	pb "github.com/wealdtech/eth2-signer-api/pb/v1"
)

func _byte(input string) []byte {
	res, _ := hex.DecodeString(strings.TrimPrefix(input, "0x"))
	return res
}

// ErroringListerServer is a mock lister server that returns errors.
type ErroringListerServer struct {
	pb.UnimplementedListerServer
}

// ListAccounts returns an error.
func (s *ErroringListerServer) ListAccounts(_ context.Context, _ *pb.ListAccountsRequest) (*pb.ListAccountsResponse, error) {
	return &pb.ListAccountsResponse{
		State: pb.ResponseState_UNKNOWN,
	}, errors.New("mock error")
}

// DenyingListerServer is a mock lister server that returns denials.
type DenyingListerServer struct {
	pb.UnimplementedListerServer
}

// ListAccounts returns an error.
func (s *DenyingListerServer) ListAccounts(_ context.Context, _ *pb.ListAccountsRequest) (*pb.ListAccountsResponse, error) {
	return &pb.ListAccountsResponse{
		State: pb.ResponseState_DENIED,
	}, nil
}

// MockListerServer is a mock lister server that returns static accounts.
type MockListerServer struct {
	pb.UnimplementedListerServer
}

// ListAccounts returns static accounts.
func (s *MockListerServer) ListAccounts(_ context.Context, in *pb.ListAccountsRequest) (*pb.ListAccountsResponse, error) {
	interopAccounts := map[string]*pb.Account{
		"Interop 0": {
			Name:      "Interop 0",
			PublicKey: _byte("0xa99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c"),
			Uuid:      _byte("0x00000000000000000000000000000000"),
		},
		"Interop 1": {
			Name:      "Interop 1",
			PublicKey: _byte("0xb89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b"),
			Uuid:      _byte("0x00000000000000000000000000000001"),
		},
		"Interop 2": {
			Name:      "Interop 2",
			PublicKey: _byte("0xa3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b"),
			Uuid:      _byte("0x00000000000000000000000000000002"),
		},
		"Interop 3": {
			Name:      "Interop 3",
			PublicKey: _byte("0x88c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e"),
			Uuid:      _byte("0x00000000000000000000000000000003"),
		},
		"Interop 4": {
			Name:      "Interop 4",
			PublicKey: _byte("0x81283b7a20e1ca460ebd9bbd77005d557370cabb1f9a44f530c4c4c66230f675f8df8b4c2818851aa7d77a80ca5a4a5e"),
			Uuid:      _byte("0x00000000000000000000000000000004"),
		},
	}
	allDistributedAccounts := map[string]*pb.DistributedAccount{
		"Interop 0": {
			Name:               "Distributed 0",
			PublicKey:          _byte("0xaaf4abea98732aa9da46a4ddd8c56c03ec173a4daae90424e986be61d2b07999db746e103d6f505dc98716e91d4f946a"),
			CompositePublicKey: _byte("0xa155a5fb0a6d732fa0f4d3714a8550ee5b90690475e010fbf89277e98e060203d69eba05fa71b2d0fa6aa6d091172f1e"),
			SigningThreshold:   3,
			Participants: []*pb.Endpoint{
				{
					Id:   1,
					Name: "signer-test01",
					Port: 12001,
				},
				{
					Id:   2,
					Name: "signer-test02",
					Port: 12002,
				},
				{
					Id:   3,
					Name: "signer-test03",
					Port: 12003,
				},
				{
					Id:   4,
					Name: "signer-test04",
					Port: 12004,
				},
				{
					Id:   5,
					Name: "signer-test05",
					Port: 12005,
				},
			},
			Uuid: _byte("0x01000000000000000000000000000000"),
		},
		"Interop 1": {
			Name:               "Distributed 1",
			PublicKey:          _byte("0x98bc7c7596d70a27a243e6b6acc4a96bf1666428783671cb8545ced08a10c641fae1afbc83b525fce9357f6be667129e"),
			CompositePublicKey: _byte("0x93c98077de26a2d382910c64664bb34ca3e29a5a6e3222c590b28efe9bc554b607677947cb6a44b168b2da5c74237fba"),
			SigningThreshold:   3,
			Participants: []*pb.Endpoint{
				{
					Id:   1,
					Name: "signer-test01",
					Port: 12001,
				},
				{
					Id:   2,
					Name: "signer-test02",
					Port: 12002,
				},
				{
					Id:   3,
					Name: "signer-test03",
					Port: 12003,
				},
				{
					Id:   4,
					Name: "signer-test04",
					Port: 12004,
				},
				{
					Id:   5,
					Name: "signer-test05",
					Port: 12005,
				},
			},
			Uuid: _byte("0x01000000000000000000000000000001"),
		},
		"Interop 2": {
			Name:               "Distributed 2",
			PublicKey:          _byte("0x98552b2bdb1860c0c6363111477e3d738220988c9a2ee25fdeaa9971077d2ecde772c87dce07ce5f73754dcb585c43bf"),
			CompositePublicKey: _byte("0xb75f33e5bd36841eb79f5018ad9f48494ddcc5b71bb671a59effdd2a139f8be18287df69bc028ce9b21e57d37bea5ffa"),
			SigningThreshold:   3,
			Participants: []*pb.Endpoint{
				{
					Id:   1,
					Name: "signer-test01",
					Port: 12001,
				},
				{
					Id:   2,
					Name: "signer-test02",
					Port: 12002,
				},
				{
					Id:   3,
					Name: "signer-test03",
					Port: 12003,
				},
				{
					Id:   4,
					Name: "signer-test04",
					Port: 12004,
				},
				{
					Id:   5,
					Name: "signer-test05",
					Port: 12005,
				},
			},
			Uuid: _byte("0x01000000000000000000000000000002"),
		},
	}

	accounts := make([]*pb.Account, 0)
	for _, account := range interopAccounts {
		if len(in.Paths) == 0 {
			accounts = append(accounts, account)
		} else {
			for i := range in.Paths {
				if !strings.Contains(in.Paths[i], "/") {
					// Wallet only.
					accounts = append(accounts, account)
					break
				}
				if strings.HasSuffix(in.Paths[i], fmt.Sprintf("/%s", account.Name)) {
					accounts = append(accounts, account)
					break
				}
			}
		}
	}

	distributedAccounts := make([]*pb.DistributedAccount, 0)
	for _, account := range allDistributedAccounts {
		if len(in.Paths) == 0 {
			distributedAccounts = append(distributedAccounts, account)
		} else {
			for i := range in.Paths {
				if !strings.Contains(in.Paths[i], "/") {
					// Wallet only.
					distributedAccounts = append(distributedAccounts, account)
					break
				}
				if strings.HasSuffix(in.Paths[i], fmt.Sprintf("/%s", account.Name)) {
					distributedAccounts = append(distributedAccounts, account)
					break
				}
			}
		}
	}

	return &pb.ListAccountsResponse{
		State:               pb.ResponseState_SUCCEEDED,
		Accounts:            accounts,
		DistributedAccounts: distributedAccounts,
	}, nil
}

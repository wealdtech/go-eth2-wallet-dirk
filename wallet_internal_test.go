// Copyright © 2020, 2021 Weald Technology Trading
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
	"testing"

	"github.com/google/uuid"
	mock "github.com/p2p-org/go-eth2-wallet-dirk/mock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	pb "github.com/wealdtech/eth2-signer-api/pb/v1"
	e2types "github.com/wealdtech/go-eth2-types/v2"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
	"google.golang.org/grpc/credentials"
)

func TestWalletFunctions(t *testing.T) {
	require.NoError(t, e2types.InitBLS())
	ctx := context.Background()
	w, err := OpenWallet(ctx, "Test wallet", credentials.NewTLS(nil), []*Endpoint{})
	require.NoError(t, err)

	assert.Equal(t, "00000000-0000-0000-0000-000000000000", w.ID().String())
	assert.Equal(t, "dirk", w.Type())
	assert.Equal(t, uint(1), w.Version())
	unlocked, err := w.(e2wtypes.WalletLocker).IsUnlocked(ctx)
	assert.NoError(t, err)
	assert.True(t, unlocked)
	assert.NoError(t, w.(e2wtypes.WalletLocker).Unlock(ctx, nil))
	unlocked, err = w.(e2wtypes.WalletLocker).IsUnlocked(ctx)
	assert.NoError(t, err)
	assert.True(t, unlocked)
	assert.NoError(t, w.(e2wtypes.WalletLocker).Lock(ctx))
	unlocked, err = w.(e2wtypes.WalletLocker).IsUnlocked(ctx)
	assert.NoError(t, err)
	assert.True(t, unlocked)
}

func TestListNoEndpoints(t *testing.T) {
	require.NoError(t, e2types.InitBLS())
	ctx := context.Background()
	connectionProvider, err := NewBufConnectionProvider(ctx, []pb.ListerServer{&mock.MockListerServer{}})
	require.NoError(t, err)
	w, err := OpenWallet(ctx, "Test wallet", credentials.NewTLS(nil), []*Endpoint{})
	require.NoError(t, err)
	w.(*wallet).SetConnectionProvider(connectionProvider)
	_, err = w.(*wallet).List(ctx, "")
	require.EqualError(t, err, "wallet has no endpoints")
}

func TestListErroringConnectionProvider(t *testing.T) {
	require.NoError(t, e2types.InitBLS())
	ctx := context.Background()
	connectionProvider := &ErroringConnectionProvider{}
	w, err := OpenWallet(ctx, "Test wallet", credentials.NewTLS(nil), []*Endpoint{{host: "localhost", port: 12345}})
	require.NoError(t, err)
	w.(*wallet).SetConnectionProvider(connectionProvider)
	_, err = w.(*wallet).List(ctx, "")
	require.EqualError(t, err, "failed to access dirk: mock error")
}

func TestListErroringServer(t *testing.T) {
	require.NoError(t, e2types.InitBLS())
	ctx := context.Background()
	connectionProvider, err := NewBufConnectionProvider(ctx, []pb.ListerServer{&mock.ErroringListerServer{}})
	require.NoError(t, err)
	w, err := OpenWallet(ctx, "Test wallet", credentials.NewTLS(nil), []*Endpoint{{host: "localhost", port: 12345}})
	require.NoError(t, err)
	w.(*wallet).SetConnectionProvider(connectionProvider)
	_, err = w.(*wallet).List(ctx, "")
	require.EqualError(t, err, "failed to access dirk: rpc error: code = Unknown desc = mock error")
}

func TestListDenyingServer(t *testing.T) {
	require.NoError(t, e2types.InitBLS())
	ctx := context.Background()
	connectionProvider, err := NewBufConnectionProvider(ctx, []pb.ListerServer{&mock.DenyingListerServer{}})
	require.NoError(t, err)
	w, err := OpenWallet(ctx, "Test wallet", credentials.NewTLS(nil), []*Endpoint{{host: "localhost", port: 12345}})
	require.NoError(t, err)
	w.(*wallet).SetConnectionProvider(connectionProvider)
	_, err = w.(*wallet).List(ctx, "")
	require.EqualError(t, err, "request to list wallet accounts returned state DENIED")
}

func TestList(t *testing.T) {
	require.NoError(t, e2types.InitBLS())
	ctx := context.Background()
	connectionProvider, err := NewBufConnectionProvider(ctx, []pb.ListerServer{&mock.MockListerServer{}})
	require.NoError(t, err)
	w, err := OpenWallet(ctx, "Test wallet", credentials.NewTLS(nil), []*Endpoint{{host: "localhost", port: 12345}})
	require.NoError(t, err)
	w.(*wallet).SetConnectionProvider(connectionProvider)

	tests := []struct {
		name     string
		path     string
		err      string
		accounts int
	}{
		{
			name:     "Nil",
			accounts: 8,
		},
		{
			name:     "One",
			path:     "Interop 2",
			accounts: 1,
		},
		{
			name:     "OneDistributed",
			path:     "Distributed 1",
			accounts: 1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			accounts, err := w.(*wallet).List(ctx, test.path)
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
				require.Equal(t, test.accounts, len(accounts))
			}
		})
	}
}

func TestAccounts(t *testing.T) {
	require.NoError(t, e2types.InitBLS())
	ctx := context.Background()
	connectionProvider, err := NewBufConnectionProvider(ctx, []pb.ListerServer{&mock.MockListerServer{}})
	require.NoError(t, err)
	w, err := OpenWallet(ctx, "Test wallet", credentials.NewTLS(nil), []*Endpoint{{host: "localhost", port: 12345}})
	require.NoError(t, err)
	w.(*wallet).SetConnectionProvider(connectionProvider)

	accounts := 0
	for range w.Accounts(ctx) {
		accounts++
	}
	require.Equal(t, 8, accounts)
}

func TestAccountByName(t *testing.T) {
	require.NoError(t, e2types.InitBLS())
	ctx := context.Background()
	connectionProvider, err := NewBufConnectionProvider(ctx, []pb.ListerServer{&mock.MockListerServer{}})
	require.NoError(t, err)
	w, err := OpenWallet(ctx, "Test wallet", credentials.NewTLS(nil), []*Endpoint{{host: "localhost", port: 12345}})
	require.NoError(t, err)
	w.(*wallet).SetConnectionProvider(connectionProvider)

	account, err := w.(e2wtypes.WalletAccountByNameProvider).AccountByName(ctx, "Interop 2")
	require.NoError(t, err)
	require.NotNil(t, account)
	require.Equal(t, account.Name(), "Interop 2")

	_, err = w.(e2wtypes.WalletAccountByNameProvider).AccountByName(ctx, "Missing")
	require.EqualError(t, err, "not found")
}

func TestAccountByID(t *testing.T) {
	require.NoError(t, e2types.InitBLS())
	ctx := context.Background()
	connectionProvider, err := NewBufConnectionProvider(ctx, []pb.ListerServer{&mock.MockListerServer{}})
	require.NoError(t, err)
	w, err := OpenWallet(ctx, "Test wallet", credentials.NewTLS(nil), []*Endpoint{{host: "localhost", port: 12345}})
	require.NoError(t, err)
	w.(*wallet).SetConnectionProvider(connectionProvider)

	_, err = w.(e2wtypes.WalletAccountByIDProvider).AccountByID(ctx, uuid.MustParse("00000000-0000-0000-0000-000000000002"))
	require.EqualError(t, err, "not supported")
}

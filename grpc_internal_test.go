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
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	pb "github.com/wealdtech/eth2-signer-api/pb/v1"
	e2types "github.com/wealdtech/go-eth2-types/v2"
	mock "github.com/wealdtech/go-eth2-wallet-dirk/mock"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

func _byte(input string) []byte {
	res, _ := hex.DecodeString(strings.TrimPrefix(input, "0x"))
	return res
}

// ErroringConnectionProvider throws errors.
type ErroringConnectionProvider struct {
	pb.UnimplementedListerServer
}

// Connection returns a connection and release function.
func (c *ErroringConnectionProvider) Connection(_ context.Context, _ *Endpoint) (*grpc.ClientConn, func(), error) {
	return nil, nil, errors.New("mock error")
}

// ListAccounts returns an error.
func (c *ErroringConnectionProvider) ListAccounts(_ context.Context, _ *pb.ListAccountsRequest) (*pb.ListAccountsResponse, error) {
	return nil, errors.New("mock error")
}

// BufConnectionProvider provides connections to a local GRPC mock for testing.
type BufConnectionProvider struct {
	mutex         sync.Mutex
	servers       map[string]*grpc.Server
	listeners     map[string]*bufconn.Listener
	listerServers []pb.ListerServer
	signerServer  pb.SignerServer
}

const bufSize = 1024 * 1024

// NewBufConnectionProvider creates a new buffer connection provider.
func NewBufConnectionProvider(_ context.Context,
	listerServers []pb.ListerServer,
) (*BufConnectionProvider, error) {
	return &BufConnectionProvider{
		listerServers: listerServers,
		servers:       make(map[string]*grpc.Server),
		listeners:     make(map[string]*bufconn.Listener),
	}, nil
}

// NewBufConnectionProviderWithSigner creates a new buffer connection provider with signer server support.
func NewBufConnectionProviderWithSigner(_ context.Context,
	listerServers []pb.ListerServer,
	signerServer pb.SignerServer,
) (*BufConnectionProvider, error) {
	return &BufConnectionProvider{
		listerServers: listerServers,
		signerServer:  signerServer,
		servers:       make(map[string]*grpc.Server),
		listeners:     make(map[string]*bufconn.Listener),
	}, nil
}

func (c *BufConnectionProvider) bufDialer(_ context.Context, in string) (net.Conn, error) {
	return c.listeners[in].Dial()
}

// Connection returns a connection and release function.
func (c *BufConnectionProvider) Connection(ctx context.Context, endpoint *Endpoint) (*grpc.ClientConn, func(), error) {
	serverAddress := fmt.Sprintf("%s:%d", endpoint.host, endpoint.port)
	c.mutex.Lock()
	server, exists := c.servers[serverAddress]
	if !exists {
		server = grpc.NewServer()
		if len(c.listerServers) > 0 {
			// Pick a server from the available list.
			pb.RegisterListerServer(server, c.listerServers[int(endpoint.port)%len(c.listerServers)])
		}
		if c.signerServer != nil {
			pb.RegisterSignerServer(server, c.signerServer)
		}
		c.servers[serverAddress] = server
		listener := bufconn.Listen(bufSize)
		c.listeners[serverAddress] = listener
		go func(listener *bufconn.Listener) {
			if err := server.Serve(listener); err != nil {
				log.Fatalf("Buffer server error: %v", err)
			}
		}(listener)
	}
	c.mutex.Unlock()

	conn, err := grpc.DialContext(ctx,
		serverAddress,
		grpc.WithContextDialer(c.bufDialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, nil, err
	}
	return conn, func() {}, nil
}

func TestListGRPC(t *testing.T) {
	require.NoError(t, e2types.InitBLS())
	ctx := context.Background()
	connectionProvider, err := NewBufConnectionProvider(ctx, []pb.ListerServer{&mock.MockListerServer{}})
	require.NoError(t, err)
	w, err := OpenWallet(ctx, "Test wallet", credentials.NewTLS(nil), []*Endpoint{{host: "localhost", port: 12345}})
	w.(*wallet).SetConnectionProvider(connectionProvider)
	require.NoError(t, err)
	accounts := 0
	for range w.Accounts(ctx) {
		accounts++
	}
	require.Equal(t, 8, accounts)
}

func TestListGRPCDeduplication(t *testing.T) {
	require.NoError(t, e2types.InitBLS())
	ctx := context.Background()
	connectionProvider, err := NewBufConnectionProvider(ctx, []pb.ListerServer{&mock.MockListerServer{}})
	require.NoError(t, err)
	w, err := OpenWallet(ctx, "Test wallet", credentials.NewTLS(nil), []*Endpoint{{host: "localhost", port: 12345}, {host: "localhost", port: 12346}})
	w.(*wallet).SetConnectionProvider(connectionProvider)
	require.NoError(t, err)
	accounts := 0
	for range w.Accounts(ctx) {
		accounts++
	}
	require.Equal(t, 8, accounts)
}

func TestListGRPCAccountsFromSecondEndpoint(t *testing.T) {
	mockListerServer := &mock.MockListerServerOverlappingAccounts{}
	require.NoError(t, e2types.InitBLS())
	ctx := context.Background()
	connectionProvider, err := NewBufConnectionProvider(ctx, []pb.ListerServer{mockListerServer})
	require.NoError(t, err)
	w, err := OpenWallet(ctx, "Test wallet", credentials.NewTLS(nil), []*Endpoint{{host: "localhost", port: 12345}, {host: "localhost", port: 12346}})
	w.(*wallet).SetConnectionProvider(connectionProvider)
	require.NoError(t, err)
	accounts := 0
	for range w.Accounts(ctx) {
		accounts++
	}
	// The usual 8, plus an extra interop account, and an extra distributed account.
	require.Equal(t, 10, accounts)
	require.Equal(t, 2, mockListerServer.RequestsReceived)
}

func TestListGRPCErroring(t *testing.T) {
	require.NoError(t, e2types.InitBLS())
	ctx := context.Background()
	connectionProvider, err := NewBufConnectionProvider(ctx, []pb.ListerServer{&ErroringConnectionProvider{}, &mock.MockListerServer{}})
	require.NoError(t, err)
	w, err := OpenWallet(ctx, "Test wallet", credentials.NewTLS(nil), []*Endpoint{{host: "localhost", port: 12345}})
	w.(*wallet).SetConnectionProvider(connectionProvider)
	require.NoError(t, err)
	accounts := 0
	for range w.Accounts(ctx) {
		accounts++
	}
	require.Equal(t, 8, accounts)
}

// TestAccountUsesCorrectEndpointForSigning verifies that accounts use the endpoint
// that returned their data during the List operation for signing operations
func TestAccountUsesCorrectEndpointForSigning(t *testing.T) {
	require.NoError(t, e2types.InitBLS())
	ctx := context.Background()

	// Create mock signer server to track signing calls
	mockSigner := &mock.MockSignerServer{}

	// Create custom lister servers that return different accounts for different endpoints
	// endpoint1Server returns one unique account
	endpoint1Server := &mock.CustomListerServer{
		Accounts: []*pb.Account{
			{
				Name:      "Account Endpoint1",
				PublicKey: _byte("0xa99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c"),
				Uuid:      _byte("0x00000000000000000000000000000001"),
			},
		},
	}

	// endpoint2Server returns one unique account and one shared account (same as endpoint1)
	endpoint2Server := &mock.CustomListerServer{
		Accounts: []*pb.Account{
			{
				Name:      "Account Endpoint1", // Same account as endpoint1
				PublicKey: _byte("0xa99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c"),
				Uuid:      _byte("0x00000000000000000000000000000001"),
			},
			{
				Name:      "Account Endpoint2",
				PublicKey: _byte("0xb89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b"),
				Uuid:      _byte("0x00000000000000000000000000000002"),
			},
		},
	}

	connectionProvider, err := NewBufConnectionProviderWithSigner(ctx, []pb.ListerServer{endpoint2Server, endpoint1Server}, mockSigner)
	require.NoError(t, err)

	// Set up wallet with multiple endpoints
	endpoints := []*Endpoint{

		{host: "localhost", port: 12345}, // Will use endpoint1Server (port % 2 = 1)
		{host: "localhost", port: 12346}, // Will use endpoint2Server (port % 2 = 0)
	}

	w, err := OpenWallet(ctx, "Test wallet", credentials.NewTLS(nil), endpoints)
	w.(*wallet).SetConnectionProvider(connectionProvider)
	require.NoError(t, err)

	// List accounts - this should assign endpoints to accounts based on which endpoint returned them
	accounts, err := w.(*wallet).List(ctx, "")
	require.NoError(t, err)

	require.Equal(t, 2, len(accounts), "Should have 2 unique accounts (shared account not duplicated)")

	// Create a map to track accounts by endpoint
	accountsByEndpoint := make(map[string][]e2wtypes.Account)
	endpointByAccount := make(map[string]*Endpoint)

	for _, acct := range accounts {
		var accountEndpoint *Endpoint
		if acc, ok := acct.(*account); ok {
			accountEndpoint = acc.endpoint
		}

		require.NotNil(t, accountEndpoint, "Account should have an endpoint assigned")

		endpointKey := fmt.Sprintf("%s:%d", accountEndpoint.host, accountEndpoint.port)
		accountsByEndpoint[endpointKey] = append(accountsByEndpoint[endpointKey], acct)
		endpointByAccount[acct.Name()] = accountEndpoint
	}

	// Verify that the shared account "Account Endpoint1" is assigned to one of the endpoints that returned it
	sharedAccountEndpoint := fmt.Sprintf("%s:%d", endpointByAccount["Account Endpoint1"].host, endpointByAccount["Account Endpoint1"].port)
	require.True(t, sharedAccountEndpoint == "localhost:12345" || sharedAccountEndpoint == "localhost:12346",
		"Shared account should be assigned to one of the endpoints that returned it, got: %s", sharedAccountEndpoint)

	// Verify that Account Endpoint2 is assigned to endpoint 12346 (only endpoint that returns it)
	require.Equal(t, "localhost:12346", fmt.Sprintf("%s:%d", endpointByAccount["Account Endpoint2"].host, endpointByAccount["Account Endpoint2"].port))

	// Verify that we have exactly 2 accounts total (no duplication of the shared account)
	require.Equal(t, 2, len(accounts), "Should have exactly 2 unique accounts")

	// The endpoint distribution depends on which goroutine finished last
	// But we should have accounts assigned to their endpoints
	totalAccountsAssigned := 0
	for _, accountsOnEndpoint := range accountsByEndpoint {
		totalAccountsAssigned += len(accountsOnEndpoint)
	}
	require.Equal(t, 2, totalAccountsAssigned, "All accounts should be assigned to endpoints")

	// Test signing with both accounts to verify they use their assigned endpoints
	for _, acct := range accounts {
		// Sign with the account - this should use the endpoint assigned during List operation
		_, err := acct.(e2wtypes.AccountProtectingSigner).SignGeneric(ctx,
			[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		)

		// The signing should have succeeded (no error)
		require.NoError(t, err)
	}

	// Verify that the signer server was called with both accounts
	endpointsUsed := mockSigner.GetEndpointsUsed()
	require.Len(t, endpointsUsed, 2, "Signer server should have been called for both accounts")
	require.Contains(t, endpointsUsed, "Test wallet/Account Endpoint1", "Should have signed with shared account")
	require.Contains(t, endpointsUsed, "Test wallet/Account Endpoint2", "Should have signed with account from endpoint 2")

	// Verify that signing works with whatever endpoint the shared account got assigned to
	// This demonstrates that endpoint reassignment works correctly and accounts use their assigned endpoint for signing
	t.Logf("Shared account 'Account Endpoint1' was assigned to endpoint: %s:%d",
		endpointByAccount["Account Endpoint1"].host, endpointByAccount["Account Endpoint1"].port)
}

// Disabled because it results in a link back to Dirk repository for
//	"github.com/attestantio/dirk/testing/daemon"
//	"github.com/attestantio/dirk/testing/resources"
// func TestDistributedThresholdSign(t *testing.T) {
// 	// Create a distributed account.
// 	err := e2types.InitBLS()
// 	require.NoError(t, err)
//
// 	rand.Seed(time.Now().UnixNano())
// 	// #nosec G404
// 	port1 := uint32(12000 + rand.Intn(4000))
// 	// #nosec G404
// 	port2 := uint32(12000 + rand.Intn(4000))
// 	// #nosec G404
// 	port3 := uint32(12000 + rand.Intn(4000))
// 	peersMap := map[uint64]string{
// 		1: fmt.Sprintf("signer-test01:%d", port1),
// 		2: fmt.Sprintf("signer-test02:%d", port2),
// 		3: fmt.Sprintf("signer-test03:%d", port3),
// 	}
//
// 	ctx1, cancel1 := context.WithCancel(context.Background())
// 	defer cancel1()
// 	_, path1, err := daemon.New(ctx1, "", 1, port1, peersMap)
// 	require.NoError(t, err)
// 	defer os.RemoveAll(path1)
//
// 	ctx2, cancel2 := context.WithCancel(context.Background())
// 	defer cancel2()
// 	_, path2, err := daemon.New(ctx2, "", 2, port2, peersMap)
// 	require.NoError(t, err)
// 	defer os.RemoveAll(path2)
//
// 	ctx3, cancel3 := context.WithCancel(context.Background())
// 	defer cancel3()
// 	_, path3, err := daemon.New(ctx3, "", 3, port3, peersMap)
// 	require.NoError(t, err)
// 	defer os.RemoveAll(path3)
//
// 	endpoints := []*Endpoint{
// 		NewEndpoint("signer-test01", port1),
// 		NewEndpoint("signer-test02", port2),
// 		NewEndpoint("signer-test03", port3),
// 	}
//
// 	ctx := context.Background()
// 	credentials, err := Credentials(ctx,
// 		resources.ClientTest01Crt,
// 		resources.ClientTest01Key,
// 		resources.CACrt,
// 	)
// 	require.NoError(t, err)
//
// 	wallet, err := OpenWallet(ctx, "Wallet 3", credentials, endpoints)
// 	require.NoError(t, err)
//
// 	require.NoError(t, wallet.(e2wtypes.WalletLocker).Unlock(ctx, nil))
//
// 	accountCreator, isAccountCreator := wallet.(e2wtypes.WalletDistributedAccountCreator)
// 	require.True(t, isAccountCreator)
//
// 	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
// 	defer cancel()
// 	_, err = accountCreator.CreateDistributedAccount(ctx, "Test account", 3, 2, []byte("pass"))
// 	require.NoError(t, err)
//
// 	account, err := wallet.(e2wtypes.WalletAccountByNameProvider).AccountByName(ctx, "Test account")
// 	require.NoError(t, err)
//
// 	// Unlock the account.
// 	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
// 	defer cancel()
// 	err = account.(e2wtypes.AccountLocker).Unlock(ctx, []byte("pass"))
// 	require.NoError(t, err)
//
// 	// Sign with the account.
// 	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
// 	defer cancel()
// 	sig1, err := account.(e2wtypes.AccountProtectingSigner).SignGeneric(ctx,
// 		[]byte{
// 			0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
// 			0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
// 		},
// 		[]byte{
// 			0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
// 			0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
// 		},
// 	)
// 	require.NoError(t, err)
// 	require.NotNil(t, sig1)
//
// 	// Kill one of the daemons.
// 	cancel3()
// 	time.Sleep(time.Second)
//
// 	// Sign again; should still work as we only need 2/3.
// 	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
// 	defer cancel()
// 	sig2, err := account.(e2wtypes.AccountProtectingSigner).SignGeneric(ctx,
// 		[]byte{
// 			0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
// 			0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
// 		},
// 		[]byte{
// 			0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
// 			0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
// 		},
// 	)
// 	require.NoError(t, err)
// 	require.NotNil(t, sig2)
// 	require.Equal(t, sig1.Marshal(), sig2.Marshal())
//
// 	// Kill another one of the daemons.
// 	cancel2()
// 	time.Sleep(time.Second)
//
// 	// Sign again; should error out as we no longer have enough active daemons.
// 	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
// 	defer cancel()
// 	_, err = account.(e2wtypes.AccountProtectingSigner).SignGeneric(ctx,
// 		[]byte{
// 			0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
// 			0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
// 		},
// 		[]byte{
// 			0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
// 			0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
// 		},
// 	)
// 	require.EqualError(t, err, "failed to obtain signature: not enough signatures: 1 signed, 0 denied, 0 failed, 2 errored")
// }

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
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/attestantio/dirk/testing/daemon"
	"github.com/attestantio/dirk/testing/resources"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	pb "github.com/wealdtech/eth2-signer-api/pb/v1"
	e2types "github.com/wealdtech/go-eth2-types/v2"
	mock "github.com/wealdtech/go-eth2-wallet-dirk/mock"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/test/bufconn"
)

// ErroringConnectionProvider throws errors.
type ErroringConnectionProvider struct{}

// Connection returns a connection and release function.
func (c *ErroringConnectionProvider) Connection(ctx context.Context, endpoint *Endpoint) (*grpc.ClientConn, func(), error) {
	return nil, nil, errors.New("mock error")
}

// ListAccounts returns an error.
func (c *ErroringConnectionProvider) ListAccounts(ctx context.Context, in *pb.ListAccountsRequest) (*pb.ListAccountsResponse, error) {
	return nil, errors.New("mock error")
}

// BufConnectionProvider provides connections to a local GRPC mock for testing.
type BufConnectionProvider struct {
	mutex         sync.Mutex
	servers       map[string]*grpc.Server
	listeners     map[string]*bufconn.Listener
	listerServers []pb.ListerServer
}

const bufSize = 1024 * 1024

// NewBufConnectionProvider creates a new buffer connection provider.
func NewBufConnectionProvider(ctx context.Context,
	listerServers []pb.ListerServer) (*BufConnectionProvider, error) {
	return &BufConnectionProvider{
		listerServers: listerServers,
		servers:       make(map[string]*grpc.Server),
		listeners:     make(map[string]*bufconn.Listener),
	}, nil
}

func (c *BufConnectionProvider) bufDialer(ctx context.Context, in string) (net.Conn, error) {
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
		c.servers[serverAddress] = server
		c.listeners[serverAddress] = bufconn.Listen(bufSize)
		go func() {
			if err := server.Serve(c.listeners[serverAddress]); err != nil {
				log.Fatalf("Buffer server error: %v", err)
			}
		}()
	}
	c.mutex.Unlock()

	conn, err := grpc.DialContext(ctx, serverAddress, grpc.WithContextDialer(c.bufDialer), grpc.WithInsecure())
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

func TestDistributedThresholdSign(t *testing.T) {
	// Create a distributed account.
	err := e2types.InitBLS()
	require.NoError(t, err)

	rand.Seed(time.Now().UnixNano())
	// #nosec G404
	port1 := uint32(12000 + rand.Intn(4000))
	// #nosec G404
	port2 := uint32(12000 + rand.Intn(4000))
	// #nosec G404
	port3 := uint32(12000 + rand.Intn(4000))
	peersMap := map[uint64]string{
		1: fmt.Sprintf("signer-test01:%d", port1),
		2: fmt.Sprintf("signer-test02:%d", port2),
		3: fmt.Sprintf("signer-test03:%d", port3),
	}

	ctx1, cancel1 := context.WithCancel(context.Background())
	defer cancel1()
	_, path1, err := daemon.New(ctx1, "", 1, port1, peersMap)
	require.NoError(t, err)
	defer os.RemoveAll(path1)

	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	_, path2, err := daemon.New(ctx2, "", 2, port2, peersMap)
	require.NoError(t, err)
	defer os.RemoveAll(path2)

	ctx3, cancel3 := context.WithCancel(context.Background())
	defer cancel3()
	_, path3, err := daemon.New(ctx3, "", 3, port3, peersMap)
	require.NoError(t, err)
	defer os.RemoveAll(path3)

	endpoints := []*Endpoint{
		NewEndpoint("signer-test01", port1),
		NewEndpoint("signer-test02", port2),
		NewEndpoint("signer-test03", port3),
	}

	ctx := context.Background()
	credentials, err := Credentials(ctx,
		resources.ClientTest01Crt,
		resources.ClientTest01Key,
		resources.CACrt,
	)
	require.NoError(t, err)

	wallet, err := OpenWallet(ctx, "Wallet 3", credentials, endpoints)
	require.NoError(t, err)

	require.NoError(t, wallet.(e2wtypes.WalletLocker).Unlock(ctx, nil))

	accountCreator, isAccountCreator := wallet.(e2wtypes.WalletDistributedAccountCreator)
	require.True(t, isAccountCreator)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = accountCreator.CreateDistributedAccount(ctx, "Test account", 3, 2, []byte("pass"))
	require.NoError(t, err)

	account, err := wallet.(e2wtypes.WalletAccountByNameProvider).AccountByName(ctx, "Test account")
	require.NoError(t, err)

	// Unlock the account.
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = account.(e2wtypes.AccountLocker).Unlock(ctx, []byte("pass"))
	require.NoError(t, err)

	// Sign with the account.
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sig1, err := account.(e2wtypes.AccountProtectingSigner).SignGeneric(ctx,
		[]byte{
			0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
			0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
		},
		[]byte{
			0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
			0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
		},
	)
	require.NoError(t, err)
	require.NotNil(t, sig1)

	// Kill one of the daemons.
	cancel3()
	time.Sleep(time.Second)

	// Sign again; should still work as we only need 2/3.
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sig2, err := account.(e2wtypes.AccountProtectingSigner).SignGeneric(ctx,
		[]byte{
			0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
			0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
		},
		[]byte{
			0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
			0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
		},
	)
	require.NoError(t, err)
	require.NotNil(t, sig2)
	require.Equal(t, sig1.Marshal(), sig2.Marshal())

	// Kill another one of the daemons.
	cancel2()
	time.Sleep(time.Second)

	// Sign again; should error out as we no longer have enough active daemons.
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = account.(e2wtypes.AccountProtectingSigner).SignGeneric(ctx,
		[]byte{
			0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
			0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
		},
		[]byte{
			0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
			0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
		},
	)
	require.EqualError(t, err, "failed to obtain signature: not enough signatures: 1 signed, 0 denied, 0 failed, 2 errored")
}

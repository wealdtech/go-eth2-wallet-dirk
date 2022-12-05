// Copyright © 2020 Weald Technology Trading
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

package dirk_test

import (
	"context"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	e2types "github.com/wealdtech/go-eth2-types/v2"
	dirk "github.com/wealdtech/go-eth2-wallet-dirk"
)

func TestComposeCredentials(t *testing.T) {
	err := e2types.InitBLS()
	require.NoError(t, err)

	tmpDir, err := ioutil.TempDir(os.TempDir(), "TestAccounts")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)
	require.NoError(t, SetupCerts(tmpDir))
	ctx := context.Background()

	tests := []struct {
		name       string
		clientPath string
		keyPath    string
		caPath     string
		err        string
	}{
		{
			name:       "ClientPathEmpty",
			clientPath: "",
			keyPath:    filepath.Join(tmpDir, "client-test01.key"),
			caPath:     filepath.Join(tmpDir, "ca.crt"),
			err:        `failed to obtain client certificate: open : no such file or directory`,
		},
		{
			name:       "ClientPathBad",
			clientPath: "bad",
			keyPath:    filepath.Join(tmpDir, "client-test01.key"),
			caPath:     filepath.Join(tmpDir, "ca.crt"),
			err:        `failed to obtain client certificate: open bad: no such file or directory`,
		},
		{
			name:       "KeyPathEmpty",
			clientPath: filepath.Join(tmpDir, "client-test01.crt"),
			keyPath:    "",
			caPath:     filepath.Join(tmpDir, "ca.crt"),
			err:        `failed to obtain client key: open : no such file or directory`,
		},
		{
			name:       "KeyPathBad",
			clientPath: filepath.Join(tmpDir, "client-test01.crt"),
			keyPath:    "bad",
			caPath:     filepath.Join(tmpDir, "ca.crt"),
			err:        `failed to obtain client key: open bad: no such file or directory`,
		},
		{
			name:       "CAPathEmpty",
			clientPath: filepath.Join(tmpDir, "client-test01.crt"),
			keyPath:    filepath.Join(tmpDir, "client-test01.key"),
			caPath:     "",
			// CA path is optional so no error expected.
		},
		{
			name:       "CAPathBad",
			clientPath: filepath.Join(tmpDir, "client-test01.crt"),
			keyPath:    filepath.Join(tmpDir, "client-test01.key"),
			caPath:     "bad",
			err:        `failed to obtain CA certificate: open bad: no such file or directory`,
		},
		{
			name:       "Good",
			clientPath: filepath.Join(tmpDir, "client-test01.crt"),
			keyPath:    filepath.Join(tmpDir, "client-test01.key"),
			caPath:     filepath.Join(tmpDir, "ca.crt"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			_, err := dirk.ComposeCredentials(ctx, test.clientPath, test.keyPath, test.caPath)
			if test.err == "" {
				require.NoError(t, err)
			} else {
				require.EqualError(t, err, test.err)
			}
		})
	}
}

// Disabled because it results in a link back to Dirk repository for
//	"github.com/attestantio/dirk/testing/daemon"
//	"github.com/attestantio/dirk/testing/resources"
// func TestAccounts(t *testing.T) {
// 	err := e2types.InitBLS()
// 	require.NoError(t, err)
//
// 	ctx, cancel := context.WithCancel(context.Background())
// 	defer cancel()
// 	rand.Seed(time.Now().UnixNano())
// 	// #nosec G404
// 	port := uint32(12000 + rand.Intn(4000))
// 	_, path, err := daemon.New(ctx, "", 1, port,
// 		map[uint64]string{
// 			1: fmt.Sprintf("signer-test01:%d", port),
// 		})
// 	defer os.RemoveAll(path)
// 	require.NoError(t, err)
//
// 	endpoints := []*dirk.Endpoint{
// 		dirk.NewEndpoint("signer-test01", port),
// 	}
//
// 	credentials, err := dirk.Credentials(ctx,
// 		resources.ClientTest01Crt,
// 		resources.ClientTest01Key,
// 		resources.CACrt,
// 	)
// 	require.NoError(t, err)
//
// 	wallet, err := dirk.OpenWallet(ctx, "Wallet 1", credentials, endpoints)
// 	require.NoError(t, err)
//
// 	accounts := 0
// 	for range wallet.Accounts(ctx) {
// 		accounts++
// 	}
// 	require.Equal(t, len(daemon.Wallet1Keys), accounts)
// }
//
// func TestAccountByName(t *testing.T) {
// 	err := e2types.InitBLS()
// 	require.NoError(t, err)
//
// 	ctx, cancel := context.WithCancel(context.Background())
// 	defer cancel()
// 	rand.Seed(time.Now().UnixNano())
// 	// #nosec G404
// 	port := uint32(12000 + rand.Intn(4000))
// 	_, path, err := daemon.New(ctx, "", 1, port,
// 		map[uint64]string{
// 			1: fmt.Sprintf("signer-test01:%d", port),
// 		})
// 	defer os.RemoveAll(path)
// 	require.NoError(t, err)
//
// 	endpoints := []*dirk.Endpoint{
// 		dirk.NewEndpoint("signer-test01", port),
// 	}
//
// 	credentials, err := dirk.Credentials(ctx,
// 		resources.ClientTest01Crt,
// 		resources.ClientTest01Key,
// 		resources.CACrt,
// 	)
// 	require.NoError(t, err)
//
// 	wallet, err := dirk.OpenWallet(ctx, "Wallet 1", credentials, endpoints)
// 	require.NoError(t, err)
//
// 	accounts := 0
// 	for range wallet.Accounts(ctx) {
// 		accounts++
// 	}
// 	require.Equal(t, len(daemon.Wallet1Keys), accounts)
//
// 	tests := []struct {
// 		name        string
// 		accountName string
// 		err         string
// 	}{
// 		{
// 			name:        "Unknown",
// 			accountName: "NotHere",
// 			err:         "not found",
// 		},
// 		{
// 			name:        "Good",
// 			accountName: "Account 1",
// 		},
// 	}
//
// 	for _, test := range tests {
// 		t.Run(test.name, func(t *testing.T) {
// 			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
// 			defer cancel()
// 			account, err := wallet.(e2wtypes.WalletAccountByNameProvider).AccountByName(ctx, test.accountName)
// 			if err != nil && strings.Contains(err.Error(), "connection refused") {
// 				// Server not running; cannot test.
// 				t.Skip()
// 			}
// 			if test.err != "" {
// 				require.EqualError(t, err, test.err)
// 			} else {
// 				require.NoError(t, err)
// 				assert.Equal(t, test.accountName, account.Name())
// 			}
// 		})
// 	}
// }
//
// func TestWalletInfo(t *testing.T) {
// 	err := e2types.InitBLS()
// 	require.NoError(t, err)
//
// 	ctx, cancel := context.WithCancel(context.Background())
// 	defer cancel()
// 	rand.Seed(time.Now().UnixNano())
// 	// #nosec G404
// 	port := uint32(12000 + rand.Intn(4000))
// 	_, path, err := daemon.New(ctx, "", 1, port,
// 		map[uint64]string{
// 			1: fmt.Sprintf("signer-test01:%d", port),
// 		})
// 	defer os.RemoveAll(path)
// 	require.NoError(t, err)
//
// 	endpoints := []*dirk.Endpoint{
// 		dirk.NewEndpoint("signer-test01", port),
// 	}
//
// 	credentials, err := dirk.Credentials(ctx,
// 		resources.ClientTest01Crt,
// 		resources.ClientTest01Key,
// 		resources.CACrt,
// 	)
// 	require.NoError(t, err)
//
// 	wallet, err := dirk.OpenWallet(ctx, "Wallet 1", credentials, endpoints)
// 	require.NoError(t, err)
//
// 	assert.Equal(t, uuid.MustParse("00000000-0000-0000-0000-000000000000"), wallet.ID())
// 	assert.Equal(t, "dirk", wallet.(e2wtypes.WalletTypeProvider).Type())
// 	assert.Equal(t, "Wallet 1", wallet.Name())
// 	assert.Equal(t, uint(1), wallet.Version())
//
// 	// Unlocking is handled implicitly by dirk so we return no error.
// 	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
// 	defer cancel()
// 	err = wallet.(e2wtypes.WalletLocker).Unlock(ctx, nil)
// 	assert.NoError(t, err)
//
// 	// Lock does nothing.
// 	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
// 	defer cancel()
// 	require.NoError(t, wallet.(e2wtypes.WalletLocker).Lock(ctx))
//
// 	// AccountByID is not supported.
// 	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
// 	defer cancel()
// 	_, err = wallet.(e2wtypes.WalletAccountByIDProvider).AccountByID(ctx, uuid.MustParse("00000000-0000-0000-0000-000000000000"))
// 	assert.EqualError(t, err, "not supported")
// }

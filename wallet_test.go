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
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	e2types "github.com/wealdtech/go-eth2-types/v2"
	dirk "github.com/wealdtech/go-eth2-wallet-dirk"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
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
			err:        `failed to access client certificate/key: open : no such file or directory`,
		},
		{
			name:       "ClientPathBad",
			clientPath: "bad",
			keyPath:    filepath.Join(tmpDir, "client-test01.key"),
			caPath:     filepath.Join(tmpDir, "ca.crt"),
			err:        `failed to access client certificate/key: open bad: no such file or directory`,
		},
		{
			name:       "KeyPathEmpty",
			clientPath: filepath.Join(tmpDir, "client-test01.crt"),
			keyPath:    "",
			caPath:     filepath.Join(tmpDir, "ca.crt"),
			err:        `failed to access client certificate/key: open : no such file or directory`,
		},
		{
			name:       "KeyPathBad",
			clientPath: filepath.Join(tmpDir, "client-test01.crt"),
			keyPath:    "bad",
			caPath:     filepath.Join(tmpDir, "ca.crt"),
			err:        `failed to access client certificate/key: open bad: no such file or directory`,
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
			err:        `failed to access CA certificate: open bad: no such file or directory`,
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

func TestAccounts(t *testing.T) {
	err := e2types.InitBLS()
	require.NoError(t, err)

	tmpDir, err := ioutil.TempDir(os.TempDir(), "TestAccounts")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)
	require.NoError(t, SetupCerts(tmpDir))
	ctx := context.Background()
	credentials, err := dirk.ComposeCredentials(ctx,
		filepath.Join(tmpDir, "client-test01.crt"),
		filepath.Join(tmpDir, "client-test01.key"),
		filepath.Join(tmpDir, "ca.crt"))
	require.NoError(t, err)

	endpoints := []*dirk.Endpoint{
		dirk.NewEndpoint("signer-test01", 8881),
		dirk.NewEndpoint("signer-test02", 8882),
		dirk.NewEndpoint("signer-test03", 8883),
	}
	wallet, err := dirk.OpenWallet(ctx, "ND wallet", credentials, endpoints)
	require.NoError(t, err)
	if !pingEndpoint(endpoints[0]) {
		t.Skip()
	}

	foundAccounts := false
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	accountsCh := wallet.Accounts(ctx)
	for range accountsCh {
		foundAccounts = true
	}
	assert.True(t, foundAccounts)

}

func TestAccountByName(t *testing.T) {
	err := e2types.InitBLS()
	require.NoError(t, err)

	tmpDir, err := ioutil.TempDir(os.TempDir(), "TestAccountByName")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)
	require.NoError(t, SetupCerts(tmpDir))
	ctx := context.Background()
	credentials, err := dirk.ComposeCredentials(ctx,
		filepath.Join(tmpDir, "client-test01.crt"),
		filepath.Join(tmpDir, "client-test01.key"),
		filepath.Join(tmpDir, "ca.crt"))
	require.NoError(t, err)

	endpoints := []*dirk.Endpoint{
		dirk.NewEndpoint("signer-test01", 8881),
		dirk.NewEndpoint("signer-test02", 8882),
		dirk.NewEndpoint("signer-test03", 8883),
	}
	wallet, err := dirk.OpenWallet(ctx, "ND wallet", credentials, endpoints)
	require.NoError(t, err)

	if !pingEndpoint(endpoints[0]) {
		t.Skip()
	}
	tests := []struct {
		name        string
		accountName string
		err         string
	}{
		{
			name:        "Unknown",
			accountName: "NotHere",
			err:         "not found",
		},
		{
			name:        "Good",
			accountName: "Test account",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			account, err := wallet.(e2wtypes.WalletAccountByNameProvider).AccountByName(ctx, test.accountName)
			if err != nil && strings.Contains(err.Error(), "connection refused") {
				// Server not running; cannot test.
				t.Skip()
			}
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, test.accountName, account.Name())
			}
		})
	}
}

func TestWalletInfo(t *testing.T) {
	err := e2types.InitBLS()
	require.NoError(t, err)

	tmpDir, err := ioutil.TempDir(os.TempDir(), "TestWalletInfo")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)
	require.NoError(t, SetupCerts(tmpDir))
	ctx := context.Background()
	credentials, err := dirk.ComposeCredentials(ctx,
		filepath.Join(tmpDir, "client-test01.crt"),
		filepath.Join(tmpDir, "client-test01.key"),
		filepath.Join(tmpDir, "ca.crt"))
	require.NoError(t, err)

	endpoints := []*dirk.Endpoint{
		dirk.NewEndpoint("signer-test01", 8881),
		dirk.NewEndpoint("signer-test02", 8882),
		dirk.NewEndpoint("signer-test03", 8883),
	}
	wallet, err := dirk.OpenWallet(ctx, "ND wallet", credentials, endpoints)
	require.NoError(t, err)
	if !pingEndpoint(endpoints[0]) {
		t.Skip()
	}

	assert.Equal(t, uuid.MustParse("00000000-0000-0000-0000-000000000000"), wallet.ID())
	assert.Equal(t, "dirk", wallet.(e2wtypes.WalletTypeProvider).Type())
	assert.Equal(t, "ND wallet", wallet.Name())
	assert.Equal(t, uint(1), wallet.Version())

	// Unlocking is handled implicitly by dirk so we return no error.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = wallet.(e2wtypes.WalletLocker).Unlock(ctx, nil)
	assert.NoError(t, err)

	// Lock does nothing.
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, wallet.(e2wtypes.WalletLocker).Lock(ctx))

	// AccountByID is not supported.
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = wallet.(e2wtypes.WalletAccountByIDProvider).AccountByID(ctx, uuid.MustParse("00000000-0000-0000-0000-000000000000"))
	assert.EqualError(t, err, "not supported")
}

// pingEndpoint pings the given endpoint to see if it exists.
func pingEndpoint(endpoint *dirk.Endpoint) bool {
	conn, err := net.DialTimeout("tcp", endpoint.String(), time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

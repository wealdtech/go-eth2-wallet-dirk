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
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	e2types "github.com/wealdtech/go-eth2-types/v2"
	dirk "github.com/wealdtech/go-eth2-wallet-dirk"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

func TestCreateAccount(t *testing.T) {
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

	accountCreator, isAccountCreator := wallet.(e2wtypes.WalletAccountCreator)
	require.True(t, isAccountCreator)

	rand.Seed(time.Now().UnixNano())
	accountName := fmt.Sprintf("Test account %d", rand.Uint32())
	_, err = accountCreator.CreateAccount(context.Background(), accountName, []byte("secret"))
	require.NoError(t, err)

	require.NoError(t, wallet.(e2wtypes.WalletLocker).Lock(ctx))

	// Fetch the account to ensure it exists.
	account, err := wallet.(e2wtypes.WalletAccountByNameProvider).AccountByName(ctx, accountName)
	require.NoError(t, err)
	require.NotNil(t, account)
	require.NotNil(t, account.ID())
	require.NotNil(t, account.PublicKey())
	require.NotNil(t, account.(e2wtypes.AccountWalletProvider).Wallet())
}

func TestUnlockAccount(t *testing.T) {
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

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	account, err := wallet.(e2wtypes.WalletAccountByNameProvider).AccountByName(ctx, "Test account")
	require.NoError(t, err)

	// Unlock with incorrect passphrase.
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = account.(e2wtypes.AccountLocker).Unlock(ctx, []byte("bad"))
	assert.EqualError(t, err, "unlock attempt failed")

	// Unlock with correct passphrase.
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = account.(e2wtypes.AccountLocker).Unlock(ctx, []byte("secret"))
	require.NoError(t, err)

	unlocked, err := account.(e2wtypes.AccountLocker).IsUnlocked(ctx)
	require.NoError(t, err)
	require.True(t, unlocked)

	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	assert.NoError(t, account.(e2wtypes.AccountLocker).Lock(ctx))
}

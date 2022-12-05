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

// Disabled because it results in a link back to Dirk repository for
//	"github.com/attestantio/dirk/testing/daemon"
//	"github.com/attestantio/dirk/testing/resources"
// func TestCreateDistributedAccount(t *testing.T) {
// 	err := e2types.InitBLS()
// 	require.NoError(t, err)
//
// 	ctx, cancel := context.WithCancel(context.Background())
// 	defer cancel()
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
// 	_, path1, err := daemon.New(ctx, "", 1, port1, peersMap)
// 	require.NoError(t, err)
// 	defer os.RemoveAll(path1)
//
// 	_, path2, err := daemon.New(ctx, "", 2, port2, peersMap)
// 	require.NoError(t, err)
// 	defer os.RemoveAll(path2)
//
// 	_, path3, err := daemon.New(ctx, "", 3, port3, peersMap)
// 	require.NoError(t, err)
// 	defer os.RemoveAll(path3)
//
// 	endpoints := []*dirk.Endpoint{
// 		dirk.NewEndpoint("signer-test01", port1),
// 		dirk.NewEndpoint("signer-test02", port2),
// 		dirk.NewEndpoint("signer-test03", port3),
// 	}
//
// 	credentials, err := dirk.Credentials(ctx,
// 		resources.ClientTest01Crt,
// 		resources.ClientTest01Key,
// 		resources.CACrt,
// 	)
// 	require.NoError(t, err)
//
// 	wallet, err := dirk.OpenWallet(ctx, "Wallet 3", credentials, endpoints)
// 	require.NoError(t, err)
//
// 	require.NoError(t, wallet.(e2wtypes.WalletLocker).Unlock(ctx, nil))
//
// 	accountCreator, isAccountCreator := wallet.(e2wtypes.WalletDistributedAccountCreator)
// 	require.True(t, isAccountCreator)
//
// 	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
// 	defer cancel()
// 	_, err = accountCreator.CreateDistributedAccount(ctx, "Test account", 3, 2, []byte("pass"))
// 	require.NoError(t, err)
//
// 	require.NoError(t, wallet.(e2wtypes.WalletLocker).Lock(ctx))
//
// 	// Fetch the account to ensure it exists.
// 	account, err := wallet.(e2wtypes.WalletAccountByNameProvider).AccountByName(ctx, "Test account")
// 	require.NoError(t, err)
// 	require.NotNil(t, account)
// 	require.NotNil(t, account.ID())
// 	require.NotNil(t, account.Name())
// 	require.NotNil(t, account.PublicKey())
// 	require.NotNil(t, account.(e2wtypes.AccountCompositePublicKeyProvider).CompositePublicKey())
// 	require.NotNil(t, account.(e2wtypes.DistributedAccount).SigningThreshold())
// 	require.NotNil(t, account.(e2wtypes.DistributedAccount).Participants())
// 	require.NotNil(t, account.(e2wtypes.AccountWalletProvider).Wallet())
// }
//
// func TestUnlockDistributedAccount(t *testing.T) {
// 	err := e2types.InitBLS()
// 	require.NoError(t, err)
//
// 	ctx, cancel := context.WithCancel(context.Background())
// 	defer cancel()
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
// 	_, path1, err := daemon.New(ctx, "", 1, port1, peersMap)
// 	require.NoError(t, err)
// 	defer os.RemoveAll(path1)
//
// 	_, path2, err := daemon.New(ctx, "", 2, port2, peersMap)
// 	require.NoError(t, err)
// 	defer os.RemoveAll(path2)
//
// 	_, path3, err := daemon.New(ctx, "", 3, port3, peersMap)
// 	require.NoError(t, err)
// 	defer os.RemoveAll(path3)
//
// 	endpoints := []*dirk.Endpoint{
// 		dirk.NewEndpoint("signer-test01", port1),
// 		dirk.NewEndpoint("signer-test02", port2),
// 		dirk.NewEndpoint("signer-test03", port3),
// 	}
//
// 	credentials, err := dirk.Credentials(ctx,
// 		resources.ClientTest01Crt,
// 		resources.ClientTest01Key,
// 		resources.CACrt,
// 	)
// 	require.NoError(t, err)
//
// 	wallet, err := dirk.OpenWallet(ctx, "Wallet 3", credentials, endpoints)
// 	require.NoError(t, err)
//
// 	require.NoError(t, wallet.(e2wtypes.WalletLocker).Unlock(ctx, nil))
//
// 	accountCreator, isAccountCreator := wallet.(e2wtypes.WalletDistributedAccountCreator)
// 	require.True(t, isAccountCreator)
//
// 	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
// 	defer cancel()
// 	_, err = accountCreator.CreateDistributedAccount(ctx, "Test account", 3, 2, []byte("pass"))
// 	require.NoError(t, err)
//
// 	require.NoError(t, wallet.(e2wtypes.WalletLocker).Lock(ctx))
//
// 	account, err := wallet.(e2wtypes.WalletAccountByNameProvider).AccountByName(ctx, "Test account")
// 	require.NoError(t, err)
//
// 	// Unlock with incorrect passphrase.
// 	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
// 	defer cancel()
// 	err = account.(e2wtypes.AccountLocker).Unlock(ctx, []byte("bad"))
// 	assert.EqualError(t, err, "unlock attempt failed")
//
// 	// Unlock with correct passphrase.
// 	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
// 	defer cancel()
// 	err = account.(e2wtypes.AccountLocker).Unlock(ctx, []byte("pass"))
// 	require.NoError(t, err)
//
// 	unlocked, err := account.(e2wtypes.AccountLocker).IsUnlocked(ctx)
// 	require.NoError(t, err)
// 	require.True(t, unlocked)
//
// 	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
// 	defer cancel()
// 	assert.NoError(t, account.(e2wtypes.AccountLocker).Lock(ctx))
// }
//
// func TestDistributedSignGeneric(t *testing.T) {
// 	err := e2types.InitBLS()
// 	require.NoError(t, err)
//
// 	ctx, cancel := context.WithCancel(context.Background())
// 	defer cancel()
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
// 	_, path1, err := daemon.New(ctx, "", 1, port1, peersMap)
// 	require.NoError(t, err)
// 	defer os.RemoveAll(path1)
//
// 	_, path2, err := daemon.New(ctx, "", 2, port2, peersMap)
// 	require.NoError(t, err)
// 	defer os.RemoveAll(path2)
//
// 	_, path3, err := daemon.New(ctx, "", 3, port3, peersMap)
// 	require.NoError(t, err)
// 	defer os.RemoveAll(path3)
//
// 	endpoints := []*dirk.Endpoint{
// 		dirk.NewEndpoint("signer-test01", port1),
// 		dirk.NewEndpoint("signer-test02", port2),
// 		dirk.NewEndpoint("signer-test03", port3),
// 	}
//
// 	credentials, err := dirk.Credentials(ctx,
// 		resources.ClientTest01Crt,
// 		resources.ClientTest01Key,
// 		resources.CACrt,
// 	)
// 	require.NoError(t, err)
//
// 	wallet, err := dirk.OpenWallet(ctx, "Wallet 3", credentials, endpoints)
// 	require.NoError(t, err)
//
// 	require.NoError(t, wallet.(e2wtypes.WalletLocker).Unlock(ctx, nil))
//
// 	accountCreator, isAccountCreator := wallet.(e2wtypes.WalletDistributedAccountCreator)
// 	require.True(t, isAccountCreator)
// 	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
// 	defer cancel()
// 	account, err := accountCreator.CreateDistributedAccount(ctx, "Test account", 3, 2, []byte("pass"))
// 	require.NoError(t, err)
//
// 	tests := []struct {
// 		name   string
// 		data   []byte
// 		domain []byte
// 		err    string
// 	}{
// 		{
// 			name: "ProposerDomain",
// 			data: []byte{
// 				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// 				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// 			},
// 			domain: []byte{
// 				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// 				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// 			},
// 			err: "failed to obtain signature: not enough signatures: 0 signed, 3 denied, 0 failed, 0 errored",
// 		},
// 		{
// 			name: "AttesterDomain",
// 			data: []byte{
// 				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// 				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// 			},
// 			domain: []byte{
// 				0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// 				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// 			},
// 			err: "failed to obtain signature: not enough signatures: 0 signed, 3 denied, 0 failed, 0 errored",
// 		},
// 		{
// 			name: "DataLengthIncorrect",
// 			data: []byte{
// 				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// 				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// 			},
// 			domain: []byte{
// 				0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// 				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// 			},
// 			err: "data must be 32 bytes in length",
// 		},
// 		{
// 			name: "Good",
// 			data: []byte{
// 				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// 				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// 			},
// 			domain: []byte{
// 				0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// 				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// 			},
// 		},
// 	}
//
// 	for _, test := range tests {
// 		t.Run(test.name, func(t *testing.T) {
// 			sig, err := account.(e2wtypes.AccountProtectingSigner).SignGeneric(ctx, test.data, test.domain)
// 			if test.err != "" {
// 				require.EqualError(t, err, test.err)
// 			} else {
// 				require.NoError(t, err)
// 				// Cannot compare against a hard-coded signature because distributed accounts are generated at test time.
// 				require.NotNil(t, sig)
// 			}
// 		})
// 	}
// }
//
// func TestDistributedSignBeaconProposal(t *testing.T) {
// 	err := e2types.InitBLS()
// 	require.NoError(t, err)
//
// 	ctx, cancel := context.WithCancel(context.Background())
// 	defer cancel()
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
// 	_, path1, err := daemon.New(ctx, "", 1, port1, peersMap)
// 	require.NoError(t, err)
// 	defer os.RemoveAll(path1)
//
// 	_, path2, err := daemon.New(ctx, "", 2, port2, peersMap)
// 	require.NoError(t, err)
// 	defer os.RemoveAll(path2)
//
// 	_, path3, err := daemon.New(ctx, "", 3, port3, peersMap)
// 	require.NoError(t, err)
// 	defer os.RemoveAll(path3)
//
// 	endpoints := []*dirk.Endpoint{
// 		dirk.NewEndpoint("signer-test01", port1),
// 		dirk.NewEndpoint("signer-test02", port2),
// 		dirk.NewEndpoint("signer-test03", port3),
// 	}
//
// 	credentials, err := dirk.Credentials(ctx,
// 		resources.ClientTest01Crt,
// 		resources.ClientTest01Key,
// 		resources.CACrt,
// 	)
// 	require.NoError(t, err)
//
// 	wallet, err := dirk.OpenWallet(ctx, "Wallet 3", credentials, endpoints)
// 	require.NoError(t, err)
//
// 	require.NoError(t, wallet.(e2wtypes.WalletLocker).Unlock(ctx, nil))
//
// 	accountCreator, isAccountCreator := wallet.(e2wtypes.WalletDistributedAccountCreator)
// 	require.True(t, isAccountCreator)
// 	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
// 	defer cancel()
// 	account, err := accountCreator.CreateDistributedAccount(ctx, "Test account", 3, 2, []byte("pass"))
// 	require.NoError(t, err)
//
// 	tests := []struct {
// 		name          string
// 		slot          uint64
// 		proposerIndex uint64
// 		parentRoot    []byte
// 		stateRoot     []byte
// 		bodyRoot      []byte
// 		domain        []byte
// 		err           string
// 	}{
// 		{
// 			name:          "Good",
// 			slot:          1,
// 			proposerIndex: 1,
// 			parentRoot: []byte{
// 				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// 				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// 			},
// 			stateRoot: []byte{
// 				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// 				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// 			},
// 			bodyRoot: []byte{
// 				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// 				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// 			},
// 			domain: []byte{
// 				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// 				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// 			},
// 		},
// 		{
// 			name:          "Repeat",
// 			slot:          1,
// 			proposerIndex: 1,
// 			parentRoot: []byte{
// 				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// 				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// 			},
// 			stateRoot: []byte{
// 				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// 				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// 			},
// 			bodyRoot: []byte{
// 				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// 				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// 			},
// 			domain: []byte{
// 				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// 				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// 			},
// 			err: "failed to obtain signature: not enough signatures: 0 signed, 3 denied, 0 failed, 0 errored",
// 		},
// 	}
//
// 	for _, test := range tests {
// 		t.Run(test.name, func(t *testing.T) {
// 			sig, err := account.(e2wtypes.AccountProtectingSigner).SignBeaconProposal(ctx, test.slot, test.proposerIndex, test.parentRoot, test.stateRoot, test.bodyRoot, test.domain)
// 			if test.err != "" {
// 				require.EqualError(t, err, test.err)
// 			} else {
// 				require.NoError(t, err)
// 				// Cannot compare against a hard-coded signature because distributed accounts are generated at test time.
// 				require.NotNil(t, sig)
// 			}
// 		})
// 	}
// }
//
// func TestDistributedSignBeaconAttestation(t *testing.T) {
// 	err := e2types.InitBLS()
// 	require.NoError(t, err)
//
// 	ctx, cancel := context.WithCancel(context.Background())
// 	defer cancel()
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
// 	_, path1, err := daemon.New(ctx, "", 1, port1, peersMap)
// 	require.NoError(t, err)
// 	defer os.RemoveAll(path1)
//
// 	_, path2, err := daemon.New(ctx, "", 2, port2, peersMap)
// 	require.NoError(t, err)
// 	defer os.RemoveAll(path2)
//
// 	_, path3, err := daemon.New(ctx, "", 3, port3, peersMap)
// 	require.NoError(t, err)
// 	defer os.RemoveAll(path3)
//
// 	endpoints := []*dirk.Endpoint{
// 		dirk.NewEndpoint("signer-test01", port1),
// 		dirk.NewEndpoint("signer-test02", port2),
// 		dirk.NewEndpoint("signer-test03", port3),
// 	}
//
// 	credentials, err := dirk.Credentials(ctx,
// 		resources.ClientTest01Crt,
// 		resources.ClientTest01Key,
// 		resources.CACrt,
// 	)
// 	require.NoError(t, err)
//
// 	wallet, err := dirk.OpenWallet(ctx, "Wallet 3", credentials, endpoints)
// 	require.NoError(t, err)
//
// 	require.NoError(t, wallet.(e2wtypes.WalletLocker).Unlock(ctx, nil))
//
// 	accountCreator, isAccountCreator := wallet.(e2wtypes.WalletDistributedAccountCreator)
// 	require.True(t, isAccountCreator)
// 	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
// 	defer cancel()
// 	account, err := accountCreator.CreateDistributedAccount(ctx, "Test account", 3, 2, []byte("pass"))
// 	require.NoError(t, err)
//
// 	tests := []struct {
// 		name           string
// 		slot           uint64
// 		committeeIndex uint64
// 		blockRoot      []byte
// 		sourceEpoch    uint64
// 		sourceRoot     []byte
// 		targetEpoch    uint64
// 		targetRoot     []byte
// 		domain         []byte
// 		err            string
// 	}{
// 		{
// 			name:           "Good",
// 			slot:           1,
// 			committeeIndex: 1,
// 			blockRoot: []byte{
// 				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// 				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// 			},
// 			sourceEpoch: 0,
// 			sourceRoot: []byte{
// 				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// 				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// 			},
// 			targetEpoch: 1,
// 			targetRoot: []byte{
// 				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// 				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// 			},
// 			domain: []byte{
// 				0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// 				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// 			},
// 		},
// 		{
// 			name:           "Repeat",
// 			slot:           1,
// 			committeeIndex: 1,
// 			blockRoot: []byte{
// 				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// 				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// 			},
// 			sourceEpoch: 0,
// 			sourceRoot: []byte{
// 				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// 				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// 			},
// 			targetEpoch: 1,
// 			targetRoot: []byte{
// 				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// 				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// 			},
// 			domain: []byte{
// 				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// 				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// 			},
// 			err: "failed to obtain signature: not enough signatures: 0 signed, 3 denied, 0 failed, 0 errored",
// 		},
// 	}
//
// 	for _, test := range tests {
// 		t.Run(test.name, func(t *testing.T) {
// 			sig, err := account.(e2wtypes.AccountProtectingSigner).SignBeaconAttestation(ctx, test.slot, test.committeeIndex, test.blockRoot, test.sourceEpoch, test.sourceRoot, test.targetEpoch, test.targetRoot, test.domain)
// 			if test.err != "" {
// 				require.EqualError(t, err, test.err)
// 			} else {
// 				require.NoError(t, err)
// 				// Cannot compare against a hard-coded signature because distributed accounts are generated at test time.
// 				require.NotNil(t, sig)
// 			}
// 		})
// 	}
// }
//
// func TestDistributedSignBeaconAttestations(t *testing.T) {
// 	err := e2types.InitBLS()
// 	require.NoError(t, err)
//
// 	ctx, cancel := context.WithCancel(context.Background())
// 	defer cancel()
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
// 	_, path1, err := daemon.New(ctx, "", 1, port1, peersMap)
// 	require.NoError(t, err)
// 	defer os.RemoveAll(path1)
//
// 	_, path2, err := daemon.New(ctx, "", 2, port2, peersMap)
// 	require.NoError(t, err)
// 	defer os.RemoveAll(path2)
//
// 	_, path3, err := daemon.New(ctx, "", 3, port3, peersMap)
// 	require.NoError(t, err)
// 	defer os.RemoveAll(path3)
//
// 	endpoints := []*dirk.Endpoint{
// 		dirk.NewEndpoint("signer-test01", port1),
// 		dirk.NewEndpoint("signer-test02", port2),
// 		dirk.NewEndpoint("signer-test03", port3),
// 	}
//
// 	credentials, err := dirk.Credentials(ctx,
// 		resources.ClientTest01Crt,
// 		resources.ClientTest01Key,
// 		resources.CACrt,
// 	)
// 	require.NoError(t, err)
//
// 	wallet, err := dirk.OpenWallet(ctx, "Wallet 3", credentials, endpoints)
// 	require.NoError(t, err)
//
// 	require.NoError(t, wallet.(e2wtypes.WalletLocker).Unlock(ctx, nil))
//
// 	accountCreator, isAccountCreator := wallet.(e2wtypes.WalletDistributedAccountCreator)
// 	require.True(t, isAccountCreator)
// 	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
// 	defer cancel()
// 	account1, err := accountCreator.CreateDistributedAccount(ctx, "Test account 1", 3, 2, []byte("pass"))
// 	require.NoError(t, err)
// 	account2, err := accountCreator.CreateDistributedAccount(ctx, "Test account 2", 3, 2, []byte("pass"))
// 	require.NoError(t, err)
//
// 	tests := []struct {
// 		name             string
// 		slot             uint64
// 		accounts         []e2wtypes.Account
// 		committeeIndices []uint64
// 		blockRoot        []byte
// 		sourceEpoch      uint64
// 		sourceRoot       []byte
// 		targetEpoch      uint64
// 		targetRoot       []byte
// 		domain           []byte
// 		duplicates       bool
// 	}{
// 		{
// 			name:             "Good",
// 			slot:             1,
// 			accounts:         []e2wtypes.Account{account1, account2},
// 			committeeIndices: []uint64{1, 2},
// 			blockRoot: []byte{
// 				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// 				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// 			},
// 			sourceEpoch: 0,
// 			sourceRoot: []byte{
// 				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// 				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// 			},
// 			targetEpoch: 1,
// 			targetRoot: []byte{
// 				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// 				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// 			},
// 			domain: []byte{
// 				0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// 				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// 			},
// 		},
// 		{
// 			name:             "Repeat2",
// 			slot:             1,
// 			accounts:         []e2wtypes.Account{account1, account2},
// 			committeeIndices: []uint64{1, 2},
// 			blockRoot: []byte{
// 				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// 				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// 			},
// 			sourceEpoch: 0,
// 			sourceRoot: []byte{
// 				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// 				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// 			},
// 			targetEpoch: 1,
// 			targetRoot: []byte{
// 				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// 				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// 			},
// 			domain: []byte{
// 				0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// 				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// 			},
// 			duplicates: true,
// 		},
// 	}
//
// 	for _, test := range tests {
// 		t.Run(test.name, func(t *testing.T) {
// 			sigs, err := account1.(e2wtypes.AccountProtectingMultiSigner).SignBeaconAttestations(ctx, test.slot, test.accounts, test.committeeIndices, test.blockRoot, test.sourceEpoch, test.sourceRoot, test.targetEpoch, test.targetRoot, test.domain)
// 			require.NoError(t, err)
// 			require.Equal(t, len(test.accounts), len(sigs))
// 			if test.duplicates {
// 				// We don't receive an error for duplicates, we have indivdiual signatures return nil.
// 				for i := range sigs {
// 					require.Nil(t, sigs[i])
// 				}
// 			} else {
// 				for i := range sigs {
// 					require.NotNil(t, sigs[i])
// 				}
// 			}
// 		})
// 	}
// }

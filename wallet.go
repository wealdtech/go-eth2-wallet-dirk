// Copyright © 2020 - 2024 Weald Technology Trading.
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
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
	"google.golang.org/grpc/credentials"
)

const (
	walletType = "dirk"
)

// wallet contains the details of a remote dirk wallet.
type wallet struct {
	log                zerolog.Logger
	id                 uuid.UUID
	name               string
	version            uint
	endpoints          []*Endpoint
	timeout            time.Duration
	connectionProvider ConnectionProvider

	accountMap   map[[48]byte]e2wtypes.Account
	accountMapMu sync.RWMutex
}

// newWallet creates a new wallet.
func newWallet() *wallet {
	return &wallet{
		id:         uuid.MustParse("00000000-0000-0000-0000-000000000000"),
		timeout:    30 * time.Second,
		version:    1,
		accountMap: make(map[[48]byte]e2wtypes.Account),
	}
}

// Open opens an existing wallet with the given name.
func Open(ctx context.Context,
	params ...Parameter,
) (
	e2wtypes.Wallet,
	error,
) {
	parameters, err := parseAndCheckParameters(params...)
	if err != nil {
		return nil, errors.Wrap(err, "problem with parameters")
	}

	// Set logging.
	log := zerologger.With().Str("service", "wallet").Str("impl", "dirk").Logger()
	if parameters.logLevel != log.GetLevel() {
		log = log.Level(parameters.logLevel)
	}

	if err := registerMetrics(ctx, parameters.monitor); err != nil {
		return nil, errors.Wrap(err, "failed to register metrics")
	}

	wallet := newWallet()
	wallet.log = log
	wallet.name = parameters.name
	wallet.timeout = parameters.timeout
	wallet.endpoints = make([]*Endpoint, len(parameters.endpoints))
	wallet.connectionProvider = &PuddleConnectionProvider{
		name:            parameters.name,
		poolConnections: parameters.poolConnections,
		credentials:     parameters.credentials.Clone(),
	}
	for i := range parameters.endpoints {
		wallet.endpoints[i] = &Endpoint{
			host: parameters.endpoints[i].host,
			port: parameters.endpoints[i].port,
		}
	}
	wallet.log.Trace().Str("name", wallet.name).Msg("Opened wallet")

	return wallet, nil
}

// OpenWallet opens an existing wallet with the given name.
// Deprecated; use Open() instead.
func OpenWallet(_ context.Context, name string, credentials credentials.TransportCredentials, endpoints []*Endpoint) (e2wtypes.Wallet, error) {
	wallet := newWallet()
	wallet.name = name
	wallet.endpoints = make([]*Endpoint, len(endpoints))
	wallet.connectionProvider = &PuddleConnectionProvider{
		poolConnections: 32,
		credentials:     credentials.Clone(),
	}
	for i := range endpoints {
		wallet.endpoints[i] = &Endpoint{
			host: endpoints[i].host,
			port: endpoints[i].port,
		}
	}

	return wallet, nil
}

// ID provides the ID for the wallet.
func (w *wallet) ID() uuid.UUID {
	return w.id
}

// Type provides the type for the wallet.
func (w *wallet) Type() string {
	return walletType
}

// Name provides the name for the wallet.
func (w *wallet) Name() string {
	return w.name
}

// Version provides the version of the wallet.
func (w *wallet) Version() uint {
	return w.version
}

// Lock locks the wallet.  A locked wallet cannot create new accounts.
// Dirk manages wallet locking, so we short-circuit the request.
func (w *wallet) Lock(_ context.Context) error {
	// No-op
	return nil
}

// Unlock unlocks the wallet.  An unlocked wallet can create new accounts.
// Dirk manages wallet locking, so we short-circuit the request.
func (w *wallet) Unlock(_ context.Context, _ []byte) error {
	return nil
}

// IsUnlocked reports if the wallet is unlocked.
// Dirk manages wallet locking, so we state it as unlocked.
func (w *wallet) IsUnlocked(_ context.Context) (bool, error) {
	return true, nil
}

// Accounts provides all accounts in the wallet.
func (w *wallet) Accounts(ctx context.Context) <-chan e2wtypes.Account {
	ch := make(chan e2wtypes.Account, 1024)
	go func() {
		accounts, err := w.List(ctx, "")
		if err != nil {
			w.log.Error().Err(err).Msg("Failed to obtain accounts")
		} else {
			for _, account := range accounts {
				ch <- account
			}
		}
		close(ch)
	}()

	return ch
}

// AccountByName provides a single account from the wallet given its name.
// This will error if the account is not found.
func (w *wallet) AccountByName(ctx context.Context, name string) (e2wtypes.Account, error) {
	accounts, err := w.List(ctx, name)
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain account")
	}
	if len(accounts) == 0 {
		return nil, errors.New("not found")
	}

	return accounts[0], nil
}

// AccountByID provides a single account from the wallet given its ID.
// This will error if the account is not found.
func (w *wallet) AccountByID(_ context.Context, _ uuid.UUID) (e2wtypes.Account, error) {
	return nil, errors.New("not supported")
}

// CreateAccount creates an account.
func (w *wallet) CreateAccount(ctx context.Context, name string, passphrase []byte) (e2wtypes.Account, error) {
	return w.GenerateDistributedAccount(ctx, name, 1, 1, passphrase)
}

// CreateDistributedAccount creates a distributed account.
func (w *wallet) CreateDistributedAccount(ctx context.Context, name string, participants uint32, signingThreshold uint32, passphrase []byte) (e2wtypes.Account, error) {
	return w.GenerateDistributedAccount(ctx, name, participants, signingThreshold, passphrase)
}

// SetConnectionProvider sets a connection provider for the wallet.
// This should, in general, only be used for testing.
func (w *wallet) SetConnectionProvider(connectionProvider ConnectionProvider) {
	w.connectionProvider = connectionProvider
}

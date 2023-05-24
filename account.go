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

package dirk

import (
	"context"
	"sync"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	e2types "github.com/wealdtech/go-eth2-types/v2"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

type account struct {
	wallet  *wallet
	id      uuid.UUID
	name    string
	pubKey  e2types.PublicKey
	version uint
	mutex   *sync.RWMutex
}

func newAccount(wallet *wallet,
	id uuid.UUID,
	name string,
	pubKey e2types.PublicKey,
	version uint,
) *account {
	return &account{
		wallet:  wallet,
		id:      id,
		name:    name,
		pubKey:  pubKey,
		version: version,
		mutex:   new(sync.RWMutex),
	}
}

// ID provides the ID for the account.
func (a *account) ID() uuid.UUID {
	return a.id
}

// Name provides the name for the account.
func (a *account) Name() string {
	return a.name
}

// PublicKey provides the public key for the account.
func (a *account) PublicKey() e2types.PublicKey {
	return a.pubKey
}

// Wallet provides the wallet for the account.
func (a *account) Wallet() e2wtypes.Wallet {
	return a.wallet
}

// Lock locks the account.  A locked account cannot sign data.
func (a *account) Lock(ctx context.Context) error {
	err := a.wallet.LockAccount(ctx, a.name)
	if err != nil {
		return errors.Wrap(err, "failed attempt to lock account")
	}

	return nil
}

// Unlock unlocks the account.  An unlocked account can sign data.
func (a *account) Unlock(ctx context.Context, passphrase []byte) error {
	unlocked, err := a.wallet.UnlockAccount(ctx, a.name, passphrase)
	if err != nil {
		return errors.Wrap(err, "failed attempt to unlock account")
	}
	if !unlocked {
		return errors.New("unlock attempt failed")
	}

	return nil
}

// IsUnlocked returns true if the account is unlocked.
// Because unlocking is a handled remotely we assume true, and let it deal with it.
func (a *account) IsUnlocked(_ context.Context) (bool, error) {
	return true, nil
}

// SignGeneric signs a generic data root.
func (a *account) SignGeneric(ctx context.Context, data []byte, domain []byte) (e2types.Signature, error) {
	sig, err := a.SignGRPC(ctx, data, domain)
	if err != nil {
		return nil, err
	}

	return sig, nil
}

// SignBeaconProposal signs a beacon proposal with protection.
func (a *account) SignBeaconProposal(ctx context.Context,
	slot uint64,
	proposerIndex uint64,
	parentRoot []byte,
	stateRoot []byte,
	bodyRoot []byte,
	domain []byte,
) (e2types.Signature, error) {
	sig, err := a.SignBeaconProposalGRPC(ctx, slot, proposerIndex, parentRoot, stateRoot, bodyRoot, domain)
	if err != nil {
		return nil, err
	}

	return sig, nil
}

// SignBeaconAttestation signs a beacon attestation with protection.
func (a *account) SignBeaconAttestation(ctx context.Context,
	slot uint64,
	committeeIndex uint64,
	blockRoot []byte,
	sourceEpoch uint64,
	sourceRoot []byte,
	targetEpoch uint64,
	targetRoot []byte,
	domain []byte,
) (e2types.Signature, error) {
	sig, err := a.SignBeaconAttestationGRPC(ctx, slot, committeeIndex, blockRoot, sourceEpoch, sourceRoot, targetEpoch, targetRoot, domain)
	if err != nil {
		return nil, err
	}

	return sig, nil
}

// SignBeaconAttestations signs multiple beacon attestations with protection.
func (a *account) SignBeaconAttestations(ctx context.Context,
	slot uint64,
	accounts []e2wtypes.Account,
	committeeIndices []uint64,
	blockRoot []byte,
	sourceEpoch uint64,
	sourceRoot []byte,
	targetEpoch uint64,
	targetRoot []byte,
	domain []byte,
) ([]e2types.Signature, error) {
	sigs, err := a.SignBeaconAttestationsGRPC(ctx, slot, accounts, committeeIndices, blockRoot, sourceEpoch, sourceRoot, targetEpoch, targetRoot, domain)
	if err != nil {
		return nil, err
	}

	return sigs, nil
}

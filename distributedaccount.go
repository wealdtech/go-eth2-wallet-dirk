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
	"fmt"
	"sync"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	e2types "github.com/wealdtech/go-eth2-types/v2"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
	"google.golang.org/grpc"
)

type distributedAccount struct {
	wallet           *wallet
	id               uuid.UUID
	name             string
	pubKey           e2types.PublicKey
	compositePubKey  e2types.PublicKey
	signingThreshold uint32
	participants     map[uint64]*Endpoint
	participantConns map[uint64]*grpc.ClientConn
	version          uint
	mutex            *sync.RWMutex
}

func newDistributedAccount(wallet *wallet,
	id uuid.UUID,
	name string,
	pubKey e2types.PublicKey,
	compositePubKey e2types.PublicKey,
	signingThreshold uint32,
	participants map[uint64]*Endpoint,
	version uint,
) *distributedAccount {
	return &distributedAccount{
		wallet:           wallet,
		id:               id,
		name:             name,
		pubKey:           pubKey,
		compositePubKey:  compositePubKey,
		signingThreshold: signingThreshold,
		participants:     participants,
		participantConns: make(map[uint64]*grpc.ClientConn),
		version:          version,
		mutex:            new(sync.RWMutex),
	}
}

// ID provides the ID for the account.
func (a *distributedAccount) ID() uuid.UUID {
	return a.id
}

// Name provides the name for the account.
func (a *distributedAccount) Name() string {
	return a.name
}

// PublicKey provides the public key for the account.
func (a *distributedAccount) PublicKey() e2types.PublicKey {
	return a.pubKey
}

// CompositePublicKey provides the composite public key for the account.
func (a *distributedAccount) CompositePublicKey() e2types.PublicKey {
	return a.compositePubKey
}

// SigningThreshold provides the composite threshold for the account.
func (a *distributedAccount) SigningThreshold() uint32 {
	return a.signingThreshold
}

// Participants provides the participants in this distributed account.
func (a *distributedAccount) Participants() map[uint64]string {
	participantsCopy := make(map[uint64]string, len(a.participants))
	for k, v := range a.participants {
		participantsCopy[k] = fmt.Sprintf("%s:%d", v.host, v.port)
	}

	return participantsCopy
}

// Wallet provides the wallet for the account.
func (a *distributedAccount) Wallet() e2wtypes.Wallet {
	return a.wallet
}

// Lock locks the account.  A locked account cannot sign data.
func (a *distributedAccount) Lock(ctx context.Context) error {
	err := a.wallet.LockAccount(ctx, a.name)
	if err != nil {
		return errors.Wrap(err, "failed attempt to unlock account")
	}

	return nil
}

// Unlock unlocks the account.  An unlocked account can sign data.
func (a *distributedAccount) Unlock(ctx context.Context, passphrase []byte) error {
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
func (a *distributedAccount) IsUnlocked(_ context.Context) (bool, error) {
	return true, nil
}

// SignGeneric signs a generic data root.
func (a *distributedAccount) SignGeneric(ctx context.Context, data []byte, domain []byte) (e2types.Signature, error) {
	sig, err := a.SignGRPC(ctx, data, domain)
	if err != nil {
		return nil, err
	}

	return sig, nil
}

// SignGenericMulti signs multiple generic data roots.
func (a *distributedAccount) SignGenericMulti(ctx context.Context, accounts []e2wtypes.Account, data [][]byte, domain []byte) ([]e2types.Signature, error) {
	sigs, err := a.SignMultiGRPC(ctx, accounts, data, domain)
	if err != nil {
		return nil, err
	}

	return sigs, nil
}

// SignBeaconProposal signs a beacon proposal with protection.
func (a *distributedAccount) SignBeaconProposal(ctx context.Context,
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
func (a *distributedAccount) SignBeaconAttestation(ctx context.Context,
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
func (a *distributedAccount) SignBeaconAttestations(ctx context.Context,
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

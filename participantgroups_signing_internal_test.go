// Copyright © 2026 Weald Technology Trading.
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
	"crypto/sha256"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
	pb "github.com/wealdtech/eth2-signer-api/pb/v1"
	e2types "github.com/wealdtech/go-eth2-types/v2"
	mock "github.com/wealdtech/go-eth2-wallet-dirk/mock"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

// thresholdSignerServer is a signer that holds one real threshold key share per account.
type thresholdSignerServer struct {
	pb.UnimplementedSignerServer

	shares map[string]*bls.SecretKey
}

func (s *thresholdSignerServer) sign(account string, msg []byte) *pb.SignResponse {
	share, exists := s.shares[account[strings.LastIndex(account, "/")+1:]]
	if !exists {
		return &pb.SignResponse{State: pb.ResponseState_DENIED}
	}

	return &pb.SignResponse{State: pb.ResponseState_SUCCEEDED, Signature: share.SignByte(msg).Serialize()}
}

func (s *thresholdSignerServer) SignBeaconAttestations(_ context.Context, req *pb.SignBeaconAttestationsRequest) (*pb.MultisignResponse, error) {
	resp := &pb.MultisignResponse{Responses: make([]*pb.SignResponse, len(req.GetRequests()))}
	for i, r := range req.GetRequests() {
		resp.Responses[i] = s.sign(r.GetAccount(), attestationTestMessage(r.GetData().GetSlot(), r.GetData().GetCommitteeIndex()))
	}

	return resp, nil
}

func (s *thresholdSignerServer) Multisign(_ context.Context, req *pb.MultisignRequest) (*pb.MultisignResponse, error) {
	resp := &pb.MultisignResponse{Responses: make([]*pb.SignResponse, len(req.GetRequests()))}
	for i, r := range req.GetRequests() {
		resp.Responses[i] = s.sign(r.GetAccount(), r.GetData())
	}

	return resp, nil
}

func attestationTestMessage(slot uint64, committeeIndex uint64) []byte {
	msg := sha256.Sum256([]byte(fmt.Sprintf("%d/%d", slot, committeeIndex)))

	return msg[:]
}

// thresholdTestAccount creates a 2-of-3 distributed account whose shares are handed to the
// signers according to the given participant map (participant ID -> signer index).
func thresholdTestAccount(t *testing.T,
	w *wallet,
	name string,
	endpoints []*Endpoint,
	signers []*thresholdSignerServer,
	order map[uint64]int,
) *distributedAccount {
	t.Helper()

	msk := make([]bls.SecretKey, 2)
	for i := range msk {
		msk[i].SetByCSPRNG()
	}

	participants := make(map[uint64]*Endpoint, len(order))
	for id, signer := range order {
		var share bls.SecretKey
		require.NoError(t, share.Set(msk, blsID(id)))
		signers[signer].shares[name] = &share
		participants[id] = endpoints[signer]
	}

	compositePubKey, err := e2types.BLSPublicKeyFromBytes(msk[0].GetPublicKey().Serialize())
	require.NoError(t, err)

	return &distributedAccount{
		wallet:           w,
		name:             name,
		compositePubKey:  compositePubKey,
		signingThreshold: 2,
		participants:     participants,
		mutex:            &sync.RWMutex{},
	}
}

func TestThresholdSignMixedParticipantOrders(t *testing.T) {
	require.NoError(t, e2types.InitBLS())
	ctx := context.Background()

	signers := make([]*thresholdSignerServer, 3)
	signerServers := make(map[int]pb.SignerServer, 3)
	endpoints := make([]*Endpoint, 3)
	for i := range signers {
		signers[i] = &thresholdSignerServer{shares: make(map[string]*bls.SecretKey)}
		signerServers[i] = signers[i]
		// The buffer connection provider picks the signer server by port modulo 3.
		endpoints[i] = NewEndpoint("localhost", uint32(12000+i))
	}
	connectionProvider, err := NewBufConnectionProviderWithSigners(ctx,
		[]pb.ListerServer{&mock.MockListerServer{}, &mock.MockListerServer{}, &mock.MockListerServer{}},
		signerServers,
	)
	require.NoError(t, err)

	w := &wallet{
		log:                zerolog.Nop(),
		name:               "Test wallet",
		timeout:            5 * time.Second,
		connectionProvider: connectionProvider,
	}

	// Two accounts on the same three signers, with participant IDs assigned in a different order.
	a1 := thresholdTestAccount(t, w, "a1", endpoints, signers, map[uint64]int{1: 0, 2: 1, 3: 2})
	b1 := thresholdTestAccount(t, w, "b1", endpoints, signers, map[uint64]int{1: 1, 2: 2, 3: 0})
	a2 := thresholdTestAccount(t, w, "a2", endpoints, signers, map[uint64]int{1: 0, 2: 1, 3: 2})
	b2 := thresholdTestAccount(t, w, "b2", endpoints, signers, map[uint64]int{1: 1, 2: 2, 3: 0})

	tests := []struct {
		name     string
		accounts []*distributedAccount
	}{
		{name: "SingleOrder", accounts: []*distributedAccount{a1, a2}},
		{name: "MixedOrdersFirstLeads", accounts: []*distributedAccount{a1, b1, a2, b2}},
		{name: "MixedOrdersSecondLeads", accounts: []*distributedAccount{b2, a2, b1, a1}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			accounts := make([]e2wtypes.Account, len(test.accounts))
			committeeIndices := make([]uint64, len(test.accounts))
			data := make([][]byte, len(test.accounts))
			for i := range test.accounts {
				accounts[i] = test.accounts[i]
				committeeIndices[i] = uint64(i)
				msg := sha256.Sum256([]byte{byte(i)})
				data[i] = msg[:]
			}
			leader := test.accounts[0]

			sigs, err := leader.SignBeaconAttestations(ctx, 1, accounts, committeeIndices,
				make([]byte, 32), 0, make([]byte, 32), 0, make([]byte, 32), make([]byte, 32))
			require.NoError(t, err)
			require.Len(t, sigs, len(accounts))
			for i, sig := range sigs {
				require.NotNil(t, sig)
				require.True(t, sig.Verify(attestationTestMessage(1, committeeIndices[i]), test.accounts[i].compositePubKey),
					"attestation signature %d does not verify against account %s", i, test.accounts[i].name)
			}

			sigs, err = leader.SignGenericMulti(ctx, accounts, data, make([]byte, 32))
			require.NoError(t, err)
			require.Len(t, sigs, len(accounts))
			for i, sig := range sigs {
				require.NotNil(t, sig)
				require.True(t, sig.Verify(data[i], test.accounts[i].compositePubKey),
					"generic signature %d does not verify against account %s", i, test.accounts[i].name)
			}
		})
	}
}

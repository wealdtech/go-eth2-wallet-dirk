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
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/google/uuid"
	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/jackc/puddle"
	"github.com/pkg/errors"
	pb "github.com/wealdtech/eth2-signer-api/pb/v1"
	e2types "github.com/wealdtech/go-eth2-types/v2"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func ComposeCredentials(ctx context.Context, certPath string, keyPath string, caCertPath string) (credentials.TransportCredentials, error) {
	// Load the client certificate.
	clientPair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, errors.Wrap(err, "failed to access client certificate/key")
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{clientPair},
	}
	if caCertPath != "" {
		// Load the CA for the server certificate.
		serverCA, err := ioutil.ReadFile(caCertPath)
		if err != nil {
			return nil, errors.Wrap(err, "failed to access CA certificate")
		}
		cp := x509.NewCertPool()
		if !cp.AppendCertsFromPEM(serverCA) {
			return nil, errors.New("failed to add CA certificate")
		}
		tlsCfg.RootCAs = cp
	}

	return credentials.NewTLS(tlsCfg), nil
}

func (w *wallet) List(ctx context.Context, accountPath string) ([]e2wtypes.Account, error) {
	var path string
	if accountPath == "" {
		path = w.Name()
	} else {
		path = fmt.Sprintf("%s/%s", w.Name(), accountPath)
	}

	connResource, err := w.ObtainConnection(ctx, w.endpoints[0])
	if err != nil {
		return nil, errors.Wrap(err, "failed to connect to endpoint")
	}
	defer connResource.Release()

	listerClient := pb.NewListerClient(connResource.Value().(*grpc.ClientConn))
	req := &pb.ListAccountsRequest{
		Paths: []string{
			path,
		},
	}
	resp, err := listerClient.ListAccounts(ctx, req)
	if err != nil {
		return nil, errors.Wrap(err, "failed to access dirk")
	}
	if resp.State != pb.ResponseState_SUCCEEDED {
		return nil, errors.New("request to list wallet accounts failed")
	}

	walletPrefixLen := len(w.Name()) + 1
	accounts := make([]e2wtypes.Account, 0)
	for _, account := range resp.Accounts {
		pubKey, err := e2types.BLSPublicKeyFromBytes(account.PublicKey)
		if err != nil {
			return nil, errors.Wrap(err, "received invalid public key")
		}

		var uuid uuid.UUID
		err = uuid.UnmarshalBinary(account.Uuid)
		if err != nil {
			return nil, errors.Wrap(err, "received invalid uuid")
		}
		var name string
		if strings.Contains(account.Name, "/") {
			name = account.Name[walletPrefixLen:]
		} else {
			name = account.Name
		}
		account, err := newAccount(w, uuid, name, pubKey, 1)
		if err != nil {
			return nil, errors.Wrap(err, "failed to create new account")
		}
		accounts = append(accounts, account)
	}
	for _, account := range resp.DistributedAccounts {
		pubKey, err := e2types.BLSPublicKeyFromBytes(account.PublicKey)
		if err != nil {
			return nil, errors.Wrap(err, "received invalid public key")
		}

		compositePubKey, err := e2types.BLSPublicKeyFromBytes(account.CompositePublicKey)
		if err != nil {
			return nil, errors.Wrap(err, "received invalid composite public key")
		}

		var uuid uuid.UUID
		err = uuid.UnmarshalBinary(account.Uuid)
		if err != nil {
			return nil, errors.Wrap(err, "received invalid uuid")
		}
		var name string
		if strings.Contains(account.Name, "/") {
			name = account.Name[walletPrefixLen:]
		} else {
			name = account.Name
		}
		participants := make(map[uint64]*Endpoint, len(account.Participants))
		for _, participant := range account.Participants {
			participants[participant.Id] = &Endpoint{
				host: participant.Name,
				port: participant.Port,
			}
		}
		account, err := newDistributedAccount(w, uuid, name, pubKey, compositePubKey, account.SigningThreshold, participants, 1)
		if err != nil {
			return nil, errors.Wrap(err, "failed to instantiate account")
		}
		accounts = append(accounts, account)
	}
	return accounts, nil
}

// Unlock unlocks an account.
func (w *wallet) UnlockAccount(ctx context.Context, accountName string, passphrase []byte) (bool, error) {
	connResource, err := w.ObtainConnection(ctx, w.endpoints[0])
	if err != nil {
		return false, errors.Wrap(err, "failed to connect to endpoint")
	}
	defer connResource.Release()

	accountManagerClient := pb.NewAccountManagerClient(connResource.Value().(*grpc.ClientConn))
	req := &pb.UnlockAccountRequest{
		Account:    fmt.Sprintf("%s/%s", w.Name(), accountName),
		Passphrase: passphrase,
	}
	resp, err := accountManagerClient.Unlock(ctx, req)
	if err != nil {
		return false, errors.Wrap(err, "failed to access dirk")
	}
	if resp.State == pb.ResponseState_FAILED {
		return false, errors.New("request to unlock account failed")
	}
	return resp.State == pb.ResponseState_SUCCEEDED, nil
}

// Lock locks an account.
func (w *wallet) LockAccount(ctx context.Context, accountName string) error {
	connResource, err := w.ObtainConnection(ctx, w.endpoints[0])
	if err != nil {
		return errors.Wrap(err, "failed to connect to endpoint")
	}
	defer connResource.Release()

	accountManagerClient := pb.NewAccountManagerClient(connResource.Value().(*grpc.ClientConn))
	req := &pb.LockAccountRequest{
		Account: fmt.Sprintf("%s/%s", w.Name(), accountName),
	}
	resp, err := accountManagerClient.Lock(ctx, req)
	if err != nil {
		return errors.Wrap(err, "failed to access dirk")
	}
	if resp.State == pb.ResponseState_FAILED {
		return errors.New("request to lock account failed")
	}
	return nil
}

// SignGRPC signs data over GRPC.
func (a *account) SignGRPC(ctx context.Context,
	root []byte,
	domain []byte) (e2types.Signature, error) {

	if len(root) != 32 {
		return nil, errors.New("data must be 32 bytes in length")
	}

	req := &pb.SignRequest{
		Id:     &pb.SignRequest_Account{Account: fmt.Sprintf("%s/%s", a.wallet.Name(), a.Name())},
		Data:   root,
		Domain: domain,
	}

	connResource, err := a.wallet.ObtainConnection(ctx, a.wallet.endpoints[0])
	if err != nil {
		return nil, errors.Wrap(err, "failed to connect to endpoint")
	}
	defer connResource.Release()

	client := pb.NewSignerClient(connResource.Value().(*grpc.ClientConn))
	if client == nil {
		return nil, errors.New("failed to set up signing client")
	}
	resp, err := client.Sign(ctx, req)
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain signature")
	}
	if resp.State == pb.ResponseState_FAILED {
		return nil, errors.New("request to obtain signature failed")
	}
	if resp.State == pb.ResponseState_DENIED {
		return nil, errors.New("request to obtain signature denied")
	}

	sig, err := e2types.BLSSignatureFromBytes(resp.Signature)
	if err != nil {
		return nil, errors.Wrap(err, "invalid signature received")
	}
	if sig == nil {
		return nil, fmt.Errorf("no signature received")
	}

	return sig, nil
}

// SignGRPC signs data over GRPC.
func (a *distributedAccount) SignGRPC(ctx context.Context,
	root []byte,
	domain []byte) (e2types.Signature, error) {

	if len(root) != 32 {
		return nil, errors.New("data must be 32 bytes in length")
	}

	req := &pb.SignRequest{
		Id:     &pb.SignRequest_Account{Account: fmt.Sprintf("%s/%s", a.wallet.Name(), a.Name())},
		Data:   root,
		Domain: domain,
	}

	sig, err := a.thresholdSign(ctx, req)
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain signature")
	}

	return sig, nil
}

// SignBeaconProposalGRPC signs a beacon chain proposal over GRPC.
func (a *account) SignBeaconProposalGRPC(ctx context.Context,
	slot uint64,
	proposerIndex uint64,
	parentRoot []byte,
	stateRoot []byte,
	bodyRoot []byte,
	domain []byte) (e2types.Signature, error) {

	req := &pb.SignBeaconProposalRequest{
		Id: &pb.SignBeaconProposalRequest_Account{Account: fmt.Sprintf("%s/%s", a.wallet.Name(), a.Name())},
		Data: &pb.BeaconBlockHeader{
			Slot:          slot,
			ProposerIndex: proposerIndex,
			ParentRoot:    parentRoot,
			StateRoot:     stateRoot,
			BodyRoot:      bodyRoot,
		},
		Domain: domain,
	}

	endpoint := a.wallet.endpoints[0]
	connResource, err := a.wallet.ObtainConnection(ctx, endpoint)
	if err != nil {
		return nil, errors.Wrap(err, "failed to connect to endpoint")
	}
	defer connResource.Release()

	client := pb.NewSignerClient(connResource.Value().(*grpc.ClientConn))
	if client == nil {
		return nil, errors.New("failed to set up signing client")
	}
	resp, err := client.SignBeaconProposal(ctx, req)
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain signature")
	}
	if resp.State == pb.ResponseState_FAILED {
		return nil, errors.New("request to obtain signature failed")
	}
	if resp.State == pb.ResponseState_DENIED {
		return nil, errors.New("request to obtain signature denied")
	}

	sig, err := e2types.BLSSignatureFromBytes(resp.Signature)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("invalid signature received from %v", endpoint))
	}
	if sig == nil {
		return nil, fmt.Errorf("no signature received from %v", endpoint)
	}

	return sig, nil
}

// SignBeaconProposalGRPC signs a beacon chain proposal over GRPC.
func (a *distributedAccount) SignBeaconProposalGRPC(ctx context.Context,
	slot uint64,
	proposerIndex uint64,
	parentRoot []byte,
	stateRoot []byte,
	bodyRoot []byte,
	domain []byte) (e2types.Signature, error) {

	req := &pb.SignBeaconProposalRequest{
		Id: &pb.SignBeaconProposalRequest_Account{Account: fmt.Sprintf("%s/%s", a.wallet.Name(), a.Name())},
		Data: &pb.BeaconBlockHeader{
			Slot:          slot,
			ProposerIndex: proposerIndex,
			ParentRoot:    parentRoot,
			StateRoot:     stateRoot,
			BodyRoot:      bodyRoot,
		},
		Domain: domain,
	}

	sig, err := a.thresholdSignBeaconProposal(ctx, req)
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain signature")
	}

	return sig, nil
}

// SignBeaconAttestationGRPC signs a beacon chain attestation over GRPC.
func (a *account) SignBeaconAttestationGRPC(ctx context.Context,
	slot uint64,
	committeeIndex uint64,
	blockRoot []byte,
	sourceEpoch uint64,
	sourceRoot []byte,
	targetEpoch uint64,
	targetRoot []byte,
	domain []byte) (e2types.Signature, error) {

	req := &pb.SignBeaconAttestationRequest{
		Id: &pb.SignBeaconAttestationRequest_Account{Account: fmt.Sprintf("%s/%s", a.wallet.Name(), a.Name())},
		Data: &pb.AttestationData{
			Slot:            slot,
			CommitteeIndex:  committeeIndex,
			BeaconBlockRoot: blockRoot,
			Source: &pb.Checkpoint{
				Epoch: sourceEpoch,
				Root:  sourceRoot,
			},
			Target: &pb.Checkpoint{
				Epoch: targetEpoch,
				Root:  targetRoot,
			},
		},
		Domain: domain,
	}

	endpoint := a.wallet.endpoints[0]
	connResource, err := a.wallet.ObtainConnection(ctx, endpoint)
	if err != nil {
		return nil, errors.Wrap(err, "failed to connect to endpoint")
	}
	defer connResource.Release()

	client := pb.NewSignerClient(connResource.Value().(*grpc.ClientConn))
	if client == nil {
		return nil, errors.New("failed to set up signing client")
	}
	resp, err := client.SignBeaconAttestation(ctx, req)
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain signature")
	}
	if resp.State == pb.ResponseState_FAILED {
		return nil, errors.New("request to obtain signature failed")
	}
	if resp.State == pb.ResponseState_DENIED {
		return nil, errors.New("request to obtain signature denied")
	}

	sig, err := e2types.BLSSignatureFromBytes(resp.Signature)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("invalid signature received from %v", endpoint))
	}
	if sig == nil {
		return nil, fmt.Errorf("no signature received from %v", endpoint)
	}

	return sig, nil
}

// SignBeaconAttestationGRPC signs a beacon chain attestation over GRPC.
func (a *distributedAccount) SignBeaconAttestationGRPC(ctx context.Context,
	slot uint64,
	committeeIndex uint64,
	blockRoot []byte,
	sourceEpoch uint64,
	sourceRoot []byte,
	targetEpoch uint64,
	targetRoot []byte,
	domain []byte) (e2types.Signature, error) {

	req := &pb.SignBeaconAttestationRequest{
		Id: &pb.SignBeaconAttestationRequest_Account{Account: fmt.Sprintf("%s/%s", a.wallet.Name(), a.Name())},
		Data: &pb.AttestationData{
			Slot:            slot,
			CommitteeIndex:  committeeIndex,
			BeaconBlockRoot: blockRoot,
			Source: &pb.Checkpoint{
				Epoch: sourceEpoch,
				Root:  sourceRoot,
			},
			Target: &pb.Checkpoint{
				Epoch: targetEpoch,
				Root:  targetRoot,
			},
		},
		Domain: domain,
	}

	sig, err := a.thresholdSignBeaconAttestation(ctx, req)
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain signature")
	}

	return sig, nil
}

// GenerateDistributedAccount generates a distributed account.
func (w *wallet) GenerateDistributedAccount(ctx context.Context,
	accountName string,
	participants uint32,
	signingThreshold uint32,
	passphrase []byte) (e2wtypes.Account, error) {
	connResource, err := w.ObtainConnection(ctx, w.endpoints[0])
	if err != nil {
		return nil, errors.Wrap(err, "failed to connect to endpoint")
	}
	defer connResource.Release()

	accountClient := pb.NewAccountManagerClient(connResource.Value().(*grpc.ClientConn))
	req := &pb.GenerateRequest{
		Account:          fmt.Sprintf("%s/%s", w.Name(), accountName),
		Participants:     participants,
		SigningThreshold: signingThreshold,
		Passphrase:       passphrase,
	}
	resp, err := accountClient.Generate(ctx, req)
	if err != nil {
		return nil, errors.Wrap(err, "failed to access dirk")
	}

	if resp.State != pb.ResponseState_SUCCEEDED {
		switch resp.State {
		case pb.ResponseState_DENIED:
			return nil, fmt.Errorf("Generate request denied: %s", resp.Message)
		case pb.ResponseState_FAILED:
			return nil, fmt.Errorf("Generate request failed: %s", resp.Message)
		default:
			return nil, fmt.Errorf("Generate request failed: %s", resp.Message)
		}
	}

	// Fetch the account to ensure it has been created.
	accountList, err := w.List(ctx, accountName)
	if err != nil {
		return nil, errors.New("failed to confirm created account")
	}
	if len(accountList) == 0 {
		return nil, errors.New("failed to obtain created account")
	}

	return accountList[0], nil
}

// thresholdSign handles signing, with a threshold of responses.
func (a *distributedAccount) thresholdSign(ctx context.Context, req *pb.SignRequest) (e2types.Signature, error) {
	clients := make(map[uint64]pb.SignerClient, len(a.Participants()))

	for id, endpoint := range a.participants {
		connResource, err := a.wallet.ObtainConnection(ctx, endpoint)
		if err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("failed to connect to endpoint %v", endpoint))
		}
		defer connResource.Release()

		clients[id] = pb.NewSignerClient(connResource.Value().(*grpc.ClientConn))
		if clients[id] == nil {
			return nil, errors.New(fmt.Sprintf("failed to set up signing client for %v", endpoint))
		}
	}

	type multiSignResponse struct {
		id   uint64
		resp *pb.SignResponse
	}
	respChannel := make(chan *multiSignResponse, len(clients))

	for id, client := range clients {
		go func(client pb.SignerClient, id uint64, req *pb.SignRequest) {
			resp, err := client.Sign(ctx, req)
			if err == nil {
				respChannel <- &multiSignResponse{
					id:   id,
					resp: resp,
				}
			}
		}(client, id, req)
	}

	// Wait for enough responses (or timeout)
	signed := 0
	denied := 0
	failed := 0
	ids := make([]bls.ID, a.signingThreshold)
	signatures := make([]bls.Sign, a.signingThreshold)
	for signed != int(a.signingThreshold) && signed+denied+failed != len(clients) {
		select {
		case <-ctx.Done():
			return nil, errors.New("context done")
		case resp := <-respChannel:
			switch resp.resp.State {
			case pb.ResponseState_DENIED:
				denied++
			case pb.ResponseState_FAILED:
				failed++
			case pb.ResponseState_SUCCEEDED:
				ids[signed] = *blsID(resp.id)
				if err := signatures[signed].Deserialize(resp.resp.Signature); err != nil {
					return nil, errors.Wrap(err, fmt.Sprintf("invalid signature received from %d", resp.id))
				}
				signed++
			}
		}
	}
	if signed != int(a.signingThreshold) {
		return nil, fmt.Errorf("Not enough signatures: %d signed, %d denied, %d failed", signed, denied, failed)
	}

	var signature bls.Sign
	if err := signature.Recover(signatures, ids); err != nil {
		return nil, errors.Wrap(err, "failed to recover composite signature")
	}

	return e2types.BLSSignatureFromSig(signature)
}

// thresholdSignBeaconAttestation handles signing, with a threshold of responses.
func (a *distributedAccount) thresholdSignBeaconAttestation(ctx context.Context, req *pb.SignBeaconAttestationRequest) (e2types.Signature, error) {
	clients := make(map[uint64]pb.SignerClient, len(a.Participants()))

	for id, endpoint := range a.participants {
		connResource, err := a.wallet.ObtainConnection(ctx, endpoint)
		if err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("failed to connect to endpoint %v", endpoint))
		}
		defer connResource.Release()

		clients[id] = pb.NewSignerClient(connResource.Value().(*grpc.ClientConn))
		if clients[id] == nil {
			return nil, errors.New(fmt.Sprintf("failed to set up signing client for %v", endpoint))
		}
	}

	type multiSignResponse struct {
		id   uint64
		resp *pb.SignResponse
	}
	respChannel := make(chan *multiSignResponse, len(clients))

	for id, client := range clients {
		go func(client pb.SignerClient, id uint64, req *pb.SignBeaconAttestationRequest) {
			resp, err := client.SignBeaconAttestation(ctx, req)
			if err == nil {
				respChannel <- &multiSignResponse{
					id:   id,
					resp: resp,
				}
			}
		}(client, id, req)
	}

	// Wait for enough responses (or timeout)
	signed := 0
	denied := 0
	failed := 0
	ids := make([]bls.ID, a.signingThreshold)
	signatures := make([]bls.Sign, a.signingThreshold)
	for signed != int(a.signingThreshold) && signed+denied+failed != len(clients) {
		select {
		case <-ctx.Done():
			return nil, errors.New("context done")
		case resp := <-respChannel:
			switch resp.resp.State {
			case pb.ResponseState_DENIED:
				denied++
			case pb.ResponseState_FAILED:
				failed++
			case pb.ResponseState_SUCCEEDED:
				ids[signed] = *blsID(resp.id)
				if err := signatures[signed].Deserialize(resp.resp.Signature); err != nil {
					return nil, errors.Wrap(err, fmt.Sprintf("invalid signature received from %d", resp.id))
				}
				signed++
			}
		}
	}
	if signed != int(a.signingThreshold) {
		return nil, fmt.Errorf("Not enough signatures: %d signed, %d denied, %d failed", signed, denied, failed)
	}

	var signature bls.Sign
	if err := signature.Recover(signatures, ids); err != nil {
		return nil, errors.Wrap(err, "failed to recover composite signature")
	}

	return e2types.BLSSignatureFromSig(signature)
}

// thresholdSignBeaconProposal handles signing, with a threshold of responses.
func (a *distributedAccount) thresholdSignBeaconProposal(ctx context.Context, req *pb.SignBeaconProposalRequest) (e2types.Signature, error) {
	clients := make(map[uint64]pb.SignerClient, len(a.Participants()))

	for id, endpoint := range a.participants {
		connResource, err := a.wallet.ObtainConnection(ctx, endpoint)
		if err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("failed to connect to endpoint %v", endpoint))
		}
		defer connResource.Release()

		clients[id] = pb.NewSignerClient(connResource.Value().(*grpc.ClientConn))
		if clients[id] == nil {
			return nil, errors.New(fmt.Sprintf("failed to set up signing client for %v", endpoint))
		}
	}

	type multiSignResponse struct {
		id   uint64
		resp *pb.SignResponse
	}
	respChannel := make(chan *multiSignResponse, len(clients))

	for id, client := range clients {
		go func(client pb.SignerClient, id uint64, req *pb.SignBeaconProposalRequest) {
			resp, err := client.SignBeaconProposal(ctx, req)
			if err == nil {
				respChannel <- &multiSignResponse{
					id:   id,
					resp: resp,
				}
			}
		}(client, id, req)
	}

	// Wait for enough responses (or timeout)
	signed := 0
	denied := 0
	failed := 0
	ids := make([]bls.ID, a.signingThreshold)
	signatures := make([]bls.Sign, a.signingThreshold)
	for signed != int(a.signingThreshold) && signed+denied+failed != len(clients) {
		select {
		case <-ctx.Done():
			return nil, errors.New("context done")
		case resp := <-respChannel:
			switch resp.resp.State {
			case pb.ResponseState_DENIED:
				denied++
			case pb.ResponseState_FAILED:
				failed++
			case pb.ResponseState_SUCCEEDED:
				ids[signed] = *blsID(resp.id)
				if err := signatures[signed].Deserialize(resp.resp.Signature); err != nil {
					return nil, errors.Wrap(err, fmt.Sprintf("invalid signature received from %d", resp.id))
				}
				signed++
			}
		}
	}
	if signed != int(a.signingThreshold) {
		return nil, fmt.Errorf("Not enough signatures: %d signed, %d denied, %d failed", signed, denied, failed)
	}

	var signature bls.Sign
	if err := signature.Recover(signatures, ids); err != nil {
		return nil, errors.Wrap(err, "failed to recover composite signature")
	}

	return e2types.BLSSignatureFromSig(signature)
}

// blsID turns a uint64 in to a BLS identifier.
func blsID(id uint64) *bls.ID {
	var res bls.ID
	buf := [8]byte{}
	binary.LittleEndian.PutUint64(buf[:], id)
	if err := res.SetLittleEndian(buf[:]); err != nil {
		panic(err)
	}
	return &res
}

// ObtainConnection obtains a connection to the required endpoint via GRPC.
// It is possible that all connections are in use, so the context passed to this call should
// have a timeout.
func (w *wallet) ObtainConnection(ctx context.Context, endpoint *Endpoint) (*puddle.Resource, error) {
	w.connsMutex.Lock()
	pool := w.obtainOrCreatePool(fmt.Sprintf("%s:%d", endpoint.host, endpoint.port))
	w.connsMutex.Unlock()

	res, err := pool.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	return res, nil
}

// obtainOrCreatePool obtains or creates a puddle pool to connect to a remote GRPC service.
// Assumes that connsMutex is already held.
func (w *wallet) obtainOrCreatePool(address string) *puddle.Pool {
	pool, exists := w.connectionPools[address]
	if !exists {
		constructor := func(ctx context.Context) (interface{}, error) {
			return grpc.Dial(address, []grpc.DialOption{
				grpc.WithTransportCredentials(w.credentials),
			}...)
		}
		destructor := func(val interface{}) {
			val.(*grpc.ClientConn).Close()
		}
		pool = puddle.NewPool(constructor, destructor, 128)
		w.connectionPools[address] = pool
	}
	return pool
}

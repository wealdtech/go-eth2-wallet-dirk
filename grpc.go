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
	"github.com/pkg/errors"
	pb "github.com/wealdtech/eth2-signer-api/pb/v1"
	e2types "github.com/wealdtech/go-eth2-types/v2"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
	"google.golang.org/grpc/credentials"
)

// ComposeCredentials composes a set of transport credentials given individual certificate and key paths.
// The CA certificate path can be empty.
func ComposeCredentials(ctx context.Context, certPath string, keyPath string, caCertPath string) (credentials.TransportCredentials, error) {
	clientCert, err := ioutil.ReadFile(certPath)
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain client certificate")
	}
	clientKey, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain client key")
	}
	var caCert []byte
	if caCertPath != "" {
		caCert, err = ioutil.ReadFile(caCertPath)
		if err != nil {
			return nil, errors.Wrap(err, "failed to obtain CA certificate")
		}
	}

	return Credentials(ctx, clientCert, clientKey, caCert)
}

// Credentials composes a set of transport credentials given a client certificate and an optional CA certificate.
func Credentials(ctx context.Context, clientCert []byte, clientKey []byte, caCert []byte) (credentials.TransportCredentials, error) {
	clientPair, err := tls.X509KeyPair(clientCert, clientKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to load client keypair")
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{clientPair},
		MinVersion:   tls.VersionTLS13,
	}

	if caCert != nil {
		cp := x509.NewCertPool()
		if !cp.AppendCertsFromPEM(caCert) {
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

	if len(w.endpoints) == 0 {
		return nil, errors.New("wallet has no endpoints")
	}

	conn, release, err := w.connectionProvider.Connection(ctx, w.endpoints[0])
	if err != nil {
		return nil, errors.Wrap(err, "failed to connect to endpoint")
	}
	defer release()

	listerClient := pb.NewListerClient(conn)
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
		return nil, fmt.Errorf("request to list wallet accounts returned state %v", resp.State)
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
	conn, release, err := w.connectionProvider.Connection(ctx, w.endpoints[0])
	if err != nil {
		return false, errors.Wrap(err, "failed to connect to endpoint")
	}
	defer release()

	accountManagerClient := pb.NewAccountManagerClient(conn)
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
	conn, release, err := w.connectionProvider.Connection(ctx, w.endpoints[0])
	if err != nil {
		return errors.Wrap(err, "failed to connect to endpoint")
	}
	defer release()

	accountManagerClient := pb.NewAccountManagerClient(conn)
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

	conn, release, err := a.wallet.connectionProvider.Connection(ctx, a.wallet.endpoints[0])
	if err != nil {
		return nil, errors.Wrap(err, "failed to connect to endpoint")
	}
	defer release()

	client := pb.NewSignerClient(conn)
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
	conn, release, err := a.wallet.connectionProvider.Connection(ctx, endpoint)
	if err != nil {
		return nil, errors.Wrap(err, "failed to connect to endpoint")
	}
	defer release()

	client := pb.NewSignerClient(conn)
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
	conn, release, err := a.wallet.connectionProvider.Connection(ctx, endpoint)
	if err != nil {
		return nil, errors.Wrap(err, "failed to connect to endpoint")
	}
	defer release()

	client := pb.NewSignerClient(conn)
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

// SignBeaconAttestationsGRPC signs multiple beacon chain attestations over GRPC.
func (a *account) SignBeaconAttestationsGRPC(ctx context.Context,
	slot uint64,
	accounts []e2wtypes.Account,
	committeeIndices []uint64,
	blockRoot []byte,
	sourceEpoch uint64,
	sourceRoot []byte,
	targetEpoch uint64,
	targetRoot []byte,
	domain []byte) ([]e2types.Signature, error) {

	req := &pb.SignBeaconAttestationsRequest{
		Requests: make([]*pb.SignBeaconAttestationRequest, len(accounts)),
	}
	for i := range accounts {
		req.Requests[i] = &pb.SignBeaconAttestationRequest{
			Id: &pb.SignBeaconAttestationRequest_Account{Account: fmt.Sprintf("%s/%s", accounts[i].(*account).wallet.Name(), accounts[i].Name())},
			Data: &pb.AttestationData{
				Slot:            slot,
				CommitteeIndex:  committeeIndices[i],
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
	}

	endpoint := a.wallet.endpoints[0]
	conn, release, err := a.wallet.connectionProvider.Connection(ctx, endpoint)
	if err != nil {
		return nil, errors.Wrap(err, "failed to connect to endpoint")
	}
	defer release()

	client := pb.NewSignerClient(conn)
	if client == nil {
		return nil, errors.New("failed to set up signing client")
	}
	resp, err := client.SignBeaconAttestations(ctx, req)
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain signatures")
	}

	sigs := make([]e2types.Signature, len(accounts))
	for i := range resp.Responses {
		if resp.Responses[i].State == pb.ResponseState_FAILED {
			return nil, errors.New("request to obtain signatures failed")
		}
		if resp.Responses[i].State == pb.ResponseState_DENIED {
			return nil, errors.New("request to obtain signatures denied")
		}
		sigs[i], err = e2types.BLSSignatureFromBytes(resp.Responses[i].Signature)
		if err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("invalid signature received from %v", endpoint))
		}
	}

	return sigs, nil
}

// SignBeaconAttestationsGRPC signs multiple beacon chain attestations over GRPC.
func (a *distributedAccount) SignBeaconAttestationsGRPC(ctx context.Context,
	slot uint64,
	accounts []e2wtypes.Account,
	committeeIndices []uint64,
	blockRoot []byte,
	sourceEpoch uint64,
	sourceRoot []byte,
	targetEpoch uint64,
	targetRoot []byte,
	domain []byte) ([]e2types.Signature, error) {

	thresholds := make([]uint32, len(accounts))
	req := &pb.SignBeaconAttestationsRequest{
		Requests: make([]*pb.SignBeaconAttestationRequest, len(accounts)),
	}
	for i := range accounts {
		thresholds[i] = accounts[i].(*distributedAccount).signingThreshold
		req.Requests[i] = &pb.SignBeaconAttestationRequest{
			Id: &pb.SignBeaconAttestationRequest_Account{Account: fmt.Sprintf("%s/%s", accounts[i].(*distributedAccount).wallet.Name(), accounts[i].Name())},
			Data: &pb.AttestationData{
				Slot:            slot,
				CommitteeIndex:  committeeIndices[i],
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
	}

	sigs, err := a.thresholdSignBeaconAttestations(ctx, req, thresholds)
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain signatures")
	}

	return sigs, nil
}

// GenerateDistributedAccount generates a distributed account.
func (w *wallet) GenerateDistributedAccount(ctx context.Context,
	accountName string,
	participants uint32,
	signingThreshold uint32,
	passphrase []byte) (e2wtypes.Account, error) {
	conn, release, err := w.connectionProvider.Connection(ctx, w.endpoints[0])
	if err != nil {
		return nil, errors.Wrap(err, "failed to connect to endpoint")
	}
	defer release()

	accountClient := pb.NewAccountManagerClient(conn)
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
			return nil, fmt.Errorf("generate request denied: %s", resp.Message)
		case pb.ResponseState_FAILED:
			return nil, fmt.Errorf("generate request failed: %s", resp.Message)
		default:
			return nil, fmt.Errorf("generate request failed: %s", resp.Message)
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
		conn, release, err := a.wallet.connectionProvider.Connection(ctx, endpoint)
		if err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("failed to connect to endpoint %v", endpoint))
		}
		defer release()

		clients[id] = pb.NewSignerClient(conn)
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
		return nil, fmt.Errorf("not enough signatures: %d signed, %d denied, %d failed", signed, denied, failed)
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
		conn, release, err := a.wallet.connectionProvider.Connection(ctx, endpoint)
		if err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("failed to connect to endpoint %v", endpoint))
		}
		defer release()

		clients[id] = pb.NewSignerClient(conn)
		if clients[id] == nil {
			return nil, errors.New(fmt.Sprintf("failed to set up signing client for %v", endpoint))
		}
	}

	type thresholdSignResponse struct {
		id   uint64
		resp *pb.SignResponse
	}
	respChannel := make(chan *thresholdSignResponse, len(clients))
	errChannel := make(chan error, len(clients))

	for id, client := range clients {
		go func(client pb.SignerClient, id uint64, req *pb.SignBeaconAttestationRequest) {
			resp, err := client.SignBeaconAttestation(ctx, req)
			if err != nil {
				errChannel <- err
			} else {
				respChannel <- &thresholdSignResponse{
					id:   id,
					resp: resp,
				}
			}
		}(client, id, req)
	}

	// Wait for enough responses (or context done).
	signed := 0
	denied := 0
	failed := 0
	errored := 0
	ids := make([]bls.ID, a.signingThreshold)
	signatures := make([]bls.Sign, a.signingThreshold)
	for signed != int(a.signingThreshold) && signed+denied+failed+errored != len(clients) {
		select {
		case <-ctx.Done():
			return nil, errors.New("context done")
		case <-errChannel:
			errored++
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
		return nil, fmt.Errorf("not enough signatures: %d signed, %d denied, %d failed, %d errored", signed, denied, failed, errored)
	}

	var signature bls.Sign
	if err := signature.Recover(signatures, ids); err != nil {
		return nil, errors.Wrap(err, "failed to recover composite signature")
	}

	return e2types.BLSSignatureFromSig(signature)
}

// thresholdSignBeaconAttestations handles signing, with a threshold of responses.
func (a *distributedAccount) thresholdSignBeaconAttestations(ctx context.Context, req *pb.SignBeaconAttestationsRequest, thresholds []uint32) ([]e2types.Signature, error) {
	clients := make(map[uint64]pb.SignerClient, len(a.Participants()))

	for id, endpoint := range a.participants {
		conn, release, err := a.wallet.connectionProvider.Connection(ctx, endpoint)
		if err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("failed to connect to endpoint %v", endpoint))
		}
		defer release()

		clients[id] = pb.NewSignerClient(conn)
		if clients[id] == nil {
			return nil, errors.New(fmt.Sprintf("failed to set up signing client for %v", endpoint))
		}
	}

	type thresholdSignResponse struct {
		id   uint64
		resp *pb.MultisignResponse
	}
	respChannel := make(chan *thresholdSignResponse, len(clients))
	errChannel := make(chan error, len(clients))

	for id, client := range clients {
		go func(client pb.SignerClient, id uint64, req *pb.SignBeaconAttestationsRequest) {
			resp, err := client.SignBeaconAttestations(ctx, req)
			if err != nil {
				errChannel <- err
			} else {
				respChannel <- &thresholdSignResponse{
					id:   id,
					resp: resp,
				}
			}
		}(client, id, req)
	}

	// Wait for enough responses (or context done).
	responses := 0
	denied := make([]int, len(thresholds))
	failed := make([]int, len(thresholds))
	ids := make([][]bls.ID, len(thresholds))
	signatures := make([][]bls.Sign, len(thresholds))
	for i := range ids {
		ids[i] = make([]bls.ID, 0, len(clients))
		signatures[i] = make([]bls.Sign, 0, len(clients))
	}
	for {
		select {
		case <-ctx.Done():
			return nil, errors.New("context done")
		case <-errChannel:
			responses++
			// log.Warn().Err(err).Msg("Received error from client")
		case resp := <-respChannel:
			responses++
			for i := range resp.resp.Responses {
				switch resp.resp.Responses[i].State {
				case pb.ResponseState_DENIED:
					denied[i]++
				case pb.ResponseState_FAILED:
					failed[i]++
				case pb.ResponseState_SUCCEEDED:
					ids[i] = append(ids[i], *blsID(resp.id))
					var sig bls.Sign
					if err := sig.Deserialize(resp.resp.Responses[i].Signature); err != nil {
						return nil, errors.Wrap(err, fmt.Sprintf("invalid signature received from %d", resp.id))
					}
					signatures[i] = append(signatures[i], sig)
				}
			}
		}

		// See if we have enough successful reponses for all requests.
		if responses == len(clients) {
			// We have all the responses; done by definition.
			break
		}

		// We could be done early if we have enough signatures.
		done := true
		for i := range ids {
			if len(ids[i]) != int(thresholds[i]) {
				done = false
				break
			}
		}
		if done {
			break
		}
	}

	res := make([]e2types.Signature, len(thresholds))
	var err error
	for i := range ids {
		var signature bls.Sign
		if err := signature.Recover(signatures[i][0:a.signingThreshold], ids[i][0:a.signingThreshold]); err != nil {
			return nil, errors.Wrap(err, "failed to recover composite signature")
		}
		res[i], err = e2types.BLSSignatureFromSig(signature)
		if err != nil {
			return nil, errors.Wrap(err, "failed to instantiate signature")
		}
	}

	return res, nil
}

// thresholdSignBeaconProposal handles signing, with a threshold of responses.
func (a *distributedAccount) thresholdSignBeaconProposal(ctx context.Context, req *pb.SignBeaconProposalRequest) (e2types.Signature, error) {
	clients := make(map[uint64]pb.SignerClient, len(a.Participants()))

	for id, endpoint := range a.participants {
		conn, release, err := a.wallet.connectionProvider.Connection(ctx, endpoint)
		if err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("failed to connect to endpoint %v", endpoint))
		}
		defer release()

		clients[id] = pb.NewSignerClient(conn)
		if clients[id] == nil {
			return nil, errors.New(fmt.Sprintf("failed to set up signing client for %v", endpoint))
		}
	}

	type multiSignResponse struct {
		id   uint64
		resp *pb.SignResponse
	}
	respChannel := make(chan *multiSignResponse, len(clients))
	errChannel := make(chan error, len(clients))

	for id, client := range clients {
		go func(client pb.SignerClient, id uint64, req *pb.SignBeaconProposalRequest) {
			resp, err := client.SignBeaconProposal(ctx, req)
			if err != nil {
				errChannel <- err
			} else {
				respChannel <- &multiSignResponse{
					id:   id,
					resp: resp,
				}
			}
		}(client, id, req)
	}

	// Wait for enough responses (or context done).
	signed := 0
	denied := 0
	failed := 0
	errored := 0
	ids := make([]bls.ID, a.signingThreshold)
	signatures := make([]bls.Sign, a.signingThreshold)
	for signed != int(a.signingThreshold) && signed+denied+failed+errored != len(clients) {
		select {
		case <-ctx.Done():
			return nil, errors.New("context done")
		case <-errChannel:
			errored++
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
		return nil, fmt.Errorf("not enough signatures: %d signed, %d denied, %d failed, %d errored", signed, denied, failed, errored)
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

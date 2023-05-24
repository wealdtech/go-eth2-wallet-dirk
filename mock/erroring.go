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
	"errors"

	pb "github.com/wealdtech/eth2-signer-api/pb/v1"
)

// ErroringService is a mock service that returns errors.
type ErroringService struct{}

// Sign returns an error.
func (s *ErroringService) Sign(_ context.Context, _ *pb.SignRequest) (*pb.SignResponse, error) {
	return &pb.SignResponse{
		State: pb.ResponseState_UNKNOWN,
	}, errors.New("mock error")
}

// SignBeaconAttestation returns an error.
func (s *ErroringService) SignBeaconAttestation(_ context.Context, _ *pb.SignBeaconAttestationRequest) (*pb.SignResponse, error) {
	return &pb.SignResponse{
		State: pb.ResponseState_UNKNOWN,
	}, errors.New("mock error")
}

// SignBeaconAttestations returns an error.
func (s *ErroringService) SignBeaconAttestations(_ context.Context,
	in *pb.SignBeaconAttestationsRequest,
) (
	*pb.MultisignResponse,
	error,
) {
	responses := make([]*pb.SignResponse, len(in.Requests))
	for i := range responses {
		responses[i] = &pb.SignResponse{
			State: pb.ResponseState_UNKNOWN,
		}
	}

	return &pb.MultisignResponse{
		Responses: responses,
	}, errors.New("mock error")
}

// SignBeaconProposal returns an error.
func (s *ErroringService) SignBeaconProposal(_ context.Context, _ *pb.SignBeaconProposalRequest) (*pb.SignResponse, error) {
	return &pb.SignResponse{
		State: pb.ResponseState_UNKNOWN,
	}, errors.New("mock error")
}

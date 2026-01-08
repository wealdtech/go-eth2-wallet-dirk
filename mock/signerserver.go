// Copyright © 2026 Weald Technology Trading.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package dirk provides mock implementations for testing.
package dirk

import (
	"context"
	"fmt"
	"strings"
	"sync"

	pb "github.com/wealdtech/eth2-signer-api/pb/v1"
)

// MockSignerServer tracks which endpoints are used for signing operations.
type MockSignerServer struct {
	pb.UnimplementedSignerServer

	endpointsUsed   []string
	mutex           sync.Mutex
	allowedAccounts map[string]bool // set of allowed account names (without wallet prefix)
}

// NewMockSignerServer creates a new mock signer server.
func NewMockSignerServer() *MockSignerServer {
	return &MockSignerServer{
		endpointsUsed:   make([]string, 0),
		allowedAccounts: make(map[string]bool),
	}
}

// NewMockSignerServerWithAccounts creates a new mock signer server that only accepts specific accounts.
func NewMockSignerServerWithAccounts(allowedAccounts []string) *MockSignerServer {
	server := NewMockSignerServer()
	for _, account := range allowedAccounts {
		server.allowedAccounts[account] = true
	}

	return server
}

func (s *MockSignerServer) Sign(_ context.Context, req *pb.SignRequest) (*pb.SignResponse, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Extract account name from path (remove wallet prefix)
	accountPath := req.GetAccount()
	// Account paths are like "Test wallet/Account Endpoint1", we want just "Account Endpoint1"
	var accountName string
	if lastSlash := strings.LastIndex(accountPath, "/"); lastSlash >= 0 {
		accountName = accountPath[lastSlash+1:]
	} else {
		accountName = accountPath
	}

	// Check if this account is allowed on this signer server
	if len(s.allowedAccounts) > 0 && !s.allowedAccounts[accountName] {
		return &pb.SignResponse{
			State: pb.ResponseState_FAILED,
		}, fmt.Errorf("account %s not available on this endpoint", accountName)
	}

	// Record the signing request
	s.endpointsUsed = append(s.endpointsUsed, req.GetAccount())

	return &pb.SignResponse{
		State: pb.ResponseState_SUCCEEDED,
		Signature: []byte{
			0x8e, 0x16, 0x21, 0x7c, 0xfb, 0x18, 0xe2, 0xf2, 0xb2, 0xc8, 0x88, 0x5b, 0x02, 0xd7, 0x34, 0x36,
			0x00, 0x69, 0x03, 0xba, 0x77, 0x32, 0x0b, 0x43, 0xa8, 0xcd, 0x7b, 0x60, 0x30, 0xbe, 0x67, 0x94,
			0x95, 0x46, 0x38, 0x1e, 0xfb, 0xd0, 0x9e, 0x8d, 0x21, 0x47, 0x85, 0x5b, 0x05, 0xad, 0x8c, 0xc9,
			0x11, 0x93, 0x33, 0xf4, 0x28, 0x99, 0xaa, 0xf7, 0x45, 0xa7, 0x61, 0x1e, 0x4f, 0xad, 0x52, 0xaa,
			0x08, 0xe6, 0xa2, 0x80, 0xe1, 0xef, 0x4e, 0xf9, 0xc5, 0x3c, 0x42, 0x60, 0x28, 0xca, 0xbf, 0x5b,
			0x45, 0xd7, 0x3c, 0xb5, 0xbc, 0x8c, 0x34, 0x3c, 0xd9, 0x44, 0xa9, 0x99, 0xda, 0x1e, 0x6f, 0x4e,
		},
	}, nil
}

func (s *MockSignerServer) GetEndpointsUsed() []string {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	result := make([]string, len(s.endpointsUsed))
	copy(result, s.endpointsUsed)

	return result
}

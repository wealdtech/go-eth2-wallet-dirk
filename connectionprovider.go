// Copyright © 2020 - 2023 Weald Technology Trading.
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

	"github.com/jackc/puddle/v2"
	"github.com/pkg/errors"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var (
	// connectionPools is a per-address connection pool, to avoid excess connections.
	connectionPools   = make(map[string]*puddle.Pool[*grpc.ClientConn])
	connectionPoolsMu = sync.RWMutex{}
)

// ConnectionProvider is an interface that provides GRPC connections.
type ConnectionProvider interface {
	// Connection returns a connection and release function.
	Connection(ctx context.Context, endpoint *Endpoint) (*grpc.ClientConn, func(), error)
}

// PuddleConnectionProvider provides connections using the Puddle connection pooler.
type PuddleConnectionProvider struct {
	name            string
	poolConnections int32
	credentials     credentials.TransportCredentials
}

// Connection returns a connection and release function.
func (c *PuddleConnectionProvider) Connection(ctx context.Context, endpoint *Endpoint) (*grpc.ClientConn, func(), error) {
	pool := c.obtainOrCreatePool(fmt.Sprintf("%s:%d", endpoint.host, endpoint.port))

	res, err := pool.Acquire(ctx)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to obtain connection")
	}

	return res.Value(), res.Release, nil
}

func (c *PuddleConnectionProvider) obtainOrCreatePool(address string) *puddle.Pool[*grpc.ClientConn] {
	connectionPoolsMu.RLock()
	pool, exists := connectionPools[address]
	connectionPoolsMu.RUnlock()
	if !exists {
		constructor := func(ctx context.Context) (*grpc.ClientConn, error) {
			conn, err := grpc.DialContext(ctx, address, []grpc.DialOption{
				grpc.WithTransportCredentials(c.credentials),
				grpc.WithDefaultCallOptions(
					// Maximum message receive size is 128 MB.
					grpc.MaxCallRecvMsgSize(128 * 1024 * 1024),
					// Use compression if available.
					// Cannot enable unilaterally; need to wait for Dirk server to support this to avoid
					// miscommunication.
					// grpc.UseCompressor(gzip.Name),
				),
				grpc.WithStatsHandler(otelgrpc.NewClientHandler()),
			}...)
			if err != nil {
				return nil, errors.Wrap(err, "failed to construct connection")
			}
			incConnections(address)

			return conn, nil
		}
		destructor := func(val *grpc.ClientConn) {
			val.Close()
			decConnections(address)
		}
		// Ignoring error, can only happen if MaxSize < 1 and we check for this
		// already in parseAndCheckParameters.
		pool, _ = puddle.NewPool(&puddle.Config[*grpc.ClientConn]{
			Constructor: constructor,
			Destructor:  destructor,
			MaxSize:     c.poolConnections,
		})
		connectionPoolsMu.Lock()
		connectionPools[address] = pool
		connectionPoolsMu.Unlock()
	}

	return pool
}

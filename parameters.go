// Copyright © 2022 Weald Technology Trading.
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
	"time"

	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	"google.golang.org/grpc/credentials"
)

type parameters struct {
	logLevel        zerolog.Level
	monitor         Metrics
	timeout         time.Duration
	name            string
	credentials     credentials.TransportCredentials
	endpoints       []*Endpoint
	poolConnections int32
}

// Parameter is the interface for service parameters.
type Parameter interface {
	apply(p *parameters)
}

type parameterFunc func(*parameters)

func (f parameterFunc) apply(p *parameters) {
	f(p)
}

// WithLogLevel sets the log level for the module.
func WithLogLevel(logLevel zerolog.Level) Parameter {
	return parameterFunc(func(p *parameters) {
		p.logLevel = logLevel
	})
}

// WithMonitor sets the monitor for the wallet.
func WithMonitor(monitor Metrics) Parameter {
	return parameterFunc(func(p *parameters) {
		p.monitor = monitor
	})
}

// WithTimeout sets the timeout for wallet requests.
func WithTimeout(timeout time.Duration) Parameter {
	return parameterFunc(func(p *parameters) {
		p.timeout = timeout
	})
}

// WithName sets the name for the wallet.
func WithName(name string) Parameter {
	return parameterFunc(func(p *parameters) {
		p.name = name
	})
}

// WithCredentials sets the transport credentials for the wallet.
func WithCredentials(credentials credentials.TransportCredentials) Parameter {
	return parameterFunc(func(p *parameters) {
		p.credentials = credentials
	})
}

// WithEndpoints sets the endpoints for the wallet.
func WithEndpoints(endpoints []*Endpoint) Parameter {
	return parameterFunc(func(p *parameters) {
		p.endpoints = endpoints
	})
}

// WithPoolConnections sets the number of connections for the wallet connection pool.
func WithPoolConnections(connections int32) Parameter {
	return parameterFunc(func(p *parameters) {
		p.poolConnections = connections
	})
}

// parseAndCheckParameters parses and checks parameters to ensure that mandatory parameters are present and correct.
func parseAndCheckParameters(params ...Parameter) (*parameters, error) {
	parameters := parameters{
		logLevel:        zerolog.GlobalLevel(),
		timeout:         30 * time.Second,
		poolConnections: 128,
		monitor:         &nullMetrics{},
	}
	for _, p := range params {
		if params != nil {
			p.apply(&parameters)
		}
	}

	if parameters.monitor == nil {
		return nil, errors.New("no monitor specified")
	}
	if parameters.timeout == 0 {
		return nil, errors.New("no timeout specified")
	}
	if parameters.name == "" {
		return nil, errors.New("no name specified")
	}
	if parameters.credentials == nil {
		return nil, errors.New("no credentials specified")
	}
	if len(parameters.endpoints) == 0 {
		return nil, errors.New("no endpoints specified")
	}
	if parameters.poolConnections < 1 {
		return nil, errors.New("no pool connections specified")
	}

	return &parameters, nil
}

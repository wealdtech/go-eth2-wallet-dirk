// Copyright © 2022 Weald Technology Limited.
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

	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	connections   *prometheus.GaugeVec
	connectionsMu sync.Mutex
)

func registerMetrics(ctx context.Context, monitor Metrics) error {
	connectionsMu.Lock()
	defer connectionsMu.Unlock()

	if connections != nil {
		// Already registered.
		return nil
	}
	if monitor == nil {
		// No monitor.
		return nil
	}
	if monitor.Presenter() == "prometheus" {
		return registerPrometheusMetrics(ctx)
	}

	return nil
}

func registerPrometheusMetrics(_ context.Context) error {
	if connections == nil {
		connections = prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "dirk",
			Name:      "server_connections",
			Help:      "Connections to remote Dirk servers",
		}, []string{"server"})
		if err := prometheus.Register(connections); err != nil {
			return errors.Wrap(err, "failed to register dirk_server_connections")
		}
	}

	return nil
}

func incConnections(address string) {
	if connections != nil {
		connections.WithLabelValues(address).Inc()
	}
}

func decConnections(address string) {
	if connections != nil {
		connections.WithLabelValues(address).Dec()
	}
}

// Metrics is an interface to a metrics provider.
type Metrics interface {
	// Presenter returns the presenter for the metrics.
	Presenter() string
}

type nullMetrics struct{}

// Presenter returns the presenter for the metrics.
func (m *nullMetrics) Presenter() string {
	return "null"
}

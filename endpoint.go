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

import "fmt"

// Endpoint specifies a host/port tuple.
type Endpoint struct {
	host string
	port uint32
}

// NewEndpoint creates a new endpoint.
func NewEndpoint(host string, port uint32) *Endpoint {
	return &Endpoint{
		host: host,
		port: port,
	}
}

// String implements the stringer interface.
func (e *Endpoint) String() string {
	return fmt.Sprintf("%s:%d", e.host, e.port)
}

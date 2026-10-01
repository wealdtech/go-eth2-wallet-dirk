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
	"testing"

	"github.com/stretchr/testify/require"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

func TestGroupByParticipants(t *testing.T) {
	ovh, ald, tux := NewEndpoint("ovh", 8882), NewEndpoint("alderlake", 8882), NewEndpoint("tuxedo", 8882)
	orderA := map[uint64]*Endpoint{1: ovh, 2: ald, 3: tux}
	orderB := map[uint64]*Endpoint{1: ald, 2: tux, 3: ovh}
	a1 := &distributedAccount{participants: orderA}
	b1 := &distributedAccount{participants: orderB}
	a2 := &distributedAccount{participants: map[uint64]*Endpoint{3: NewEndpoint("tuxedo", 8882), 1: NewEndpoint("ovh", 8882), 2: NewEndpoint("alderlake", 8882)}}
	b2 := &distributedAccount{participants: orderB}

	groups, keys, err := groupByParticipants([]e2wtypes.Account{a1, b1, a2, b2})
	require.NoError(t, err)
	require.Equal(t, [][]int{{0, 2}, {1, 3}}, groups)
	require.True(t, needsParticipantSplit(a1, groups, keys))

	groups, keys, err = groupByParticipants([]e2wtypes.Account{b1, b2})
	require.NoError(t, err)
	require.Equal(t, [][]int{{0, 1}}, groups)
	require.False(t, needsParticipantSplit(b1, groups, keys))
	require.True(t, needsParticipantSplit(a1, groups, keys))
}

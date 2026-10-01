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
	"fmt"
	"slices"
	"strings"

	"github.com/pkg/errors"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

// participantsKey returns a canonical representation of an account's participant ID to endpoint map.
// Threshold recovery uses participant IDs as Lagrange coordinates, so accounts can only share a
// batched threshold request if their maps are identical.
func participantsKey(a *distributedAccount) string {
	ids := make([]uint64, 0, len(a.participants))
	for id := range a.participants {
		ids = append(ids, id)
	}
	slices.Sort(ids)

	var sb strings.Builder
	for _, id := range ids {
		fmt.Fprintf(&sb, "%d=%s;", id, a.participants[id])
	}

	return sb.String()
}

// groupByParticipants returns the indices of accounts grouped by identical participant maps, in
// first-seen order.
func groupByParticipants(accounts []e2wtypes.Account) ([][]int, []string, error) {
	groups := make([][]int, 0, 1)
	keys := make([]string, 0, 1)
	positions := make(map[string]int)
	for i := range accounts {
		account, isAccount := accounts[i].(*distributedAccount)
		if !isAccount {
			return nil, nil, errors.New("account not of required type")
		}
		key := participantsKey(account)
		pos, exists := positions[key]
		if !exists {
			pos = len(groups)
			positions[key] = pos
			groups = append(groups, nil)
			keys = append(keys, key)
		}
		groups[pos] = append(groups[pos], i)
	}

	return groups, keys, nil
}

// needsParticipantSplit reports whether a batch must be split before threshold signing via a.
func needsParticipantSplit(a *distributedAccount, groups [][]int, keys []string) bool {
	if len(groups) > 1 {
		return true
	}

	return len(keys) == 1 && keys[0] != participantsKey(a)
}

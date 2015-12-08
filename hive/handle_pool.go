// Copyright 2015 PLUMgrid
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// vim: set ts=8:sts=8:sw=8:noet

package hive

import (
	"fmt"
	"github.com/willf/bitset"
)

// HandlePool is used to contain a sequential list of integer handles. Storage is a bit set.
type HandlePool struct {
	bitset.BitSet
}

func NewHandlePool(size uint) *HandlePool {
	handles := &HandlePool{}
	// make sure ids is big enough, triggers extendSetMaybe
	handles.Set(size - 1).Clear(size - 1)
	// turn all the bits on
	handles.InPlaceUnion(handles.Complement())
	return handles
}
func (handles *HandlePool) Acquire() (uint, error) {
	handle, ok := handles.NextSet(0)
	if !ok {
		return 0, fmt.Errorf("HandlePool: pool empty")
	}
	handles.Clear(handle)
	return handle + 1, nil
}
func (handles *HandlePool) Release(handle uint) {
	handles.Set(handle - 1)
}

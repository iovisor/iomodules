// Copyright 2016 PLUMgrid
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

package hover

import (
	"fmt"
	"github.com/vishvananda/netlink"
)

type BridgeAdapter struct {
	uuid   string
	name   string
	tags   []string
	perm   uint
	config map[string]interface{}
	link   *netlink.Bridge
}

func (ba *BridgeAdapter) UUID() string   { return ba.uuid }
func (ba *BridgeAdapter) FD() int        { return 0 }
func (ba *BridgeAdapter) Tags() []string { return []string{} }
func (ba *BridgeAdapter) Type() string   { return "bridge" }
func (ba *BridgeAdapter) Name() string   { return ba.name }
func (ba *BridgeAdapter) Perm() uint     { return ba.perm }
func (ba *BridgeAdapter) Close()         {}

func (ba *BridgeAdapter) SetConfig(req createModuleRequest, g Graph, id int) error {
	return nil
}

func (ba *BridgeAdapter) Config() map[string]interface{} {
	return ba.config
}

func (ba *BridgeAdapter) Tables() []map[string]interface{} {
	return []map[string]interface{}{}
}

type BridgeTable struct {
}

func (ba *BridgeAdapter) Table(name string) AdapterTable      { return &BridgeTable{} }
func (table *BridgeTable) ID() string                         { return "0" }
func (table *BridgeTable) Name() string                       { return "" }
func (table *BridgeTable) Config() map[string]interface{}     { return map[string]interface{}{} }
func (table *BridgeTable) Get(key string) (interface{}, bool) { return nil, false }

func (table *BridgeTable) Set(key, val string) error {
	return fmt.Errorf("BridgeTable: Set operation not supported")
}
func (table *BridgeTable) Delete(key string) error {
	return fmt.Errorf("BridgeTable: Delete operation not supported")
}
func (table *BridgeTable) Iter() <-chan AdapterTablePair {
	ch := make(chan AdapterTablePair)
	close(ch)
	return ch
}

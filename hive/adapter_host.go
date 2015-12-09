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
	_ "github.com/vishvananda/netlink"
)

type HostAdapter struct {
	id     string
	handle uint
	name   string
	perm   uint
	config map[string]interface{}
}

func (adapter *HostAdapter) Type() string {
	return "host"
}

func (adapter *HostAdapter) Name() string {
	return adapter.name
}

func (adapter *HostAdapter) Perm() uint {
	return adapter.perm
}

func (adapter *HostAdapter) SetConfig(config map[string]interface{}) error {
	return nil
}

func (adapter *HostAdapter) Config() map[string]interface{} {
	return adapter.config
}

func (adapter *HostAdapter) ID() string {
	return adapter.id
}

func (adapter *HostAdapter) Handle() uint {
	return adapter.handle
}

func (adapter *HostAdapter) Init() error {
	return nil
}

func (adapter *HostAdapter) Close() {
}

func (adapter *HostAdapter) Interfaces() <-chan Interface {
	ch := make(chan Interface)
	close(ch)
	return ch
}
func (adapter *HostAdapter) CreateInterface() (uint, error) {
	return 0, nil
}

func (adapter *HostAdapter) DeleteInterface(id uint) error {
	return nil
}

func (adapter *HostAdapter) Tables() []map[string]interface{} {
	return []map[string]interface{}{}
}

type HostTable struct {
}

func (adapter *HostAdapter) Table(name string) AdapterTable {
	return &HostTable{}
}
func (table *HostTable) ID() string {
	return "0"
}
func (table *HostTable) Name() string {
	return ""
}
func (table *HostTable) Config() map[string]interface{} {
	return map[string]interface{}{}
}
func (table *HostTable) Get(key interface{}) (interface{}, bool) {
	return nil, false
}
func (table *HostTable) Set(key, val interface{}) error {
	return fmt.Errorf("HostAdapter: Set operation not supported")
}
func (table *HostTable) Delete(key interface{}) error {
	return fmt.Errorf("HostAdapter: Delete operation not supported")
}
func (table *HostTable) Iter() <-chan AdapterTablePair {
	ch := make(chan AdapterTablePair)
	close(ch)
	return ch
}

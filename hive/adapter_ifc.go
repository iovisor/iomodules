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

type IfcAdapter struct {
	id     string
	handle uint
	name   string
	perm   uint
	config map[string]interface{}
}

func (adapter *IfcAdapter) Type() string {
	return "interfaces"
}

func (adapter *IfcAdapter) Name() string {
	return adapter.name
}

func (adapter *IfcAdapter) Perm() uint {
	return adapter.perm
}

func (adapter *IfcAdapter) SetConfig(config map[string]interface{}) error {
	return nil
}

func (adapter *IfcAdapter) Config() map[string]interface{} {
	return adapter.config
}

func (adapter *IfcAdapter) ID() string {
	return adapter.id
}

func (adapter *IfcAdapter) Handle() uint {
	return adapter.handle
}

func (adapter *IfcAdapter) Init() error {
	return nil
}

func (adapter *IfcAdapter) Close() {
}

func (adapter *IfcAdapter) Interfaces() <-chan Interface {
	ch := make(chan Interface)
	close(ch)
	return ch
}
func (adapter *IfcAdapter) CreateInterface() (uint, error) {
	return 0, nil
}

func (adapter *IfcAdapter) DeleteInterface(id uint) error {
	return nil
}

func (adapter *IfcAdapter) Tables() []map[string]interface{} {
	return []map[string]interface{}{}
}

type IfcTable struct {
}

func (adapter *IfcAdapter) Table(name string) AdapterTable {
	return &IfcTable{}
}
func (table *IfcTable) ID() string {
	return "0"
}
func (table *IfcTable) Name() string {
	return ""
}
func (table *IfcTable) Config() map[string]interface{} {
	return map[string]interface{}{}
}
func (table *IfcTable) Get(key interface{}) (interface{}, bool) {
	return nil, false
}
func (table *IfcTable) Set(key, val interface{}) error {
	return fmt.Errorf("IfcAdapter: Set operation not supported")
}
func (table *IfcTable) Delete(key interface{}) error {
	return fmt.Errorf("IfcAdapter: Delete operation not supported")
}
func (table *IfcTable) Iter() <-chan AdapterTablePair {
	ch := make(chan AdapterTablePair)
	close(ch)
	return ch
}

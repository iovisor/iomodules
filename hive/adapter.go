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

func NewAdapter(req *createModuleRequest) (Adapter, error) {
	uuid, err := NewUUID4()
	if err != nil {
		return nil, err
	}

	var adapter Adapter
	switch req.ModuleType {
	case "bpf":
		adapter = &BpfAdapter{
			id:     uuid,
			name:   req.DisplayName,
			config: make(map[string]interface{}),
		}
		if err := adapter.SetConfig(req.Config); err != nil {
			return nil, err
		}
	}
	return adapter, nil
}

type Adapter interface {
	ID() string
	Close() error
	Type() string
	Name() string
	Config() map[string]interface{}
	SetConfig(map[string]interface{}) error
	CreateInterface(name string) (string, error)
	DeleteInterface(id string) error
	Tables() []map[string]interface{}
	Table(name string) AdapterTable
}

type AdapterTablePair struct {
	Key   interface{} `json:"key"`
	Value interface{} `json:"value"`
}

type AdapterTable interface {
	ID() string
	Name() string
	Config() map[string]interface{}
	Get(key interface{}) (interface{}, bool)
	Set(key, val interface{}) error
	Delete(key interface{}) error
	Iter() <-chan AdapterTablePair
}

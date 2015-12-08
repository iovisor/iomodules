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

func NewAdapter(req *createModuleRequest, pp *PatchPanel) (adapter Adapter, err error) {
	var (
		id     string
		handle uint
	)
	id, err = NewUUID4()
	if err != nil {
		return
	}
	handle, err = pp.AcquireHandle()
	if err != nil {
		return
	}
	defer func() {
		if err != nil {
			pp.ReleaseHandle(handle)
		}
	}()

	switch req.ModuleType {
	case "bpf":
		a := &BpfAdapter{
			id:         id,
			handle:     handle,
			name:       req.DisplayName,
			config:     make(map[string]interface{}),
			patchPanel: pp,
			interfaces: NewHandlePool(1024),
		}
		if err = a.SetConfig(req.Config); err != nil {
			return
		}
		adapter = a
	}
	return
}

type Adapter interface {
	ID() string
	Handle() uint
	Close()
	Type() string
	Name() string
	Config() map[string]interface{}
	SetConfig(map[string]interface{}) error
	CreateInterface() (uint, error)
	DeleteInterface(id uint) error
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

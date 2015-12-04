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
	"io/ioutil"
)

var (
	patchCode  string
	patchPanel *BpfAdapter
)

type PatchPanel struct {
	adapter *BpfAdapter
}

func NewPatchPanel() (*PatchPanel, error) {
	b, err := ioutil.ReadFile(".patch.c")
	if err != nil {
		return nil, err
	}

	uuid, err := NewUUID4()
	if err != nil {
		return nil, err
	}
	pp := &PatchPanel{}
	pp.adapter = &BpfAdapter{
		id:     uuid,
		name:   "patch",
		config: make(map[string]interface{}),
	}
	pp.adapter.bpf = NewBpfModule(string(b))
	if pp.adapter.bpf == nil {
		return nil, fmt.Errorf("Unable to load patch panel module")
	}
	t := pp.adapter.Table("modules")
	Debug.Println("Patch panel module table loaded\n", t.Config())
	return pp, nil
}

func (p *PatchPanel) Close() {
	p.adapter.Close()
}

func (p *PatchPanel) FD() int {
	return 0
}

func (p *PatchPanel) Connect(a, b Adapter) (string, error) {
	id, err := NewUUID4()
	if err != nil {
		return "", err
	}
	return id, nil
}

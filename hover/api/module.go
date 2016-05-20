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

package api

type ModuleBase struct {
	ModuleType  string                 `json:"module_type"`
	DisplayName string                 `json:"display_name"`
	Tags        []string               `json:"tags"`
	Config      map[string]interface{} `json:"config"`
}
type Module struct {
	ModuleBase
	Id   string `json:"id"`
	Perm string `json:"permissions"`
}

type ModuleTableEntry struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

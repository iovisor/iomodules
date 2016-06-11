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

package models

type Policy struct {
	Id         string `json:"id"`
	SourceEPG  string `json:"sourceepg"`
	SourcePort string `json:"sourceport"`
	DestEPG    string `json:"destepg"`
	DestPort   string `json:"destport"`
	Protocol   string `json:"protocol"`
	Action     string `json:"action"` // action:Allow/Redirect
}

type EndpointEntry struct {
	Id    string `json:"id"`
	Ip    string `json:"ip"`
	EpgId string `json:"epgid"`
}

type InfoEntry struct {
	Id string `json:"id"`
}

type EndpointGroup struct {
	Id     string `json:"id"`
	Epg    string `json:"epg"`
	WireId string `json:"wire-id"`
}

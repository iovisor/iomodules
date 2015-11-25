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

package gbp

import (
	"fmt"
)

type Parameter struct {
	Name  string  `json:"name"`
	Value float64 `json:"int-value"`
}

func (x *Parameter) String() string {
	return fmt.Sprintf("{n=%s v=%d}", x.Name, int(x.Value))
}

type Classifier struct {
	Name           string       `json:"name"`
	ParameterValue []*Parameter `json:"parameter-value"`
	Id             string       `json:"classifier-definition-id"`
}

func (x *Classifier) String() string {
	return fmt.Sprintf("{%s %s %s}", x.Name, x.ParameterValue, x.Id)
}

type Action struct {
	Name  string  `json:"name"`
	Order float64 `json:"order"`
	Id    string  `json:"action-definition-id"`
}

func (x *Action) String() string {
	return fmt.Sprintf("{n=%s o=%d i=%s}", x.Name, int(x.Order), x.Id)
}

type Rule struct {
	Name        string        `json:"name"`
	Classifiers []*Classifier `json:"classifier"`
	Order       float64       `json:"order"`
	Actions     []*Action     `json:"action"`
}

func (x *Rule) String() string {
	return fmt.Sprintf("{n=%s c=%s o=%d a=%s}", x.Name, x.Classifiers, int(x.Order), x.Actions)
}

type PolicyRuleGroup struct {
	TenantId      string  `json:"tenant-id"`
	ContractId    string  `json:"contract-id"`
	SubjectName   string  `json:"subject-name"`
	ResolvedRules []*Rule `json:"resolved-rule"`
}

func (x *PolicyRuleGroup) String() string {
	return fmt.Sprintf("{ti=%s ci=%s sn=%s rr=%s}",
		x.TenantId, x.ContractId, x.SubjectName, x.ResolvedRules)
}

type PolicyRuleGroupConstrained struct {
	PolicyRuleGroups []*PolicyRuleGroup `json:"policy-rule-group"`
}

func (x *PolicyRuleGroupConstrained) String() string {
	return fmt.Sprintf("{prg=%s}", x.PolicyRuleGroups)
}

type Policy struct {
	ConsumerTenantId string                        `json:"consumer-tenant-id"`
	ConsumerEpgId    string                        `json:"consumer-epg-id"`
	ProviderTenantId string                        `json:"provider-tenant-id"`
	ProviderEpgId    string                        `json:"provider-epg-id"`
	PolicyRuleGroups []*PolicyRuleGroupConstrained `json:"policy-rule-group-with-endpoint-constraints"`
}

func (x *Policy) String() string {
	return fmt.Sprintf("{cti=%s cei=%s pti=%s pei=%s prg=%s}",
		x.ConsumerTenantId, x.ConsumerEpgId, x.ProviderTenantId,
		x.ProviderEpgId, x.PolicyRuleGroups)
}

type ResolvedPolicy struct {
	ResolvedPolicies []*Policy `json:"resolved-policy"`
}

func (x *ResolvedPolicy) String() string {
	return fmt.Sprintf("%s", x.ResolvedPolicies)
}

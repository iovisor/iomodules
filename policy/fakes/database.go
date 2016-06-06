// This file was generated by counterfeiter
package fakes

import (
	"sync"

	"github.com/iovisor/iomodules/policy/database"
	"github.com/iovisor/iomodules/policy/models"
	_ "github.com/mattn/go-sqlite3"
)

type Database struct {
	EndpointsStub        func() ([]models.EndpointEntry, error)
	endpointsMutex       sync.RWMutex
	endpointsArgsForCall []struct{}
	endpointsReturns     struct {
		result1 []models.EndpointEntry
		result2 error
	}
	PoliciesStub        func() ([]models.Policy, error)
	policiesMutex       sync.RWMutex
	policiesArgsForCall []struct{}
	policiesReturns     struct {
		result1 []models.Policy
		result2 error
	}
	AddEndpointStub        func(models.EndpointEntry) error
	addEndpointMutex       sync.RWMutex
	addEndpointArgsForCall []struct {
		arg1 models.EndpointEntry
	}
	addEndpointReturns struct {
		result1 error
	}
	AddPolicyStub        func(models.Policy) error
	addPolicyMutex       sync.RWMutex
	addPolicyArgsForCall []struct {
		arg1 models.Policy
	}
	addPolicyReturns struct {
		result1 error
	}
	DeleteEndpointStub        func(EpId string) error
	deleteEndpointMutex       sync.RWMutex
	deleteEndpointArgsForCall []struct {
		EpId string
	}
	deleteEndpointReturns struct {
		result1 error
	}
	DeletePolicyStub        func(PolicyId string) error
	deletePolicyMutex       sync.RWMutex
	deletePolicyArgsForCall []struct {
		PolicyId string
	}
	deletePolicyReturns struct {
		result1 error
	}
	GetPolicyStub        func(PolicyId string) (models.Policy, error)
	getPolicyMutex       sync.RWMutex
	getPolicyArgsForCall []struct {
		PolicyId string
	}
	getPolicyReturns struct {
		result1 models.Policy
		result2 error
	}
	GetEndpointStub        func(EndpointId string) (models.EndpointEntry, error)
	getEndpointMutex       sync.RWMutex
	getEndpointArgsForCall []struct {
		EndpointId string
	}
	getEndpointReturns struct {
		result1 models.EndpointEntry
		result2 error
	}
	GetEndpointByNameStub        func(epg string) (models.EndpointEntry, error)
	getEndpointByNameMutex       sync.RWMutex
	getEndpointByNameArgsForCall []struct {
		epg string
	}
	getEndpointByNameReturns struct {
		result1 models.EndpointEntry
		result2 error
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *Database) Endpoints() ([]models.EndpointEntry, error) {
	fake.endpointsMutex.Lock()
	fake.endpointsArgsForCall = append(fake.endpointsArgsForCall, struct{}{})
	fake.recordInvocation("Endpoints", []interface{}{})
	fake.endpointsMutex.Unlock()
	if fake.EndpointsStub != nil {
		return fake.EndpointsStub()
	} else {
		return fake.endpointsReturns.result1, fake.endpointsReturns.result2
	}
}

func (fake *Database) EndpointsCallCount() int {
	fake.endpointsMutex.RLock()
	defer fake.endpointsMutex.RUnlock()
	return len(fake.endpointsArgsForCall)
}

func (fake *Database) EndpointsReturns(result1 []models.EndpointEntry, result2 error) {
	fake.EndpointsStub = nil
	fake.endpointsReturns = struct {
		result1 []models.EndpointEntry
		result2 error
	}{result1, result2}
}

func (fake *Database) Policies() ([]models.Policy, error) {
	fake.policiesMutex.Lock()
	fake.policiesArgsForCall = append(fake.policiesArgsForCall, struct{}{})
	fake.recordInvocation("Policies", []interface{}{})
	fake.policiesMutex.Unlock()
	if fake.PoliciesStub != nil {
		return fake.PoliciesStub()
	} else {
		return fake.policiesReturns.result1, fake.policiesReturns.result2
	}
}

func (fake *Database) PoliciesCallCount() int {
	fake.policiesMutex.RLock()
	defer fake.policiesMutex.RUnlock()
	return len(fake.policiesArgsForCall)
}

func (fake *Database) PoliciesReturns(result1 []models.Policy, result2 error) {
	fake.PoliciesStub = nil
	fake.policiesReturns = struct {
		result1 []models.Policy
		result2 error
	}{result1, result2}
}

func (fake *Database) AddEndpoint(arg1 models.EndpointEntry) error {
	fake.addEndpointMutex.Lock()
	fake.addEndpointArgsForCall = append(fake.addEndpointArgsForCall, struct {
		arg1 models.EndpointEntry
	}{arg1})
	fake.recordInvocation("AddEndpoint", []interface{}{arg1})
	fake.addEndpointMutex.Unlock()
	if fake.AddEndpointStub != nil {
		return fake.AddEndpointStub(arg1)
	} else {
		return fake.addEndpointReturns.result1
	}
}

func (fake *Database) AddEndpointCallCount() int {
	fake.addEndpointMutex.RLock()
	defer fake.addEndpointMutex.RUnlock()
	return len(fake.addEndpointArgsForCall)
}

func (fake *Database) AddEndpointArgsForCall(i int) models.EndpointEntry {
	fake.addEndpointMutex.RLock()
	defer fake.addEndpointMutex.RUnlock()
	return fake.addEndpointArgsForCall[i].arg1
}

func (fake *Database) AddEndpointReturns(result1 error) {
	fake.AddEndpointStub = nil
	fake.addEndpointReturns = struct {
		result1 error
	}{result1}
}

func (fake *Database) AddPolicy(arg1 models.Policy) error {
	fake.addPolicyMutex.Lock()
	fake.addPolicyArgsForCall = append(fake.addPolicyArgsForCall, struct {
		arg1 models.Policy
	}{arg1})
	fake.recordInvocation("AddPolicy", []interface{}{arg1})
	fake.addPolicyMutex.Unlock()
	if fake.AddPolicyStub != nil {
		return fake.AddPolicyStub(arg1)
	} else {
		return fake.addPolicyReturns.result1
	}
}

func (fake *Database) AddPolicyCallCount() int {
	fake.addPolicyMutex.RLock()
	defer fake.addPolicyMutex.RUnlock()
	return len(fake.addPolicyArgsForCall)
}

func (fake *Database) AddPolicyArgsForCall(i int) models.Policy {
	fake.addPolicyMutex.RLock()
	defer fake.addPolicyMutex.RUnlock()
	return fake.addPolicyArgsForCall[i].arg1
}

func (fake *Database) AddPolicyReturns(result1 error) {
	fake.AddPolicyStub = nil
	fake.addPolicyReturns = struct {
		result1 error
	}{result1}
}

func (fake *Database) DeleteEndpoint(EpId string) error {
	fake.deleteEndpointMutex.Lock()
	fake.deleteEndpointArgsForCall = append(fake.deleteEndpointArgsForCall, struct {
		EpId string
	}{EpId})
	fake.recordInvocation("DeleteEndpoint", []interface{}{EpId})
	fake.deleteEndpointMutex.Unlock()
	if fake.DeleteEndpointStub != nil {
		return fake.DeleteEndpointStub(EpId)
	} else {
		return fake.deleteEndpointReturns.result1
	}
}

func (fake *Database) DeleteEndpointCallCount() int {
	fake.deleteEndpointMutex.RLock()
	defer fake.deleteEndpointMutex.RUnlock()
	return len(fake.deleteEndpointArgsForCall)
}

func (fake *Database) DeleteEndpointArgsForCall(i int) string {
	fake.deleteEndpointMutex.RLock()
	defer fake.deleteEndpointMutex.RUnlock()
	return fake.deleteEndpointArgsForCall[i].EpId
}

func (fake *Database) DeleteEndpointReturns(result1 error) {
	fake.DeleteEndpointStub = nil
	fake.deleteEndpointReturns = struct {
		result1 error
	}{result1}
}

func (fake *Database) DeletePolicy(PolicyId string) error {
	fake.deletePolicyMutex.Lock()
	fake.deletePolicyArgsForCall = append(fake.deletePolicyArgsForCall, struct {
		PolicyId string
	}{PolicyId})
	fake.recordInvocation("DeletePolicy", []interface{}{PolicyId})
	fake.deletePolicyMutex.Unlock()
	if fake.DeletePolicyStub != nil {
		return fake.DeletePolicyStub(PolicyId)
	} else {
		return fake.deletePolicyReturns.result1
	}
}

func (fake *Database) DeletePolicyCallCount() int {
	fake.deletePolicyMutex.RLock()
	defer fake.deletePolicyMutex.RUnlock()
	return len(fake.deletePolicyArgsForCall)
}

func (fake *Database) DeletePolicyArgsForCall(i int) string {
	fake.deletePolicyMutex.RLock()
	defer fake.deletePolicyMutex.RUnlock()
	return fake.deletePolicyArgsForCall[i].PolicyId
}

func (fake *Database) DeletePolicyReturns(result1 error) {
	fake.DeletePolicyStub = nil
	fake.deletePolicyReturns = struct {
		result1 error
	}{result1}
}

func (fake *Database) GetPolicy(PolicyId string) (models.Policy, error) {
	fake.getPolicyMutex.Lock()
	fake.getPolicyArgsForCall = append(fake.getPolicyArgsForCall, struct {
		PolicyId string
	}{PolicyId})
	fake.recordInvocation("GetPolicy", []interface{}{PolicyId})
	fake.getPolicyMutex.Unlock()
	if fake.GetPolicyStub != nil {
		return fake.GetPolicyStub(PolicyId)
	} else {
		return fake.getPolicyReturns.result1, fake.getPolicyReturns.result2
	}
}

func (fake *Database) GetPolicyCallCount() int {
	fake.getPolicyMutex.RLock()
	defer fake.getPolicyMutex.RUnlock()
	return len(fake.getPolicyArgsForCall)
}

func (fake *Database) GetPolicyArgsForCall(i int) string {
	fake.getPolicyMutex.RLock()
	defer fake.getPolicyMutex.RUnlock()
	return fake.getPolicyArgsForCall[i].PolicyId
}

func (fake *Database) GetPolicyReturns(result1 models.Policy, result2 error) {
	fake.GetPolicyStub = nil
	fake.getPolicyReturns = struct {
		result1 models.Policy
		result2 error
	}{result1, result2}
}

func (fake *Database) GetEndpoint(EndpointId string) (models.EndpointEntry, error) {
	fake.getEndpointMutex.Lock()
	fake.getEndpointArgsForCall = append(fake.getEndpointArgsForCall, struct {
		EndpointId string
	}{EndpointId})
	fake.recordInvocation("GetEndpoint", []interface{}{EndpointId})
	fake.getEndpointMutex.Unlock()
	if fake.GetEndpointStub != nil {
		return fake.GetEndpointStub(EndpointId)
	} else {
		return fake.getEndpointReturns.result1, fake.getEndpointReturns.result2
	}
}

func (fake *Database) GetEndpointCallCount() int {
	fake.getEndpointMutex.RLock()
	defer fake.getEndpointMutex.RUnlock()
	return len(fake.getEndpointArgsForCall)
}

func (fake *Database) GetEndpointArgsForCall(i int) string {
	fake.getEndpointMutex.RLock()
	defer fake.getEndpointMutex.RUnlock()
	return fake.getEndpointArgsForCall[i].EndpointId
}

func (fake *Database) GetEndpointReturns(result1 models.EndpointEntry, result2 error) {
	fake.GetEndpointStub = nil
	fake.getEndpointReturns = struct {
		result1 models.EndpointEntry
		result2 error
	}{result1, result2}
}

func (fake *Database) GetEndpointByName(epg string) (models.EndpointEntry, error) {
	fake.getEndpointByNameMutex.Lock()
	fake.getEndpointByNameArgsForCall = append(fake.getEndpointByNameArgsForCall, struct {
		epg string
	}{epg})
	fake.recordInvocation("GetEndpointByName", []interface{}{epg})
	fake.getEndpointByNameMutex.Unlock()
	if fake.GetEndpointByNameStub != nil {
		return fake.GetEndpointByNameStub(epg)
	} else {
		return fake.getEndpointByNameReturns.result1, fake.getEndpointByNameReturns.result2
	}
}

func (fake *Database) GetEndpointByNameCallCount() int {
	fake.getEndpointByNameMutex.RLock()
	defer fake.getEndpointByNameMutex.RUnlock()
	return len(fake.getEndpointByNameArgsForCall)
}

func (fake *Database) GetEndpointByNameArgsForCall(i int) string {
	fake.getEndpointByNameMutex.RLock()
	defer fake.getEndpointByNameMutex.RUnlock()
	return fake.getEndpointByNameArgsForCall[i].epg
}

func (fake *Database) GetEndpointByNameReturns(result1 models.EndpointEntry, result2 error) {
	fake.GetEndpointByNameStub = nil
	fake.getEndpointByNameReturns = struct {
		result1 models.EndpointEntry
		result2 error
	}{result1, result2}
}

func (fake *Database) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.endpointsMutex.RLock()
	defer fake.endpointsMutex.RUnlock()
	fake.policiesMutex.RLock()
	defer fake.policiesMutex.RUnlock()
	fake.addEndpointMutex.RLock()
	defer fake.addEndpointMutex.RUnlock()
	fake.addPolicyMutex.RLock()
	defer fake.addPolicyMutex.RUnlock()
	fake.deleteEndpointMutex.RLock()
	defer fake.deleteEndpointMutex.RUnlock()
	fake.deletePolicyMutex.RLock()
	defer fake.deletePolicyMutex.RUnlock()
	fake.getPolicyMutex.RLock()
	defer fake.getPolicyMutex.RUnlock()
	fake.getEndpointMutex.RLock()
	defer fake.getEndpointMutex.RUnlock()
	fake.getEndpointByNameMutex.RLock()
	defer fake.getEndpointByNameMutex.RUnlock()
	return fake.invocations
}

func (fake *Database) recordInvocation(key string, args []interface{}) {
	fake.invocationsMutex.Lock()
	defer fake.invocationsMutex.Unlock()
	if fake.invocations == nil {
		fake.invocations = map[string][][]interface{}{}
	}
	if fake.invocations[key] == nil {
		fake.invocations[key] = [][]interface{}{}
	}
	fake.invocations[key] = append(fake.invocations[key], args)
}

var _ database.Database = new(Database)

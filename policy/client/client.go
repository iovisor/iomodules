package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/iovisor/iomodules/policy/log"
	"github.com/iovisor/iomodules/policy/models"
)

//go: generginkgo bootstrap # set up a new ginkgo suite
type PolicyClient interface {
	AddEndpoint(*models.EndpointEntry) error
	DeleteEndpoint(endpointId string) error
	GetEndpoint(endpointId string) (models.EndpointEntry, error)
	Endpoints() ([]models.EndpointEntry, error)
	AddPolicy(*models.Policy) error
	DeletePolicy(policyId string) error
	GetPolicy(policyId string) (models.Policy, error)
	Policies() ([]models.Policy, error)
	AddEndpointGroup(*models.EndpointGroup) error
	DeleteEndpointGroup(epgId string) error
	GetEndpointGroup(epgId string) (models.EndpointGroup, error)
	EndpointGroups() ([]models.EndpointGroup, error)
}

type policyclient struct {
	client  *http.Client
	baseUrl string
}

func NewClient(baseUrl string) PolicyClient {
	httpclient := &http.Client{}
	return &policyclient{
		client:  httpclient,
		baseUrl: baseUrl,
	}
}

func (p *policyclient) GetObject(url string, responseObj interface{}) (err error) {
	resp, err := p.client.Get(p.baseUrl + url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var body []byte
		if body, err = ioutil.ReadAll(resp.Body); err != nil {
			log.Error.Print(string(body))
		}
		return fmt.Errorf("module server returned %s", resp.Status)
	}
	if responseObj != nil {
		err = json.NewDecoder(resp.Body).Decode(responseObj)
	}
	return nil
}

func (p *policyclient) PostObject(url string, requestObj interface{}, responseObj interface{}) (err error) {
	b, err := json.Marshal(requestObj)
	if err != nil {
		return
	}
	resp, err := p.client.Post(p.baseUrl+url, "application/json", bytes.NewReader(b))
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var body []byte
		if body, err = ioutil.ReadAll(resp.Body); err != nil {
			log.Error.Print(string(body))
		}
		return fmt.Errorf("module server returned %s", resp.Status)
	}
	if responseObj != nil {
		err = json.NewDecoder(resp.Body).Decode(responseObj)
		if err != nil {
			return fmt.Errorf("module server returned %s", resp.Status)
		}
	}
	return nil
}

func (p *policyclient) deleteObject(url string) error {
	req, err := http.NewRequest("DELETE", p.baseUrl+url, nil)
	if err != nil {
		return fmt.Errorf("module server returned: %s", err)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("module server returned: %s", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("module server returned: %s", resp.Status)
	}
	return nil
}

func (p *policyclient) AddEndpoint(endpoint *models.EndpointEntry) error {
	err := p.PostObject("/endpoints/", endpoint, nil)
	if err != nil {
		return fmt.Errorf("Add Endpoint to server %s", err)
	}
	return nil
}

func (p *policyclient) DeleteEndpoint(endpointId string) error {

	err := p.deleteObject("/endpoints/" + endpointId)
	if err != nil {
		return fmt.Errorf("Delete endpoint from server %s", err)
	}
	return nil
}

func (p *policyclient) GetEndpoint(endpointId string) (models.EndpointEntry, error) {
	var endpoint models.EndpointEntry

	err := p.GetObject("/endpoints/"+endpointId, &endpoint)
	if err != nil {
		return endpoint, fmt.Errorf("Get Endpoint from server %s", err)
	}
	return endpoint, nil
}

func (p *policyclient) Endpoints() ([]models.EndpointEntry, error) {
	var epList []models.EndpointEntry
	err := p.GetObject("/endpoints/", &epList)
	if err != nil {
		return epList, fmt.Errorf("Get Endpoint from server %s", err)
	}
	return epList, nil

}

func (p *policyclient) AddPolicy(policy *models.Policy) error {
	err := p.PostObject("/policies/", policy, nil)
	if err != nil {
		return fmt.Errorf("Add policy to server %s", err)
	}
	return nil
}

func (p *policyclient) DeletePolicy(policyId string) error {
	err := p.deleteObject("/policies/" + policyId)
	if err != nil {
		return fmt.Errorf("Delete endpoint from server %s", err)
	}
	return nil
}

func (p *policyclient) GetPolicy(policyId string) (models.Policy, error) {
	var policy models.Policy

	err := p.GetObject("/policies/"+policyId, &policy)
	if err != nil {
		return policy, fmt.Errorf("Get Endpoint from server %s", err)
	}
	return policy, nil
}

func (p *policyclient) Policies() ([]models.Policy, error) {
	var policylist []models.Policy
	err := p.GetObject("/policies/", &policylist)
	if err != nil {
		return policylist, fmt.Errorf("Get policies from server %s", err)
	}
	return policylist, nil
}

func (p *policyclient) AddEndpointGroup(epg *models.EndpointGroup) error {
	err := p.PostObject("/epg/", epg, nil)
	if err != nil {
		return fmt.Errorf("Add epg to server %s", err)
	}
	return nil

}

func (p *policyclient) DeleteEndpointGroup(epgId string) error {
	err := p.deleteObject("/epg/" + epgId)
	if err != nil {
		return fmt.Errorf("Delete endpoint from server %s", err)
	}
	return nil
}

func (p *policyclient) GetEndpointGroup(epgId string) (models.EndpointGroup, error) {
	var epg models.EndpointGroup
	err := p.GetObject("/epg/"+epgId, &epg)
	if err != nil {
		return epg, fmt.Errorf("Get Endpoint from server %s", err)
	}
	return epg, nil
}

func (p *policyclient) EndpointGroups() ([]models.EndpointGroup, error) {
	var epgList []models.EndpointGroup
	err := p.GetObject("/epg/", &epgList)
	if err != nil {
		return epgList, fmt.Errorf("Get Endpoint from server %s", err)
	}
	return epgList, nil
}

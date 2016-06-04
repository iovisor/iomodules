package client

import (
	"bytes"
	"crypto/sha1"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/appc/cni/pkg/skel"
	"github.com/appc/cni/pkg/types"
)

type PolicyClient struct {
	client  *http.Client
	baseUrl string
	//daemonClient *client.DaemonClient
}

func NewClient() *PolicyClient {
	httpclient := &http.Client{}
	//	daemonClient := client.New("http://127.0.0.1:4001", http.DefaultClient)
	p := &PolicyClient{
		client:  httpclient,
		baseUrl: "http://127.0.0.1:5001",
		//	daemonClient: nil,
	}
	return p
}

func ContainertoIf(containerID string) string {
	const maxLength = 15
	hash := sha1.Sum([]byte(containerID))
	return string(base32.StdEncoding.EncodeToString(hash[:])[:maxLength])
}

func (p *PolicyClient) CreateEndpoint(input *skel.CmdArgs) (types.Result, error) {

	//container, err := p.daemonClient.GetContainer(input.ContainerID)
	result := types.Result{}

	//log.Info.Print("input container identifier is", container.IP, container.App)

	//ifname := ContainertoIf(input.ContainerID)

	//obj := &models.EndpointEntry{
	//	Ip:  container.IP,
	//	Epg: container.App,
	//}

	//err = p.PostObject("/endpoints/", obj, nil)
	return result, nil
}

func (p *PolicyClient) PostObject(url string, requestObj interface{}, responseObj interface{}) (err error) {
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
			Error.Print(string(body))
		}
		return fmt.Errorf("module server returned %s", resp.Status)
	}
	if responseObj != nil {
		err = json.NewDecoder(resp.Body).Decode(responseObj)
	}
	return
}

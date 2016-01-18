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
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/iovisor/iomodules/hive"
	"github.com/vishvananda/netlink"
)

var testPolicy = `
{
  "resolved-policy": [
    {
      "consumer-tenant-id": "tenant-red",
      "consumer-epg-id": "clients",
      "provider-tenant-id": "tenant-red",
      "provider-epg-id": "webservers",
      "policy-rule-group-with-endpoint-constraints": [
        {
          "policy-rule-group": [
            {
              "tenant-id": "tenant-red",
              "contract-id": "icmp-http-contract",
              "subject-name": "allow-http-subject",
              "resolved-rule": [
                {
                  "name": "allow-http-rule",
                  "classifier": [
                    {
                      "name": "http-dest",
                      "connection-tracking": "normal",
                      "parameter-value": [
                        {
                          "name": "destport",
                          "int-value": 5001
                        },
                        {
                          "name": "proto",
                          "int-value": 6
                        }
                      ],
                      "direction": "in",
                      "classifier-definition-id": "Classifier-L4"
                    },
                    {
                      "name": "http-src",
                      "connection-tracking": "normal",
                      "parameter-value": [
                        {
                          "name": "proto",
                          "int-value": 6
                        },
                        {
                          "name": "sourceport",
                          "int-value": 5001
                        }
                      ],
                      "direction": "out",
                      "classifier-definition-id": "Classifier-L4"
                    }
                  ],
                  "order": 0,
                  "action": [
                    {
                      "name": "allow1",
                      "order": 0,
                      "action-definition-id": "Action-Allow"
                    }
                  ]
                }
              ]
            },
            {
              "tenant-id": "tenant-red",
              "contract-id": "icmp-http-contract",
              "subject-name": "allow-icmp-subject",
              "resolved-rule": [
                {
                  "name": "allow-icmp-rule",
                  "classifier": [
                    {
                      "name": "icmp",
                      "connection-tracking": "normal",
                      "parameter-value": [
                        {
                          "name": "proto",
                          "int-value": 1
                        }
                      ],
                      "direction": "bidirectional",
                      "classifier-definition-id": "Classifier-IP-Protocol"
                    }
                  ],
                  "order": 0,
                  "action": [
                    {
                      "name": "allow1",
                      "order": 0,
                      "action-definition-id": "Action-Allow"
                    }
                  ]
                }
              ]
            }
          ]
        }
      ]
    }
  ]
}
`

type testCase struct {
	url  string    // url of the request
	body io.Reader // body of the request
	code int       // expected pass criteria
}

// this class will mock the request/response of an upstream GBP renderer
type mockUpstream struct {
}

func (m *mockUpstream) handleGet(r *http.Request) routeResponse {
	return notFound()
}

func (m *mockUpstream) handleBasicResolvedPolicy(r *http.Request) routeResponse {
	var rsp ResolvedPolicy
	if err := json.NewDecoder(strings.NewReader(testPolicy)).Decode(&rsp); err != nil {
		panic(err)
	}
	return routeResponse{body: rsp}
}

var basicResolvedPolicyUri = "/restconf/operational/resolved-policy:resolved-policies/resolved-policy/tenant-red/clients/tenant-red/webservers"

func newMockUpstream() http.Handler {
	mock := &mockUpstream{}

	rtr := mux.NewRouter()
	rtr.Methods("GET").Path("/").HandlerFunc(makeHandler(mock.handleGet))
	rtr.Methods("GET").Path(basicResolvedPolicyUri).HandlerFunc(makeHandler(mock.handleBasicResolvedPolicy))
	// TODO: fill in more methods as per the below test cases

	return rtr
}

func TestBasicPolicy(t *testing.T) {
	hiveServer := hive.NewServer()
	defer hiveServer.Close()
	hive := httptest.NewServer(hiveServer.Handler())
	defer hive.Close()
	upstream := httptest.NewServer(newMockUpstream())
	defer upstream.Close()
	g, err := NewServer(upstream.URL, hive.URL)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(g.Handler())
	defer srv.Close()
	testValues := []testCase{
		{
			url:  srv.URL + "/policies/",
			body: strings.NewReader(`{"resolved-policy-uri": "` + basicResolvedPolicyUri + `"}`),
			code: http.StatusOK,
		},
	}
	for _, test := range testValues {
		testOne(t, test, nil)
	}
}

var dockerSetup string = `
images=(gliderlabs/alpine moutten/iperf)
for i in ${images[@]}; do
  [[ $(docker images -q $i) != "" ]] || docker pull $i
done
`

func runCommand(cmd string, input io.Reader) (out string, err error) {
	cmds := strings.Split(cmd, " ")
	c := exec.Command(cmds[0], cmds[1:]...)
	if input != nil {
		c.Stdin = input
	}
	var outbuf, errbuf bytes.Buffer
	c.Stdout, c.Stderr = &outbuf, &errbuf
	err = c.Run()
	if err != nil {
		Error.Print(errbuf.String())
		return
	}
	out = strings.TrimSpace(outbuf.String())
	return
}

func startCommand(t *testing.T, cmd string) (*exec.Cmd, *io.PipeWriter, *bytes.Buffer) {
	out := &bytes.Buffer{}
	rpipe, wpipe := io.Pipe()
	cmds := strings.Split(cmd, " ")
	c := exec.Command(cmds[0], cmds[1:]...)
	c.Stdin, c.Stdout, c.Stderr = rpipe, out, out
	err := c.Start()
	if err != nil {
		t.Fatal(err)
	}
	return c, wpipe, out
}

func runTestCommand(t *testing.T, cmd string, input io.Reader) string {
	out, err := runCommand(cmd, input)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// gatherLinks listens for netlink notifications and collects the list of links
// created during the subscription window.
func gatherLinks(ch <-chan netlink.LinkUpdate) ([]netlink.Link, error) {
	linkSet := make(map[int32]bool)
	timeout := time.After(500 * time.Millisecond)
	Debug.Printf("Waiting for link updates\n")
outer:
	for {
		select {
		case update := <-ch:
			if update.Header.Type == syscall.RTM_NEWLINK {
				if _, ok := update.Link.(*netlink.Veth); ok {
					linkSet[update.Index] = true
				}
			} else if update.Header.Type == syscall.RTM_DELLINK {
				delete(linkSet, update.Index)
			}
		case <-timeout:
			break outer
		}
	}
	links := []netlink.Link{}
	for index, _ := range linkSet {
		l, err := netlink.LinkByIndex(int(index))
		if err == nil {
			links = append(links, l)
		}

	}
	return links, nil
}

func gatherOneLink(t *testing.T, ch <-chan netlink.LinkUpdate) netlink.Link {
	links, err := gatherLinks(ch)
	if err != nil {
		t.Fatal(err)
	}
	if len(links) != 1 {
		t.Fatalf("could not determine veth belonging to container (len == %d)", len(links))
	}
	return links[0]
}

func TestInterfaces(t *testing.T) {
	hiveServer := hive.NewServer()
	defer hiveServer.Close()
	hive := httptest.NewServer(hiveServer.Handler())
	defer hive.Close()
	upstream := httptest.NewServer(newMockUpstream())
	defer upstream.Close()
	g, err := NewServer(upstream.URL, hive.URL)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(g.Handler())
	defer srv.Close()

	// launch one policy dataplane
	testOne(t, testCase{
		url:  srv.URL + "/policies/",
		body: strings.NewReader(`{"resolved-policy-uri": "` + basicResolvedPolicyUri + `"}`),
		code: http.StatusOK,
	}, nil)

	// set up docker prereqs
	runTestCommand(t, "bash -ex", strings.NewReader(dockerSetup))

	// monitor for netlink updates to find docker veth
	ch, done := make(chan netlink.LinkUpdate), make(chan struct{})
	defer close(done)
	if err := netlink.LinkSubscribe(ch, done); err != nil {
		t.Error(err)
	}

	id1, id2 := "TestInterfaces-1", "TestInterfaces-2"
	// spawn one test server process
	runTestCommand(t, "docker run --name="+id1+" -d moutten/iperf", nil)
	defer runCommand("docker rm -f "+id1, nil)

	link1 := gatherOneLink(t, ch)
	testOne(t, testCase{
		url:  fmt.Sprintf("%s/modules/host/interfaces/%s/policies/", hive.URL, link1.Attrs().Name),
		body: strings.NewReader(fmt.Sprintf(`{"module": "%s"}`, g.dataplane.Id())),
		code: http.StatusOK,
	}, nil)

	// find the ip of the test server
	ip1 := runTestCommand(t, "docker inspect -f {{.NetworkSettings.IPAddress}} "+id1, nil)

	// start a test client
	clientCmd, clientStdin, clientOutput := startCommand(t, "docker run -i --name="+id2+" --entrypoint /bin/sh moutten/iperf -ex")
	defer runCommand("docker rm -f "+id2, nil)

	link2 := gatherOneLink(t, ch)

	ip2 := runTestCommand(t, "docker inspect -f {{.NetworkSettings.IPAddress}} "+id2, nil)
	Debug.Printf("ip2=%s\n", ip2)

	testOne(t, testCase{
		url:  fmt.Sprintf("%s/modules/host/interfaces/%s/policies/", hive.URL, link2.Attrs().Name),
		body: strings.NewReader(fmt.Sprintf(`{"module": "%s"}`, g.dataplane.Id())),
		code: http.StatusOK,
	}, nil)

	if err := g.dataplane.AddEndpoint(ip1, "pepsi", "webservers"); err != nil {
		t.Fatal(err)
	}
	if err := g.dataplane.AddEndpoint(ip2, "pepsi", "clients"); err != nil {
		t.Fatal(err)
	}

	Debug.Println("Endpoints:")
	for endpoint := range g.dataplane.Endpoints() {
		Debug.Printf("%v\n", *endpoint)
	}

	clientStdin.Write([]byte("iperf -t 2 -c " + ip1 + "\n"))
	clientStdin.Close()
	if err := clientCmd.Wait(); err != nil {
		Error.Print(clientOutput.String())
		t.Fatal(err)
	}
	Debug.Print(clientOutput.String())
}

func testOne(t *testing.T, test testCase, rsp interface{}) {
	client := &http.Client{}

	resp, err := client.Post(test.url, "application/json", test.body)
	if err != nil {
		panic(err)
	}
	body, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Error(err)
	}
	if resp.StatusCode != test.code {
		t.Errorf("Expected %d, got %d", test.code, resp.StatusCode)
	}
	if rsp != nil {
		if err := json.Unmarshal(body, rsp); err != nil {
			t.Error(err)
		}
	}
}

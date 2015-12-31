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

	"github.com/iovisor/iomodules/hive"
	"github.com/vishvananda/netlink"
)

var testPolicy string = `
{
  "resolved-policies": {
    "resolved-policy": [
      {
        "consumer-tenant-id": "pepsi",
        "consumer-epg-id": "client",
        "provider-tenant-id": "pepsi",
        "provider-epg-id": "web",
        "policy-rule-group-with-endpoint-constraints": [
          {
            "policy-rule-group": [
              {
                "tenant-id": "pepsi",
                "contract-id": "web-client",
                "subject-name": "icmp-subject",
                "resolved-rule": [
                  {
                    "name": "allow-icmp-rule",
                    "classifier": [
                      {
                        "name": "icmp",
                        "parameter-value": [
                          {
                            "name": "proto",
                            "int-value": 1
                          }
                        ],
                        "classifier-definition-id": "icmp-proto"
                      }
                    ],
                    "order": 0,
                    "action": [
                      {
                        "name": "allow1",
                        "order": 0,
                        "action-definition-id": "allow"
                      }
                    ]
                  }
                ]
              },
              {
                "tenant-id": "pepsi",
                "contract-id": "web-client",
                "subject-name": "http-subject",
                "resolved-rule": [
                  {
                    "name": "http-chain-rule-in",
                    "classifier": [
                      {
                        "name": "http-dest",
                        "parameter-value": [
                          {
                            "name": "destport",
                            "int-value": 80
                          },
                          {
                            "name": "proto",
                            "int-value": 6
                          }
                        ],
                        "direction": "in",
                        "classifier-definition-id": "tcp-http-proto"
                      }
                    ],
                    "order": 0,
                    "action": [
                      {
                        "name": "chain1",
                        "parameter-value": [
                          {
                            "name": "sfc-chain-name",
                            "string-value": "SFCGBP"
                          }
                        ],
                        "order": 0,
                        "action-definition-id": "chain"
                      }
                    ]
                  },
                  {
                    "name": "http-chain-rule-out",
                    "classifier": [
                      {
                        "name": "http-src",
                        "parameter-value": [
                          {
                            "name": "proto",
                            "int-value": 6
                          },
                          {
                            "name": "sourceport",
                            "int-value": 80
                          }
                        ],
                        "direction": "out",
                        "classifier-definition-id": "tcp-http-proto"
                      }
                    ],
                    "order": 1,
                    "action": [
                      {
                        "name": "chain1",
                        "parameter-value": [
                          {
                            "name": "sfc-chain-name",
                            "string-value": "SFCGBP"
                          }
                        ],
                        "order": 0,
                        "action-definition-id": "chain"
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
}
`

type testCase struct {
	url  string    // url of the request
	body io.Reader // body of the request
	code int       // expected pass criteria
}

func TestBasicPolicy(t *testing.T) {
	srv := httptest.NewServer(NewServer())
	defer srv.Close()
	testValues := []testCase{
		{
			url:  srv.URL + "/policies/",
			body: strings.NewReader(testPolicy),
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
	hive := httptest.NewServer(hive.NewServer())
	defer hive.Close()
	if err := dataplane.Init(hive.URL); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(NewServer())
	defer srv.Close()

	// launch one policy dataplane
	testOne(t, testCase{
		url:  srv.URL + "/policies/",
		body: strings.NewReader(testPolicy),
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
		url: hive.URL + "/links/",
		body: strings.NewReader(fmt.Sprintf(
			`{"modules": ["host", "%s"], "interfaces": ["%s", ""]}`,
			dataplane.Id(), link1.Attrs().Name)),
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
		url: hive.URL + "/links/",
		body: strings.NewReader(fmt.Sprintf(
			`{"modules": ["host", "%s"], "interfaces": ["%s", ""]}`,
			dataplane.Id(), link2.Attrs().Name)),
		code: http.StatusOK,
	}, nil)

	if err := dataplane.AddEndpoint(ip1, "pepsi", "web"); err != nil {
		t.Fatal(err)
	}
	if err := dataplane.AddEndpoint(ip2, "pepsi", "client"); err != nil {
		t.Fatal(err)
	}

	Debug.Println("Endpoints:")
	for endpoint := range dataplane.Endpoints() {
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

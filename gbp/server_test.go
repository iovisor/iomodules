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
                        "classifier-definition-id": "ip-proto"
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
                        "classifier-definition-id": "4250ab32-e8b8-445a-aebb-e1bd2cdd291f"
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
                        "action-definition-id": "3d886be7-059f-4c4f-bbef-0356bea40933"
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
                        "classifier-definition-id": "4250ab32-e8b8-445a-aebb-e1bd2cdd291f"
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
                        "action-definition-id": "3d886be7-059f-4c4f-bbef-0356bea40933"
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

func runCommand(cmd, input string) (out string, err error) {
	cmds := strings.Split(cmd, " ")
	c := exec.Command(cmds[0], cmds[1:]...)
	if len(input) != 0 {
		c.Stdin = strings.NewReader(input)
	}
	var stdbuf, errbuf bytes.Buffer
	c.Stdout, c.Stderr = &stdbuf, &errbuf
	err = c.Run()
	if err != nil {
		Error.Print(errbuf.String())
		return
	}
	out = strings.TrimSpace(stdbuf.String())
	return
}

func runTestCommand(t *testing.T, cmd, input string) string {
	out, err := runCommand(cmd, input)
	if err != nil {
		t.Error(err)
	}
	return out
}

// gatherLinks listens for netlink notifications and collects the list of links
// created during the subscription window.
func gatherLinks(ch <-chan netlink.LinkUpdate) ([]netlink.Link, error) {
	linkSet := make(map[int32]bool)
	timeout := time.After(200 * time.Millisecond)
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
		t.Error(err)
	}
	if len(links) != 1 {
		t.Error("could not determine veth belonging to container (len == %d)", len(links))
	}
	return links[0]
}

func TestInterfaces(t *testing.T) {
	srv := httptest.NewServer(NewServer())
	defer srv.Close()
	hive := httptest.NewServer(hive.NewServer())
	defer hive.Close()

	// launch one policy dataplane
	testOne(t, testCase{
		url:  srv.URL + "/policies/",
		body: strings.NewReader(testPolicy),
		code: http.StatusOK,
	}, nil)

	// set up docker prereqs
	runTestCommand(t, "bash -ex", dockerSetup)

	// monitor for netlink updates to find docker veth
	ch, done := make(chan netlink.LinkUpdate), make(chan struct{})
	defer close(done)
	if err := netlink.LinkSubscribe(ch, done); err != nil {
		t.Error(err)
	}

	// spawn one test server process
	id1 := runTestCommand(t, "docker run -d moutten/iperf", "")
	defer runCommand("docker rm -f "+id1, "")

	link := gatherOneLink(t, ch)
	Debug.Printf("new docker link %s\n", link.Attrs().Name)

	// find the ip of the test server
	ip1 := runTestCommand(t, "docker inspect -f {{.NetworkSettings.IPAddress}} "+id1, "")

	// start a test client
	Debug.Printf("\n%s", runTestCommand(t, "docker run --rm moutten/iperf iperf -t 2 -c "+ip1, ""))
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

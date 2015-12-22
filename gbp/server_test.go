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
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
	url  string // url of the request
	body string // body of the request
	code int    // expected pass criteria
}

func TestPolicy(t *testing.T) {
	srv := httptest.NewServer(NewServer())
	defer srv.Close()
	testValues := []testCase{
		{
			url:  srv.URL + "/policies/",
			body: testPolicy,
			code: http.StatusOK,
		},
	}
	for _, test := range testValues {
		testOne(t, test, nil)
	}
}

func testOne(t *testing.T, test testCase, rsp interface{}) {
	client := &http.Client{}

	r := strings.NewReader(test.body)
	resp, err := client.Post(test.url, "application/json", r)
	if err != nil {
		panic(err)
	}
	_, err = ioutil.ReadAll(resp.Body)
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

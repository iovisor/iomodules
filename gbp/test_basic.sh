#!/bin/bash

S=gbptest
hivesock=127.0.0.1:5000
gbpsock=127.0.0.1:5001
upstreamsock=127.0.0.1:5002
files=()

tmux has-session -t $S &> /dev/null
if [[ $? == 0 ]]; then
  echo "tmux session $S is already running"
  exit 1
fi

function cleanup() {
  trap - EXIT
  for f in ${files[@]}; do
    rm -f $f
  done
  tmux kill-session -t gbptest
  docker rm -f gbptest1 gbptest2
}

trap cleanup EXIT

tmux new-session -s $S -n "source" -d
tmux new-window -t $S:1 -n "hived"
tmux new-window -t $S:2 -n "upstream"
tmux new-window -t $S:3 -n "gbp"
tmux new-window -t $S:4 -n "test1"
tmux new-window -t $S:5 -n "test2"

# pull and build the dependencies of this test, stop and exit if any one command fails
sleep 20 &
w=$!
tmux send -t $S:0 'go get github.com/iovisor/iomodules/hive/hived; x=$?' C-m
tmux send -t $S:0 'go get github.com/iovisor/iomodules/gbp/gbp; x=$[$x+$?]' C-m
tmux send -t $S:0 'go install github.com/iovisor/iomodules/hive/hived; x=$[$x+$?]' C-m
tmux send -t $S:0 'go install github.com/iovisor/iomodules/gbp/gbp; x=$[$x+$?]' C-m
tmux send -t $S:0 'docker pull gliderlabs/alpine; x=$[$x+$?]' C-m
tmux send -t $S:0 "[[ \$x -eq 0 ]] && kill $w" C-m
wait $w &> /dev/null && { echo "source fetch took too long"; exit 1; }

# Start the hive server, a stub upstream server, and finally the gbp server.
# The upstream server should be replaced with a real GBP implementation.
sleep 10 &
w=$!
tmux send -t $S:1 "sudo -E hived -listen $hivesock" C-m
sleep 1
tmux send -t $S:2 'echo -en "HTTP/1.0 200 OK\r\n\r\n" | nc -l 5002' C-m
tmux send -t $S:2 "kill $w" C-m
sleep 1
tmux send -t $S:3 "gbp -upstream http://$upstreamsock -listen $gbpsock -dataplane http://$hivesock" C-m
sleep 1
wait $w &> /dev/null && { echo "server startup took too long"; exit 1; }

# find the new uuid of the gbp server in the hive db
id=$(http GET 127.0.0.1:5001/info | jq -r .id)
echo $id

links1=$(ip link show | awk -F'[ @\t:]*' '/master docker0/ {print $2}' | sort)
# start two test clients
tmux send -t $S:4 "docker run --rm -ti --name gbptest1 gliderlabs/alpine sh" C-m
sleep 1
links2=$(ip link show | awk -F'[ @\t:]*' '/master docker0/ {print $2}' | sort)
tmux send -t $S:5 "docker run --rm -ti --name gbptest2 gliderlabs/alpine sh" C-m
sleep 1
links3=$(ip link show | awk -F'[ @\t:]*' '/master docker0/ {print $2}' | sort)

oldIFS=$IFS IFS=$'\n\t'
if1=$(comm -3 <(echo "${links1[*]}") <(echo "${links2[*]}") | xargs)
if2=$(comm -3 <(echo "${links2[*]}") <(echo "${links3[*]}") | xargs)
IFS=$oldIFS

ip1=$(docker inspect -f {{.NetworkSettings.IPAddress}} gbptest1)
ip2=$(docker inspect -f {{.NetworkSettings.IPAddress}} gbptest2)
echo $ip1 $ip2
if [[ "$ip1" = "" || "$ip2" = "" ]]; then
  echo "could not determine IPs of test containers"
  exit 1
fi

f=$(mktemp /tmp/gbpserver_XXXXXX.py)
files+=($f)

cat > $f <<'DELIM__'
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
class handler(BaseHTTPRequestHandler):
  def do_GET(self):
    self.send_response(200)
    self.send_header('Content-Type', 'application/json')
    self.end_headers()
    self.wfile.write("""
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
""")
    return

try:
  server = HTTPServer(('', 5002), handler)
  server.serve_forever()
except KeyboardInterrupt:
  server.socket.close()
DELIM__

tmux send -t $S:2 "python2 $f" C-m
echo '{"resolved-policy-uri": "/restconf/operational/resolved-policy:resolved-policies/resolved-policy/tenant-red/clients/tenant-red/webservers"}' | http POST http://$gbpsock/policies/
echo '{"module": "'$id'"}' | http POST http://$hivesock/modules/host/interfaces/$if1/policies/
echo '{"module": "'$id'"}' | http POST http://$hivesock/modules/host/interfaces/$if2/policies/
echo '{"ip": "'$ip1'", "tenant": "tenant-red", "epg": "webservers"}' | http POST http://$gbpsock/endpoints/
echo '{"ip": "'$ip2'", "tenant": "tenant-red", "epg": "clients"}' | http POST http://$gbpsock/endpoints/

read -p "Enter: "

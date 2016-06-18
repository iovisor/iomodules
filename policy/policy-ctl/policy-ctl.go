package main

import (
	"fmt"
	"os"

	"github.com/hokaccha/go-prettyjson"
	"github.com/iovisor/iomodules/policy/client"
	"github.com/iovisor/iomodules/policy/models"
	"github.com/urfave/cli"
)

func main() {
	app := cli.NewApp()
	app.Name = "policy-cli"
	app.EnableBashCompletion = true
	app.Usage = "cli to configure policy iomodule"
	app.Action = func(c *cli.Context) error {
		fmt.Println("IOVisor -- CLI to configure policy iomodule")
		return nil
	}
	app.Commands = []cli.Command{
		{
			Name:  "endpoint-group",
			Usage: "endpoint group commands",
			Subcommands: []cli.Command{
				{
					Name:  "create",
					Usage: "create an endpoint group",
					Action: func(c *cli.Context) error {
						var epg models.EndpointGroup
						epg = models.EndpointGroup{
							Epg:    c.String("endpoint-group-name"),
							WireId: c.String("wire-id"),
						}
						p := client.NewClient("http://localhost:5001")
						err := p.AddEndpointGroup(&epg)
						if err != nil {
							return err
						}
						s, _ := prettyjson.Marshal(epg)
						fmt.Printf("%+v\n", string(s))
						return nil
					},
					Flags: []cli.Flag{
						cli.StringFlag{
							Name:  "endpoint-group-name",
							Value: "",
							Usage: "name identifying endpoint group",
						},
						cli.StringFlag{
							Name:  "wire-id",
							Value: "",
							Usage: "identifier used on the wire",
						},
					},
				},
				{
					Name:  "delete",
					Usage: "delete an endpoint group",
					Action: func(c *cli.Context) error {
						p := client.NewClient("http://localhost:5001")
						err := p.DeleteEndpointGroup(c.String("endpoint-group-id"))
						if err != nil {
							fmt.Println(err)
						}
						return nil
					},
					Flags: []cli.Flag{
						cli.StringFlag{
							Name:  "endpoint-group-id",
							Value: "",
							Usage: "uuid of endpoint group",
						},
					},
				},
				{
					Name:  "show",
					Usage: "show an endpoint group",
					Action: func(c *cli.Context) error {
						p := client.NewClient("http://localhost:5001")
						epg, err := p.GetEndpointGroup(c.String("endpoint-group-id"))
						if err != nil {
							fmt.Println(err)
						}
						s, _ := prettyjson.Marshal(epg)
						fmt.Printf("%+v\n", string(s))
						return nil
					},
					Flags: []cli.Flag{
						cli.StringFlag{
							Name:  "endpoint-group-id",
							Value: "",
							Usage: "uuid of endpoint group",
						},
					},
				},
				{
					Name:  "list",
					Usage: "list endpoint groups",
					Action: func(c *cli.Context) error {
						p := client.NewClient("http://localhost:5001")
						epgs, err := p.EndpointGroups()
						if err != nil {
							fmt.Println(err)
						}
						for _, epg := range epgs {
							s, _ := prettyjson.Marshal(epg)
							fmt.Printf("%+v\n", string(s))
						}
						return nil
					},
				},
			},
		},
		{
			Name:  "endpoint",
			Usage: "endpoint commands",
			Subcommands: []cli.Command{
				{
					Name:  "create",
					Usage: "create an endpoint",
					Action: func(c *cli.Context) error {
						var id string
						p := client.NewClient("http://localhost:5001")
						epgs, _ := p.EndpointGroups()
						for _, epg := range epgs {
							if epg.Epg == c.String("endpoint-group-name") {
								id = epg.Id
							}
						}
						ep := models.EndpointEntry{
							Ip:    c.String("ipaddress"),
							EpgId: id,
						}
						err := p.AddEndpoint(&ep)
						if err != nil {
							fmt.Println(err)
							return err
						}
						s, _ := prettyjson.Marshal(ep)
						fmt.Printf("%+v\n", string(s))
						return err
					},
					Flags: []cli.Flag{
						cli.StringFlag{
							Name:  "endpoint-group-name",
							Value: "",
							Usage: "name of endpoint group",
						},
						cli.StringFlag{
							Name:  "ipaddress",
							Value: "",
							Usage: "ip address identifying endpoint",
						},
					},
				},
				{
					Name:  "delete",
					Usage: "delete an endpoint",
					Action: func(c *cli.Context) error {
						fmt.Println("removed task template: ", c.Args().First())
						p := client.NewClient("http://localhost:5001")
						err := p.DeleteEndpoint(c.String("endpoint-id"))
						if err != nil {
							fmt.Println(err)
						}
						return nil
					},
					Flags: []cli.Flag{
						cli.StringFlag{
							Name:  "endpoint-id",
							Value: "",
							Usage: "uuid of endpoint",
						},
					},
				},
				{
					Name:  "show",
					Usage: "show an endpoint",
					Action: func(c *cli.Context) error {
						p := client.NewClient("http://localhost:5001")
						ep, err := p.GetEndpoint(c.String("endpoint-id"))
						if err != nil {
							fmt.Println(err)
						}
						s, _ := prettyjson.Marshal(ep)
						fmt.Printf("%+v\n", string(s))
						return nil
					},
					Flags: []cli.Flag{
						cli.StringFlag{
							Name:  "endpoint-id",
							Value: "",
							Usage: "uuid of endpoint",
						},
					},
				},
				{
					Name:  "list",
					Usage: "list endpoints",
					Action: func(c *cli.Context) error {
						p := client.NewClient("http://localhost:5001")
						eps, err := p.Endpoints()
						if err != nil {
							fmt.Println(err)
							return err
						}
						for _, e := range eps {
							s, _ := prettyjson.Marshal(e)
							fmt.Printf("%+v\n", string(s))
						}
						return nil
					},
				},
			},
		},
		{
			Name:  "policy-rule",
			Usage: "policy rule commands",
			Subcommands: []cli.Command{
				{
					Name:  "create",
					Usage: "create a policy rule",
					Action: func(c *cli.Context) error {
						var destid, srcid string
						p := client.NewClient("http://localhost:5001")
						epgs, _ := p.EndpointGroups()
						for _, epg := range epgs {
							if epg.Epg == c.String("dest-endpoint-group") {
								destid = epg.Id
							}
							if epg.Epg == c.String("source-endpoint-group") {
								srcid = epg.Id
							}
						}
						policy := models.Policy{
							SourceEPG:  srcid,
							SourcePort: c.String("source-port"),
							DestEPG:    destid,
							DestPort:   c.String("dest-port"),
							Protocol:   c.String("protocol"),
							Action:     c.String("action"),
						}
						err := p.AddPolicy(&policy)
						if err != nil {
							fmt.Println(err)
							return err
						}
						s, _ := prettyjson.Marshal(policy)
						fmt.Printf("%+v\n", string(s))
						return nil
					},
					Flags: []cli.Flag{
						cli.StringFlag{
							Name:  "source-endpoint-group",
							Value: "",
							Usage: "name of source endpoint group",
						},
						cli.StringFlag{
							Name:  "source-port",
							Value: "0",
							Usage: "source port",
						},
						cli.StringFlag{
							Name:  "dest-endpoint-group",
							Value: "",
							Usage: "name of destination endpoint group",
						},
						cli.StringFlag{
							Name:  "dest-port",
							Value: "0",
							Usage: "destination port",
						},
						cli.StringFlag{
							Name:  "protocol",
							Value: "17",
							Usage: "l4 protocol",
						},
						cli.StringFlag{
							Name:  "action",
							Value: "allow",
							Usage: "policy rule action",
						},
					},
				},
				{
					Name:  "delete",
					Usage: "delete a policy rule",
					Action: func(c *cli.Context) error {
						p := client.NewClient("http://localhost:5001")
						err := p.DeletePolicy(c.String("policy-rule-id"))
						if err != nil {
							fmt.Println(err)
							return err
						}
						return nil
					},
					Flags: []cli.Flag{
						cli.StringFlag{
							Name:  "policy-rule-id",
							Value: "",
							Usage: "uuid of policy rule",
						},
					},
				},
				{
					Name:  "show",
					Usage: "show a policy rule",
					Action: func(c *cli.Context) error {
						p := client.NewClient("http://localhost:5001")
						policy, err := p.GetPolicy(c.String("policy-rule-id"))
						if err != nil {
							fmt.Println(err)
							return err
						}
						s, _ := prettyjson.Marshal(policy)
						fmt.Printf("%+v\n", string(s))
						return nil
					},
					Flags: []cli.Flag{
						cli.StringFlag{
							Name:  "policy-rule-id",
							Value: "",
							Usage: "uuid of policy rule",
						},
					},
				},
				{
					Name:  "list",
					Usage: "list policy rule",
					Action: func(c *cli.Context) error {
						p := client.NewClient("http://localhost:5001")
						policies, err := p.Policies()
						if err != nil {
							fmt.Println(err)
							return err
						}
						for _, pl := range policies {
							s, _ := prettyjson.Marshal(pl)
							fmt.Printf("%+v\n", string(s))
						}
						return nil
					},
				},
			},
		},
	}
	app.Run(os.Args)
}

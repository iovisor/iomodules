package main

import (
	"fmt"
	"os"

	"github.com/urfave/cli"
)

func main() {
	app := cli.NewApp()
	app.Name = "policy-cli"
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
						fmt.Println("new task template: ", c.Args().First())
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
						fmt.Println("removed task template: ", c.Args().First())
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
						fmt.Println("removed task template: ", c.Args().First())
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
						fmt.Println("removed task template: ", c.Args().First())
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
						fmt.Println("new task template: ", c.Args().First())
						return nil
					},
					Flags: []cli.Flag{
						cli.StringFlag{
							Name:  "endpoint-group-id",
							Value: "",
							Usage: "uuid of endpoint group",
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
						fmt.Println("removed task template: ", c.Args().First())
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
						fmt.Println("removed task template: ", c.Args().First())
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
						fmt.Println("new task template: ", c.Args().First())
						return nil
					},
					Flags: []cli.Flag{
						cli.StringFlag{
							Name:  "source-endpoint-group-id",
							Value: "",
							Usage: "uuid of source endpoint group",
						},
						cli.StringFlag{
							Name:  "source-port",
							Value: "0",
							Usage: "source port",
						},
						cli.StringFlag{
							Name:  "dest-endpoint-group-id",
							Value: "",
							Usage: "uuid of destination endpoint group",
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
						fmt.Println("removed task template: ", c.Args().First())
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
						fmt.Println("removed task template: ", c.Args().First())
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
						fmt.Println("removed task template: ", c.Args().First())
						return nil
					},
				},
			},
		},
	}
	app.Run(os.Args)
}

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
				},
				{
					Name:  "delete",
					Usage: "delete an endpoint group",
					Action: func(c *cli.Context) error {
						fmt.Println("removed task template: ", c.Args().First())
						return nil
					},
				},
				{
					Name:  "show",
					Usage: "show an endpoint group",
					Action: func(c *cli.Context) error {
						fmt.Println("removed task template: ", c.Args().First())
						return nil
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
				},
				{
					Name:  "delete",
					Usage: "delete an endpoint",
					Action: func(c *cli.Context) error {
						fmt.Println("removed task template: ", c.Args().First())
						return nil
					},
				},
				{
					Name:  "show",
					Usage: "show an endpoint",
					Action: func(c *cli.Context) error {
						fmt.Println("removed task template: ", c.Args().First())
						return nil
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
				},
				{
					Name:  "delete",
					Usage: "delete a policy rule",
					Action: func(c *cli.Context) error {
						fmt.Println("removed task template: ", c.Args().First())
						return nil
					},
				},
				{
					Name:  "show",
					Usage: "show a policy rule",
					Action: func(c *cli.Context) error {
						fmt.Println("removed task template: ", c.Args().First())
						return nil
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

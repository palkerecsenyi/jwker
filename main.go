package main

import (
	"log"
	"os"

	"github.com/palkerecsenyi/jwker/commands"
	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:  "jwker",
		Usage: "A CLI for generating and manipulating JWKs",
		Commands: []*cli.Command{
			{
				Name:    "generate",
				Aliases: []string{"g"},
				Usage:   "Generates a new JWK keypair",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name: "private-output",
						Usage: "File to save JWK to. If not provided, uses stdout.",
						Category: "Private Key Component",
						Required: false,
					},
					&cli.StringFlag{
						Name: "private-format",
						Value: "json",
						Usage: "Format of output. Either 'json' or 'base64'.",
						Category: "Private Key Component",
						Required: false,
					},
					&cli.BoolFlag{
						Name: "public",
						Usage: "If true, will generate a corresponding public JWK.",
						Value: false,
						Category: "Public Key Component",
						Required: false,
					},
					&cli.StringFlag{
						Name: "public-output",
						Usage: "File to save public JWK to. If not provided, uses stdout (appending to the end of the private output, separated by a newline).",
						Category: "Public Key Component",
						Required: false,
					},
					&cli.StringFlag{
						Name: "public-format",
						Value: "json",
						Usage: "Format of output for public JWK. Either 'json' or 'base64'.",
						Category: "Public Key Component",
						Required: false,
					},
					&cli.StringFlag{
						Name:     "type",
						Value:    "rsa",
						Usage:    "Type of key to generate. Currently only 'rsa'.",
						Required: true,
					},
					&cli.IntFlag{
						Name:     "rsa-bits",
						Value:    2048,
						Usage:    "Bits to use for RSA key (if using RSA).",
						Category: "RSA",
					},
				},
				Action: commands.Generate,
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

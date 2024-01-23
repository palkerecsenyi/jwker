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
		Usage: "Generate and manipulate JWKs. Can output to any format out of 'json', 'base64', 'base64url'.",
		DefaultCommand: "generate",
		EnableBashCompletion: true,
		Commands: []*cli.Command{
			commands.GenerateSpec(),
			commands.WrapSpec(),
			commands.ThumbprintSpec(),
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

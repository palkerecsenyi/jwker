package commands

import (
	"fmt"

	"github.com/palkerecsenyi/jwker/data"
	"github.com/urfave/cli/v2"
)

func thumbprintMethodFlag(name string, required bool) *cli.StringFlag {
	return &cli.StringFlag{
		Name:     name,
		Usage:    "Which thumbprint method to use. One of 'sha256', 'sha512'.",
		Value:    "sha256",
		Required: required,
	}
}

func parseThumbprintMethod(cliInput string) (data.KeyThumbprint, error) {
	switch cliInput {
	case "sha256":
		return data.KeyThumbprintSHA256, nil
	case "sha512":
		return data.KeyThumbprintSHA512, nil
	default:
		return data.KeyThumbprint(-1), fmt.Errorf("unknown key thumbprint: %s", cliInput)
	}
}

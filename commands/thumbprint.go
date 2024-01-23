package commands

import (
	"fmt"

	"github.com/palkerecsenyi/jwker/data"
	"github.com/urfave/cli/v2"
)

func ThumbprintSpec() *cli.Command {
	return &cli.Command{
		Name: "thumbprint",
		Usage: "Generates the base64url-encoded thumbprint of a JWK (RFC 7638).",
		Flags: []cli.Flag{
			thumbprintMethodFlag("method", false),
			&cli.StringFlag{
				Name: "input",
				Usage: "File to get JWK from.",
				Required: true,
			},
		},
		Action: thumbprint,
	}
}

func thumbprint(ctx *cli.Context) error {
	thumbprintMethodString := ctx.String("method")
	inputFile := ctx.String("input")

	thumbprintMethod, err := parseThumbprintMethod(thumbprintMethodString)
	if err != nil {
		return err
	}

	thumbprint, err := data.Thumbprint(data.ThumbprintOptions{
		InputFile: inputFile,
		Method: thumbprintMethod,
	})
	if err != nil {
		return err
	}

	fmt.Println(thumbprint)

	return nil
}

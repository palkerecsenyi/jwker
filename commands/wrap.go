package commands

import (
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/palkerecsenyi/jwker/data"
	"github.com/palkerecsenyi/jwker/util"
	"github.com/urfave/cli/v2"
)

func WrapSpec() *cli.Command {
	return &cli.Command{
		Name:    "wrap",
		Aliases: []string{"w"},
		Usage:   "Wrap one or more existing JWK(s) (public or private) in a JWKS.",
		Flags: []cli.Flag{
			&cli.StringSliceFlag{
				Name:     "input",
				Usage:    "File(s) to input from. Pass multiple times to specify multiple JWKs to include in the JWKS. Files can be JWKS themselves, which will then be merged together.",
				Required: true,
			},
			&cli.StringFlag{
				Name:     "output",
				Usage:    "File to output JWKS to. If not specified, uses stdout.",
				Required: false,
			},
			&cli.StringFlag{
				Name:     "format",
				Value:    "json",
				Usage:    "Format of output for JWKS. See main help for formats.",
				Required: false,
			},
		},
		Action: wrap,
	}
}

func wrap(ctx *cli.Context) error {
	inputFileNames := ctx.StringSlice("input")
	outputJWKS := jwk.NewSet()
	for _, fileName := range inputFileNames {
		jwks, err := data.WrapParseFileIntoJWKs(ctx.Context, fileName)
		if err != nil {
			return err
		}
		for _, singleJwk := range jwks {
			outputJWKS.Add(singleJwk)
		}
	}

	outputJson, err := json.Marshal(outputJWKS)
	if err != nil {
		return fmt.Errorf("marshal output json: %s", err)
	}

	outputFile := ctx.String("output")
	outputFormat := ctx.String("format")
	util.OutputJsonBytesToFile(outputJson, outputFormat, outputFile)
	return nil
}


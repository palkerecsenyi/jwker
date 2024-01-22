package commands

import (
	"fmt"

	"github.com/palkerecsenyi/jwker/data"
	"github.com/palkerecsenyi/jwker/util"
	"github.com/urfave/cli/v2"
)

func GenerateSpec() *cli.Command {
	return &cli.Command{
		Name:    "generate",
		Aliases: []string{"g"},
		Usage:   "Generates a new JWK keypair",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "private-output",
				Usage:    "File to save JWK to. If not provided, uses stdout.",
				Category: "Private Key Component",
				Required: false,
			},
			&cli.StringFlag{
				Name:     "private-format",
				Value:    "json",
				Usage:    "Format of output. See main help for formats.",
				Category: "Private Key Component",
				Required: false,
			},
			&cli.BoolFlag{
				Name:     "private-jwks",
				Value:    false,
				Usage:    "Wrap the private key output in a JWKS",
				Category: "Private Key Component",
				Required: false,
			},
			&cli.BoolFlag{
				Name:     "public",
				Usage:    "If true, will generate a corresponding public JWK.",
				Value:    false,
				Category: "Public Key Component",
				Required: false,
			},
			&cli.StringFlag{
				Name:     "public-output",
				Usage:    "File to save public JWK to. If not provided, uses stdout (appending to the end of the private output, separated by a newline).",
				Category: "Public Key Component",
				Required: false,
			},
			&cli.StringFlag{
				Name:     "public-format",
				Value:    "json",
				Usage:    "Format of output for public JWK. See main help for formats.",
				Category: "Public Key Component",
				Required: false,
			},
			&cli.BoolFlag{
				Name:     "public-jwks",
				Value:    false,
				Usage:    "Wrap the public key output in a JWKS",
				Category: "Public Key Component",
				Required: false,
			},
			&cli.StringFlag{
				Name:  "type",
				Value: "rsa",
				Usage: "Type of key to generate. Currently only 'rsa'.",
			},
			&cli.IntFlag{
				Name:     "rsa-bits",
				Value:    2048,
				Usage:    "Bits to use for RSA key (if using RSA).",
				Category: "RSA",
			},
		},
		Action: generate,
	}
}

func generate(ctx *cli.Context) error {
	keyType := ctx.String("type")
	var keyGen data.KeyGenerator
	switch keyType {
	case "rsa":
		keyGen = data.RSAGenerator{
			Bits: ctx.Int("rsa-bits"),
		}
	}

	privKeyBytes, pubKeyBytes, err := data.Generate(data.KeyGeneratorOptions{
		Generator:               keyGen,
		GeneratePublicComponent: ctx.Bool("public"),
		WrapInJwks: data.OptionForEachComponent{
			Public:  ctx.Bool("public-jwks"),
			Private: ctx.Bool("private-jwks"),
		},
	})
	if err != nil {
		return fmt.Errorf("generate key: %s", err)
	}

	privFormat := ctx.String("private-format")
	privOutput := ctx.String("private-output")
	err = util.OutputJsonBytesToFile(privKeyBytes, privFormat, privOutput)
	if err != nil {
		return fmt.Errorf("private key: %s", err)
	}

	if pubKeyBytes != nil {
		pubFormat := ctx.String("public-format")
		pubOutput := ctx.String("public-output")
		err = util.OutputJsonBytesToFile(pubKeyBytes, pubFormat, pubOutput)
		if err != nil {
			return fmt.Errorf("public key: %s", err)
		}
	}

	return nil
}

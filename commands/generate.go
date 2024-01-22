package commands

import (
	"fmt"

	"github.com/palkerecsenyi/jwker/data"
	"github.com/palkerecsenyi/jwker/util"
	"github.com/urfave/cli/v2"
)

func Generate(ctx *cli.Context) error {
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

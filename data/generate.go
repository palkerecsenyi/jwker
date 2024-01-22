package data

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/jwk"
)

type KeyType int

type KeyGenerator interface {
	GenerateKey() (interface{}, error)
}

type RSAGenerator struct {
	Bits int
}

func (g RSAGenerator) GenerateKey() (interface{}, error) {
	return rsa.GenerateKey(rand.Reader, g.Bits)
}

type KeyGeneratorOptions struct {
	Generator               KeyGenerator
	GeneratePublicComponent bool
	WrapInJwks              OptionForEachComponent
}

func Generate(opt KeyGeneratorOptions) ([]byte, []byte, error) {
	generatedKey, err := opt.Generator.GenerateKey()
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %s", err)
	}

	privJwkKey, err := jwk.New(generatedKey)
	if err != nil {
		return nil, nil, fmt.Errorf("build jwk: %s", err)
	}

	var privKeyToMarshal interface{}
	privKeyToMarshal = privJwkKey
	if opt.WrapInJwks.Private {
		privKeyToMarshal = wrapInJwks(privJwkKey)
	}

	rawPrivJson, err := json.Marshal(privKeyToMarshal)
	if err != nil {
		return nil, nil, fmt.Errorf("stringify jwk: %s", err)
	}

	if opt.GeneratePublicComponent {
		publicJwkKey, err := privJwkKey.PublicKey()
		if err != nil {
			return nil, nil, fmt.Errorf("build public jwk: %s", err)
		}

		var publicKeyToMarshal interface{}
		publicKeyToMarshal = publicJwkKey
		if opt.WrapInJwks.Public {
			publicKeyToMarshal = wrapInJwks(publicJwkKey)
		}

		rawPublicJson, err := json.Marshal(publicKeyToMarshal)
		if err != nil {
			return nil, nil, fmt.Errorf("stringify public jwk: %s", err)
		}

		return rawPrivJson, rawPublicJson, nil
	}

	return rawPrivJson, nil, nil
}

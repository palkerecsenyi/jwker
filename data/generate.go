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

func Generate(generator KeyGenerator, includePublic bool) ([]byte, []byte, error) {
	generatedKey, err := generator.GenerateKey()
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %s", err)
	}

	jwkKey, err := jwk.New(generatedKey)
	if err != nil {
		return nil, nil, fmt.Errorf("build jwk: %s", err)
	}

	rawJson, err := json.Marshal(jwkKey)
	if err != nil {
		return nil, nil, fmt.Errorf("stringify jwk: %s", err)
	}

	if includePublic {
		publicJwkKey, err := jwkKey.PublicKey()
		if err != nil {
			return nil, nil, fmt.Errorf("build public jwk: %s", err)
		}

		rawPublicJson, err := json.Marshal(publicJwkKey)
		if err != nil {
			return nil, nil, fmt.Errorf("stringify public jwk: %s", err)
		}

		return rawJson, rawPublicJson, nil
	}

	return rawJson, nil, nil
}

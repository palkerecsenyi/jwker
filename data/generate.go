package data

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
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

type ECGenerator struct {
	CurveName string
}

func (g ECGenerator) GenerateKey() (interface{}, error) {
	var curve elliptic.Curve
	switch g.CurveName {
	case "P224":
		curve = elliptic.P224()
	case "P256":
		curve = elliptic.P256()
	case "P384":
		curve = elliptic.P384()
	case "P521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unrecognised elliptic curve %s", g.CurveName)
	}

	return ecdsa.GenerateKey(curve, rand.Reader)
}

type OKPGenerator struct {
}

func (g OKPGenerator) GenerateKey() (interface{}, error) {
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	return privKey, err
}

type KeyUsage string

const (
	KeyUsageSignature  KeyUsage = "sig"
	KeyUsageEncryption KeyUsage = "enc"
)

type KeyThumbprint int

const (
	KeyThumbprintSHA256 KeyThumbprint = iota
	KeyThumbprintSHA512
)

type KeyGeneratorOptions struct {
	Generator               KeyGenerator
	GeneratePublicComponent bool
	WrapInJwks              OptionForEachComponent

	Usage              KeyUsage
	IDMethod           string
	IDThumbprintMethod KeyThumbprint
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

	err = privJwkKey.Set("use", string(opt.Usage))
	if err != nil {
		return nil, nil, fmt.Errorf("set key use: %s", err)
	}

	var keyId string
	switch opt.IDMethod {
	case "uuid":
		keyId = uuid.New().String()
	case "thumbprint":
		keyId, err = keyThumbprintId(privJwkKey, opt.IDThumbprintMethod)
		if err != nil {
			return nil, nil, err
		}
	default:
		keyId = opt.IDMethod
	}

	err = privJwkKey.Set("kid", keyId)
	if err != nil {
		return nil, nil, fmt.Errorf("set key ID: %s", err)
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

package data

import (
	"crypto"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/lestrrat-go/jwx/jwk"
)

type OptionForEachComponent struct {
	Public  bool
	Private bool
}

func wrapInJwks(key jwk.Key) jwk.Set {
	newSet := jwk.NewSet()
	newSet.Add(key)
	return newSet
}

func keyThumbprintId(key jwk.Key, method KeyThumbprint) (string, error) {
	var hashMethod crypto.Hash
	switch method {
	case KeyThumbprintSHA256:
		hashMethod = crypto.SHA256
	case KeyThumbprintSHA512:
		hashMethod = crypto.SHA512
	default:
		return "", fmt.Errorf("unsupported key thumbprint method: %d", method)
	}

	thumbprint, err := key.Thumbprint(hashMethod)
	if err != nil {
		return "", fmt.Errorf("generate thumbprint: %s", err)
	}
	return base64.URLEncoding.EncodeToString(thumbprint), nil
}

func jwkSetFromFile(fileName string) (jwk.Set, error) {
	fileContents, err := os.ReadFile(fileName)
	if err != nil {
		return nil, fmt.Errorf("read file %s: %s", fileName, err)
	}

	jwks, err := jwk.Parse(fileContents)
	if err != nil {
		return nil, fmt.Errorf("parse JWK(S) in file %s: %s", fileName, err)
	}

	return jwks, nil
}

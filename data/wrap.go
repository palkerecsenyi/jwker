package data

import (
	"context"
	"fmt"

	"github.com/lestrrat-go/jwx/jwk"
)

func WrapParseFileIntoJWKs(ctx context.Context, fileName string) ([]jwk.Key, error) {
	newJWKS, err := jwkSetFromFile(fileName)
	if err != nil {
		return nil, err
	}

	newJWKSIterator := newJWKS.Iterate(ctx)
	var outputJWKS []jwk.Key
	for newJWKSIterator.Next(ctx) {
		value := newJWKSIterator.Pair().Value
		if jwkValue, ok := value.(jwk.Key); ok {
			outputJWKS = append(outputJWKS, jwkValue)
		} else {
			return nil, fmt.Errorf("parse one of the JWKs in file %s: %s", fileName, err)
		}
	}

	return outputJWKS, nil
}

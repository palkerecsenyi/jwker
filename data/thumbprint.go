package data

import "fmt"

type ThumbprintOptions struct {
	InputFile string
	Method    KeyThumbprint
}

func Thumbprint(opt ThumbprintOptions) (string, error) {
	jwkSet, err := jwkSetFromFile(opt.InputFile)
	if err != nil {
		return "", err
	}

	if jwkSet.Len() != 1 {
		return "", fmt.Errorf("file must contain exactly one JWK. JWK Sets with more than one JWK are not supported.")
	}

	key, ok := jwkSet.Get(0)
	if !ok {
		return "", fmt.Errorf("key at index 0 does not exist")
	}

	thumbprint, err := keyThumbprintId(key, opt.Method)
	if err != nil {
		return "", err
	}

	return thumbprint, nil
}

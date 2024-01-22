package data

import "github.com/lestrrat-go/jwx/jwk"

type OptionForEachComponent struct {
	Public  bool
	Private bool
}

func wrapInJwks(key jwk.Key) jwk.Set {
	newSet := jwk.NewSet()
	newSet.Add(key)
	return newSet
}

package se

import "crypto"

type cryptoSHA256 struct{}

func (cryptoSHA256) HashFunc() crypto.Hash { return crypto.SHA256 }

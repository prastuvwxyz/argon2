package main

import (
	"fmt"

	"github.com/prastuvwxyz/argon2"
)

func main() {
	hash, err := argon2.NewDefault().CreateHash("foo")
	if err != nil {
		panic(err)
	}
	fmt.Printf("hash: %+v\n", string(hash))
	// output -> hash: $argon2id$v=13$m=65536,t=1,p=2$b7ppeoqQ/4q09UeE3r4Qlw$GaksQXaaBOedHC1qhncsxi01AAAYbibUcPMK5qqKfXc

	argon, err := argon2.NewWithHash("$argon2id$v=13$m=65536,t=1,p=2$b7ppeoqQ/4q09UeE3r4Qlw$GaksQXaaBOedHC1qhncsxi01AAAYbibUcPMK5qqKfXc")
	if err != nil {
		panic(err)
	}
	match, err := argon.Match("foo")
	if err != nil {
		panic(err)
	}
	fmt.Printf("match: %+v\n", match)
	// output -> match: true

	match, err = argon.Match("bar")
	if err != nil {
		panic(err)
	}
	fmt.Printf("match: %+v\n", match)
	// output -> match: false
}

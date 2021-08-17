package main

import (
	"fmt"
	"log"

	"github.com/tacotaha/ecc/ecc"
)

func main() {
	g, e, err := ecc.Secp256k1()
	if err != nil {
		log.Fatal(err)
	}

	priv := ecc.GenKey(256)
	pub := e.Mul(g, priv)

	fmt.Println("Priv Key: ", priv.Text(16))
	fmt.Println("Pub key: ", pub.ToString(true))
}

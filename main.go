package main

import (
	"fmt"
	"log"

	"github.com/tacotaha/ecc/ecc"
	"github.com/tacotaha/ecc/ecdsa"
)

func main() {
	c, g, _, err := ecc.Secp256k1()
	if err != nil {
		log.Fatal(err)
	}

	priv := ecc.GenKey(256)
	pub := c.Mul(g, priv)

	fmt.Println("Priv Key: ", priv.Text(16))
	fmt.Println("Pub key: ", pub.ToString(true))

	e := ecdsa.NewECDSA()
	msg := []byte("This message is to be signed")

	r, s := e.Sign(msg, priv)
	valid := e.Verify(msg, r, s, pub)

	_, pub1 := e.GenKeyPair()
	invalid := e.Verify(msg, r, s, pub1)

	fmt.Println("Valid sig: ", valid)
	fmt.Println("Invalid sig: ", invalid)
}

package main

import (
	"encoding/hex"
	"fmt"
	"log"

	"github.com/tacotaha/ecc/ecc"
	"github.com/tacotaha/ecc/ecdsa"
)

func testEncoding() {
	c, g, _, err := ecc.Secp256k1()
	if err != nil {
		log.Fatal(err)
	}

	for i := 0; i < (1 << 10); i++ {
		priv := ecc.GenKey(256)
		pub := c.Mul(g, priv)

		decoded, err := c.Decode(pub.Encode(false), g)
		if err != nil {
			log.Fatal(err)
		}
		if !decoded.Equal(pub) {
			log.Fatal("Invalid Encoding")
		}

		decoded, err = c.Decode(pub.Encode(true), g)
		if err != nil {
			log.Fatal(err)
		}
		if !decoded.Equal(pub) {
			log.Fatal("Invalid Encoding")
		}
	}
}

func main() {
	c, g, _, err := ecc.Secp256k1()
	if err != nil {
		log.Fatal(err)
	}

	priv := ecc.GenKey(256)
	pub := c.Mul(g, priv)

	fmt.Println("Priv Key: ", priv.Text(16))
	fmt.Println("Pub key: ", hex.EncodeToString(pub.Encode(true)))

	e := ecdsa.NewECDSA()
	msg := []byte("This message is to be signed")

	r, s := e.Sign(msg, priv)
	valid := e.Verify(msg, r, s, pub)

	_, pub1 := e.GenKeyPair()
	invalid := e.Verify(msg, r, s, pub1)

	fmt.Println("Valid sig: ", valid)
	fmt.Println("Invalid sig: ", invalid)

	testEncoding()
}

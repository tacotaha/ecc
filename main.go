package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"

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

func testGProps() {
	c := new(big.Int)
	s, g, n, err := ecc.Secp256k1()
	if err != nil {
		log.Fatal(err)
	}

	if !s.Mul(g, n).IsInf {
		log.Fatal("infinity check")
	}

	for i := 0; i < (1 << 10); i++ {
		a, _ := rand.Int(rand.Reader, n)
		b, _ := rand.Int(rand.Reader, n)
		c.Add(a, b)

		p := s.Mul(g, a)
		q := s.Mul(g, b)
		r := s.Mul(g, c)

		pq := s.Add(q, p)
		qp := s.Add(p, q)

		if !pq.Equal(qp) {
			log.Fatal("commutative check")
		}

		if !pq.Equal(r) {
			log.Fatal("distributive check")
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

	testGProps()
	testEncoding()
}

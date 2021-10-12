package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"

	"github.com/tacotaha/ecc/curve25519"
	"github.com/tacotaha/ecc/ecc"
	"github.com/tacotaha/ecc/ecdsa"
	"github.com/tacotaha/ecc/secp256k1"
)

func testEncoding() {
	s := secp256k1.NewCurve()

	for i := 0; i < (1 << 10); i++ {
		priv := ecc.GenKey(256)
		pub := s.Mul(s.G, priv)

		decoded, err := s.Decode(pub.Encode(false))
		if err != nil {
			log.Fatal(err)
		}
		if !decoded.Equal(pub) {
			log.Fatal("Invalid Encoding")
		}

		decoded, err = s.Decode(pub.Encode(true))
		if err != nil {
			log.Fatal(err)
		}
		if !decoded.Equal(pub) {
			log.Fatal("Invalid Encoding")
		}
	}
}

func s256k1() {
	c := new(big.Int)
	s := secp256k1.NewCurve()

	if !s.Mul(s.G, s.N).IsInf {
		log.Fatal("infinity check")
	}

	for i := 0; i < (1 << 10); i++ {
		a, _ := rand.Int(rand.Reader, s.N)
		b, _ := rand.Int(rand.Reader, s.N)
		c.Add(a, b)

		p := s.Mul(s.G, a)
		q := s.Mul(s.G, b)
		r := s.Mul(s.G, c)

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

func c25519() {
	curve := curve25519.NewCurve()

	if !curve.Mul(curve.G.ToJacobi(), curve.N).IsInf() {
		log.Fatal("infinity check")
	}

	for i := 0; i < (1 << 10); i++ {
		a, _ := rand.Int(rand.Reader, curve.N)
		b, _ := rand.Int(rand.Reader, curve.N)

		gJ := curve.G.ToJacobi()

		p := curve.Mul(gJ, a)
		q := curve.Mul(gJ, b)
		pq := curve.Add(q, p)
		qp := curve.Add(p, q)

		if !pq.Equal(qp) {
			log.Fatal("commutative check")
		}
	}

	return
}

func main() {
	curve := secp256k1.NewCurve()

	priv := ecc.GenKey(256)
	pub := curve.Mul(curve.G, priv)

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
	s256k1()
	c25519()
}

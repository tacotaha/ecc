package ecdsa

import (
	"math/big"

	"crypto/rand"
	"crypto/sha256"

	"github.com/tacotaha/ecc/ecc"
)

type ECDSA struct {
	E *ecc.Curve
	G *ecc.Point
	N *big.Int
}

func NewECDSA() *ECDSA {
	e := new(ECDSA)
	e.E, e.G, e.N, _ = ecc.Secp256k1()
	return e
}

func (e *ECDSA) GenKeyPair() (*big.Int, *ecc.Point) {
	priv, _ := rand.Int(rand.Reader, e.N)
	pub := e.E.Mul(e.G, priv)
	return priv, pub
}

func (e *ECDSA) HashMsg(msg []byte) *big.Int {
	msgHash := sha256.Sum256(msg)
	mh := new(big.Int)
	mh.SetBytes(msgHash[:])
	return mh
}

func (e *ECDSA) Sign(msg []byte, priv *big.Int) (*big.Int, *big.Int) {
	s := big.NewInt(0)
	kEInv := big.NewInt(0)

	mh := e.HashMsg(msg)

	kE, _ := rand.Int(rand.Reader, e.N)
	kEInv.ModInverse(kE, e.N)

	// r = kE * G
	r := e.E.Mul(e.G, kE).X

	// s = (h(msg) + priv * r) * kE^-1 mod n
	s.Mul(priv, r)
	s.Add(s, mh)
	s.Mul(s, kEInv)
	s.Mod(s, e.N)

	return r, s
}

func (e *ECDSA) Verify(msg []byte, r, s *big.Int, pubKey *ecc.Point) bool {
	x := big.NewInt(0)
	y := big.NewInt(0)
	sInv := big.NewInt(0)
	check := big.NewInt(0)

	mh := e.HashMsg(msg)
	sInv.ModInverse(s, e.N)

	// x = s^-1 * h(msg) mod n
	x.Mul(sInv, mh)
	x.Mod(x, e.N)

	// y = s^-1 * r mod n
	y.Mul(sInv, r)
	y.Mod(y, e.N)

	// p = x * G + y * PubKey
	p := e.E.Add(e.E.Mul(e.G, x), e.E.Mul(pubKey, y))

	check.Mod(r, e.N)

	// P_x == r mod n
	return p.X.Cmp(check) == 0
}

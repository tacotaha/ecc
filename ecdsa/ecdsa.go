package ecdsa

import (
	"math/big"

	"crypto/rand"
	"crypto/sha256"

	"github.com/tacotaha/ecc/ecc"
	"github.com/tacotaha/ecc/secp256k1"
)

type ECDSA struct {
	S *secp256k1.Secp256k1
}

func NewECDSA() *ECDSA {
	return &ECDSA{secp256k1.NewCurve()}
}

func (e *ECDSA) GenKeyPair() (*big.Int, *ecc.Point) {
	priv, _ := rand.Int(rand.Reader, e.S.N)
	pub := e.S.Mul(e.S.G, priv)
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

	kE, _ := rand.Int(rand.Reader, e.S.N)
	kEInv.ModInverse(kE, e.S.N)

	// r = kE * G
	r := e.S.Mul(e.S.G, kE).X

	// s = (h(msg) + priv * r) * kE^-1 mod n
	s.Mul(priv, r)
	s.Add(s, mh)
	s.Mul(s, kEInv)
	s.Mod(s, e.S.N)

	return r, s
}

func (e *ECDSA) Verify(msg []byte, r, s *big.Int, pubKey *ecc.Point) bool {
	x := big.NewInt(0)
	y := big.NewInt(0)
	sInv := big.NewInt(0)
	check := big.NewInt(0)

	mh := e.HashMsg(msg)
	sInv.ModInverse(s, e.S.N)

	// x = s^-1 * h(msg) mod n
	x.Mul(sInv, mh)
	x.Mod(x, e.S.N)

	// y = s^-1 * r mod n
	y.Mul(sInv, r)
	y.Mod(y, e.S.N)

	// p = x * G + y * PubKey
	p := e.S.Add(e.S.Mul(e.S.G, x), e.S.Mul(pubKey, y))

	check.Mod(r, e.S.N)

	// P_x == r mod n
	return p.X.Cmp(check) == 0
}

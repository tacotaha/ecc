package ecc

import (
	"crypto/rand"
	"math/big"
)

type Point struct {
	X, Y  *big.Int
	IsInf bool
}

type Jacobi struct {
	X, Y, Z *big.Int
}

func NewJacobi() *Jacobi {
	j := new(Jacobi)
	j.X = new(big.Int)
	j.Y = new(big.Int)
	j.Z = new(big.Int)
	return j
}

func (j *Jacobi) Equal(p *Jacobi) bool {
	return j.X.Cmp(p.X) == 0 && j.Y.Cmp(p.Y) == 0 && j.Z.Cmp(p.Z) == 0
}

func (j *Jacobi) Set(p *Jacobi) {
	j.X.Set(p.X)
	j.Y.Set(p.Y)
	j.Z.Set(p.Z)
}

func (j *Jacobi) IsInf() bool {
	return j.Z.Int64() == 0
}

func (j *Jacobi) ToAffline(p *big.Int) *Point {
	q := NewPoint(j.X, j.Y)
	zinv := new(big.Int)
	zinv.ModInverse(j.Z, p)
	q.X.Mul(q.X, zinv)
	q.X.Mod(q.X, p)
	q.Y.Mul(q.Y, zinv)
	q.Y.Mod(q.Y, p)
	return q
}

func (p *Point) ToJacobi() *Jacobi {
	q := NewJacobi()
	q.X.Set(p.X)
	q.Y.Set(p.Y)
	q.Z = big.NewInt(1)
	return q
}

func NewPoint(x, y *big.Int) *Point {
	p := new(Point)
	p.X = new(big.Int)
	p.Y = new(big.Int)
	if x != nil {
		p.X.Set(x)
	}
	if y != nil {
		p.Y.Set(y)
	}
	p.IsInf = false
	return p
}

func Inf() *Point {
	p := new(Point)
	p.X = big.NewInt(0)
	p.Y = big.NewInt(0)
	p.IsInf = true
	return p
}

func (p *Point) CheckInf() bool {
	return p.X.Int64() == 0 && p.Y.Int64() == 0
}

func (p *Point) Equal(p2 *Point) bool {
	return p.X.Cmp(p2.X) == 0 && p.Y.Cmp(p2.Y) == 0
}

func (p *Point) Encode(compressed bool) []byte {
	x := make([]byte, 32)
	y := make([]byte, 32)

	p.X.FillBytes(x)
	p.Y.FillBytes(y)

	if !compressed {
		return append(append([]byte{0x04}, x...), y...)
	}

	prefix := byte(0x02 + p.Y.Bit(0))
	return append([]byte{prefix}, x...)
}

func GenKey(blen int) *big.Int {
	key := make([]byte, blen>>3)
	rand.Read(key)
	k := big.NewInt(0)
	k.SetBytes(key)
	return k
}

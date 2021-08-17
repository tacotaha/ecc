package ecc

import (
	"errors"
	"fmt"
	"math/big"

	"crypto/rand"
)

type Point struct {
	X, Y *big.Int
}

type Curve struct {
	// y^2 = x^3 + ax + b mod p
	A, B, P *big.Int
}

func NewPoint(x, y *big.Int) *Point {
	p := Zero()
	p.X.Set(x)
	p.Y.Set(y)
	return p
}

func Zero() *Point {
	p := new(Point)
	p.X = big.NewInt(0)
	p.Y = big.NewInt(0)
	return p
}

func (p *Point) Equal(p2 *Point) bool {
	return p.X.Cmp(p2.X) == 0 && p.Y.Cmp(p2.Y) == 0
}

func (p *Point) ToString(compressed bool) string {
	if !compressed {
		return "04 " + p.X.Text(16) + " " + p.Y.Text(16)
	}

	var prefix string

	if p.Y.Bit(0) == 1 {
		prefix = "03"
	} else {
		prefix = "02"
	}

	return prefix + " " + p.X.Text(16)
}

func NewCurve(A, B, P *big.Int) (*Curve, error) {
	c := &Curve{big.NewInt(0), big.NewInt(0), big.NewInt(0)}

	c.A.Set(A)
	c.B.Set(B)
	c.P.Set(P)

	if !c.Valid() {
		return c, errors.New("Singular curve")
	}

	return c, nil
}

func Secp256k1() (*Point, *Curve, error) {
	p := big.NewInt(0)
	gX := big.NewInt(0)
	gY := big.NewInt(0)

	// recommended params: http://www.secg.org/sec2-v2.pdf
	pStr := "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"
	gXStr := "0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
	gYStr := "0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"

	fmt.Sscan(pStr, p)
	fmt.Sscan(gXStr, gX)
	fmt.Sscan(gYStr, gY)

	c, err := NewCurve(big.NewInt(0), big.NewInt(7), p)
	g := NewPoint(gX, gY)

	return g, c, err
}

func (c *Curve) Valid() bool {
	a := big.NewInt(0)
	b := big.NewInt(0)

	if !c.P.ProbablyPrime(100) {
		return false
	}

	// Singularity check for nonzero discriminant
	a.Exp(c.A, big.NewInt(3), c.P)
	a.Mul(a, big.NewInt(4)) // 4a^3

	b.Exp(c.B, big.NewInt(2), c.P)
	b.Mul(b, big.NewInt(27)) // 27b^2

	// 4a^3 + 27b^2 mod p != 0
	a.Add(a, b)
	a.Mod(a, c.P)
	return a.Cmp(big.NewInt(0)) != 0
}

func (c *Curve) Add(p, q *Point) *Point {
	// slope of line through P & Q
	sNum := big.NewInt(0)
	sDen := big.NewInt(0)
	x := big.NewInt(0)
	y := big.NewInt(0)
	two := big.NewInt(2)

	if p.Equal(q) { // s = (3x^2 + a) / 2y mod p
		sNum.Exp(p.X, two, c.P)
		sNum.Mul(sNum, big.NewInt(3))
		sNum.Add(sNum, c.A)
		sDen.Set(p.Y)
		sDen.Mul(sDen, two)
	} else { // s = (y_2 - y_1) / (x_2 - x_1) mod p
		sNum.Set(q.Y)
		sNum.Sub(sNum, p.Y)
		sDen.Set(q.X)
		sDen.Sub(sDen, p.X)
	}

	sDen.ModInverse(sDen, c.P)
	sNum.Mul(sNum, sDen)
	sNum.Mod(sNum, c.P)

	// x = s^2 - x_1 - x_2
	x.Exp(sNum, two, c.P)
	x.Sub(x, p.X)
	x.Sub(x, q.X)
	x.Mod(x, c.P)

	// y = s(x_1 - x) - y_1
	y.Sub(p.X, x)
	y.Mul(y, sNum)
	y.Sub(y, p.Y)
	y.Mod(y, c.P)

	return NewPoint(x, y)
}

func (c *Curve) Inv(p *Point) *Point {
	q := Zero()
	q.X.Set(p.X)
	q.Y.Sub(c.P, p.Y)
	return q // (x, P - y)
}

func (c *Curve) Mul(p *Point, a *big.Int) *Point {
	res := NewPoint(p.X, p.Y)

	bl := 0
	for bl = a.BitLen(); bl >= 0; bl-- {
		if a.Bit(bl) == 1 {
			break
		}
	}

	for i := bl - 1; i >= 0; i-- {
		res = c.Add(res, res)
		if a.Bit(i) == 1 {
			res = c.Add(res, p)
		}
	}
	return res
}

func GenKey(blen int) *big.Int {
	key := make([]byte, blen>>3)
	rand.Read(key)
	k := big.NewInt(0)
	k.SetBytes(key)
	return k
}

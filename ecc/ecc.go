package ecc

import (
	"errors"
	"fmt"
	"math/big"

	"crypto/rand"
)

type Point struct {
	X, Y  *big.Int
	IsInf bool
}

type Curve struct {
	// y^2 = x^3 + ax + b mod p
	A, B, P *big.Int
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
	p.IsInf = p.CheckInf()
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
	z := int64(0)
	return p.X.Int64() == z && p.Y.Int64() == z
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

func Secp256k1() (*Curve, *Point, *big.Int, error) {
	p := big.NewInt(0)
	gX := big.NewInt(0)
	gY := big.NewInt(0)
	gOrder := big.NewInt(0)

	// recommended params: http://www.secg.org/sec2-v2.pdf
	pStr := "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"
	gXStr := "0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
	gYStr := "0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"
	gOrderStr := "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"

	fmt.Sscan(pStr, p)
	fmt.Sscan(gXStr, gX)
	fmt.Sscan(gYStr, gY)
	fmt.Sscan(gOrderStr, gOrder)

	c, err := NewCurve(big.NewInt(0), big.NewInt(7), p)
	g := NewPoint(gX, gY)

	return c, g, gOrder, err
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

	if sDen.Int64() == 0 {
		return Inf()
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
	q := NewPoint(p.X, p.Y)
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
		if res.CheckInf() {
			return Inf()
		}
		if a.Bit(i) == 1 {
			res = c.Add(res, p)
		}
	}
	return res
}

// eval y = sqrt(x^3 + ax + b mod p)
func (c *Curve) Eval(x *big.Int) *big.Int {
	y_2 := new(big.Int)
	x_3 := new(big.Int)
	a_x := new(big.Int)
	p_1 := new(big.Int)
	inv := new(big.Int)

	// x^3 mod p
	x_3.Exp(x, big.NewInt(3), c.P)

	// ax
	a_x.Mul(c.A, x)
	a_x.Mod(a_x, c.P)

	// y_2 = x^3 + ax + b mod p
	y_2.Add(x_3, a_x)
	y_2.Add(y_2, c.B)
	y_2.Mod(y_2, c.P)

	// (p + 1) / 4
	p_1.Add(c.P, big.NewInt(1))
	inv.ModInverse(big.NewInt(4), c.P)
	p_1.Mul(p_1, inv)
	p_1.Mod(p_1, c.P)

	// y = (y_2) ^ ((p + 1) / 4) mod p
	return y_2.Exp(y_2, p_1, c.P)
}

func (c *Curve) Decode(buf []byte, g *Point) (*Point, error) {
	prefix := buf[0]
	point := buf[1:]
	pt := NewPoint(nil, nil)

	if prefix > 0x04 || prefix < 0x02 {
		return nil, fmt.Errorf("Invalid string prefix: %x. Must be one of (02, 03, 04)\n", prefix)
	}

	pt.X.SetBytes(point[:32])
	if prefix == 0x04 {
		pt.Y.SetBytes(point[32:])
	} else {
		pt.Y = c.Eval(pt.X)
		if (prefix == 0x03 && pt.Y.Bit(0) != 1) || (prefix == 0x02 && pt.Y.Bit(0) == 1) {
			pt.Y.Sub(c.P, pt.Y)
		}
	}

	return pt, nil
}

func GenKey(blen int) *big.Int {
	key := make([]byte, blen>>3)
	rand.Read(key)
	k := big.NewInt(0)
	k.SetBytes(key)
	return k
}

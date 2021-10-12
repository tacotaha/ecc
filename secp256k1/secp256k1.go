package secp256k1

import (
	"fmt"
	"math/big"

	"github.com/tacotaha/ecc/ecc"
)

type Secp256k1 struct {
	// y^2 = x^3 + ax + b mod p
	A, B, P *big.Int
	G       *ecc.Point
	N       *big.Int
}

func NewCurve() *Secp256k1 {
	p := new(big.Int)
	gX := new(big.Int)
	gY := new(big.Int)
	n := new(big.Int)

	// recommended params: http://www.secg.org/sec2-v2.pdf
	p.SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
	gX.SetString("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16)
	gY.SetString("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
	n.SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	a := big.NewInt(0)
	b := big.NewInt(7)

	g := ecc.NewPoint(gX, gY)

	return &Secp256k1{a, b, p, g, n}
}

func (s *Secp256k1) Add(p, q *ecc.Point) *ecc.Point {
	sNum := big.NewInt(0)
	sDen := big.NewInt(0)
	x := big.NewInt(0)
	y := big.NewInt(0)
	two := big.NewInt(2)

	if p.Equal(q) { // s = (3x^2 + a) / 2y mod p
		sNum.Exp(p.X, two, s.P)
		sNum.Mul(sNum, big.NewInt(3))
		sNum.Add(sNum, s.A)
		sDen.Set(p.Y)
		sDen.Mul(sDen, two)
	} else { // s = (y_2 - y_1) / (x_2 - x_1) mod p
		sNum.Set(q.Y)
		sNum.Sub(sNum, p.Y)
		sDen.Set(q.X)
		sDen.Sub(sDen, p.X)
	}

	if sDen.Int64() == 0 {
		return ecc.Inf()
	}

	sDen.ModInverse(sDen, s.P)
	sNum.Mul(sNum, sDen)
	sNum.Mod(sNum, s.P)

	// x = s^2 - x_1 - x_2
	x.Exp(sNum, two, s.P)
	x.Sub(x, p.X)
	x.Sub(x, q.X)
	x.Mod(x, s.P)

	// y = s(x_1 - x) - y_1
	y.Sub(p.X, x)
	y.Mul(y, sNum)
	y.Sub(y, p.Y)
	y.Mod(y, s.P)

	return ecc.NewPoint(x, y)
}

func (s *Secp256k1) Inv(p *ecc.Point) *ecc.Point {
	q := ecc.NewPoint(p.X, p.Y)
	q.Y.Sub(s.P, p.Y)
	return q // (x, P - y)
}

func (s *Secp256k1) Mul(p *ecc.Point, a *big.Int) *ecc.Point {
	res := ecc.NewPoint(p.X, p.Y)

	bl := 0
	for bl = a.BitLen(); bl >= 0; bl-- {
		if a.Bit(bl) == 1 {
			break
		}
	}

	for i := bl - 1; i >= 0; i-- {
		res = s.Add(res, res)
		if res.CheckInf() {
			return ecc.Inf()
		}
		if a.Bit(i) == 1 {
			res = s.Add(res, p)
		}
	}
	return res
}

// eval y = sqrt(x^3 + ax + b mod p)
func (s *Secp256k1) Eval(x *big.Int) (*big.Int, error) {
	y_2 := new(big.Int)
	x_3 := new(big.Int)
	a_x := new(big.Int)
	p_1 := new(big.Int)
	inv := new(big.Int)

	// x^3 mod p
	x_3.Exp(x, big.NewInt(3), s.P)

	// ax
	a_x.Mul(s.A, x)
	a_x.Mod(a_x, s.P)

	// y_2 = x^3 + ax + b mod p
	y_2.Add(x_3, a_x)
	y_2.Add(y_2, s.B)
	y_2.Mod(y_2, s.P)

	if big.Jacobi(y_2, s.P) == -1 {
		return nil, fmt.Errorf("Invalid point")
	}

	// (p + 1) / 4
	p_1.Add(s.P, big.NewInt(1))
	inv.ModInverse(big.NewInt(4), s.P)
	p_1.Mul(p_1, inv)
	p_1.Mod(p_1, s.P)

	// y = (y_2) ^ ((p + 1) / 4) mod p
	return y_2.Exp(y_2, p_1, s.P), nil
}

func (s *Secp256k1) ValidX(x *big.Int) bool {
	x_3 := new(big.Int)
	a_x := new(big.Int)
	y_2 := new(big.Int)

	// x^3 mod p
	x_3.Exp(x, big.NewInt(3), s.P)

	// ax
	a_x.Mul(s.A, x)
	a_x.Mod(a_x, s.P)

	// y_2 = x^3 + ax + b mod p
	y_2.Add(x_3, a_x)
	y_2.Add(y_2, s.B)
	y_2.Mod(y_2, s.P)

	// y_2 should be a quad res mod p
	return big.Jacobi(y_2, s.P) != -1
}

func (s *Secp256k1) Decode(buf []byte) (*ecc.Point, error) {
	prefix := buf[0]
	point := buf[1:]
	pt := ecc.NewPoint(nil, nil)

	if prefix > 0x04 || prefix < 0x02 {
		return nil, fmt.Errorf("Invalid string prefix: %x. Must be one of (02, 03, 04)\n", prefix)
	}

	pt.X.SetBytes(point[:32])

	if prefix == 0x04 {
		pt.Y.SetBytes(point[32:])
	} else {
		var err error
		pt.Y, err = s.Eval(pt.X)
		if err != nil {
			return nil, err
		}
		if (prefix == 0x03 && pt.Y.Bit(0) != 1) || (prefix == 0x02 && pt.Y.Bit(0) == 1) {
			pt.Y.Sub(s.P, pt.Y)
		}
	}

	return pt, nil
}

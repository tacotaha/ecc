package curve25519

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/tacotaha/ecc/ecc"
)

type Curve25519 struct {
	// y^2 = x^3 + ax^2 + x mod p
	A, P, N *big.Int
	G       *ecc.Point
}

func NewCurve() *Curve25519 {
	p := new(big.Int)
	n := new(big.Int)
	gY := new(big.Int)

	// recommended params (sec 4.1): https://datatracker.ietf.org/doc/html/rfc7748
	p.SetString("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed", 16)
	n.SetString("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed", 16)
	gY.SetString("14781619447589544791020593568409986887264606134616475288964881837755586237401", 10)
	gX := big.NewInt(9)
	a := big.NewInt(486662)

	g := ecc.NewPoint(gX, gY)

	return &Curve25519{a, p, n, g}
}

func (c *Curve25519) RandPoint() *ecc.Jacobi {
	var err error
	j := ecc.NewJacobi()
	for {
		j.X, _ = rand.Int(rand.Reader, c.N)
		j.Y, err = c.Eval(j)
		if err != nil {
			break
		}
	}
	return j
}

func (c *Curve25519) Valid(p *ecc.Jacobi) bool {
	x := p.ToAffline(c.P).X
	x3 := new(big.Int)
	ax := new(big.Int)

	x3.Exp(x, big.NewInt(3), c.P)
	ax.Exp(x, big.NewInt(2), c.P)
	ax.Mul(ax, c.A)

	x3.Add(x3, ax)
	x3.Add(x3, x)

	return big.Jacobi(x3, c.P) != -1
}

func (c *Curve25519) Eval(p *ecc.Jacobi) (*big.Int, error) {
	x := p.ToAffline(c.P).X
	x3 := new(big.Int)
	ax := new(big.Int)

	x3.Exp(x, big.NewInt(3), c.P)
	ax.Exp(x, big.NewInt(2), c.P)
	ax.Mul(ax, c.A)

	x3.Add(x3, ax)
	x3.Add(x3, x)

	if big.Jacobi(x3, c.P) == -1 {
		return nil, fmt.Errorf("invalid point")
	}

	x3.ModSqrt(x3, c.P)

	return x3.Sub(c.P, x3), nil
}

func (c *Curve25519) Add(p, q *ecc.Jacobi) *ecc.Jacobi {
	res := ecc.NewJacobi()
	if p.X.Int64() == 0 && p.Y.Int64() == 0 {
		res.Set(q)
	} else if q.X.Int64() == 0 && q.Y.Int64() == 0 {
		res.Set(p)
	} else if p.Equal(q) {
		res = c.Double(p)
	} else {
		two := big.NewInt(2)
		x := new(big.Int)
		z := new(big.Int)

		x.Mul(p.X, q.X)
		z.Mul(p.Z, q.Z)
		x.Sub(x, z)
		res.X.Exp(x, two, c.P)

		x.Mul(p.X, q.Z)
		z.Mul(q.X, p.Z)
		x.Sub(x, z)
		res.Z.Exp(x, two, c.P)
		res.Z.Mul(res.Z, c.G.X)
		res.Z.Mod(res.Z, c.P)
	}

	return res
}

func (c *Curve25519) Double(p *ecc.Jacobi) *ecc.Jacobi {
	res := ecc.NewJacobi()
	two := big.NewInt(2)
	x := new(big.Int)
	z := new(big.Int)
	axz := new(big.Int)

	res.X.Exp(p.X, two, c.P)
	res.Z.Exp(p.Z, two, c.P)
	res.X.Sub(res.X, res.Z)
	res.X.Exp(res.X, two, c.P)

	res.Z.Mul(p.X, p.Z)
	res.Z.Mul(res.Z, big.NewInt(4))
	x.Exp(p.X, two, c.P)
	axz.Mul(c.A, p.X)
	axz.Mul(axz, p.Z)
	z.Exp(p.Z, two, c.P)

	x.Add(x, axz)
	x.Add(x, z)
	res.Z.Mul(res.Z, x)
	res.Z.Mod(res.Z, c.P)

	return res
}

func (c *Curve25519) Mul(p *ecc.Jacobi, n *big.Int) *ecc.Jacobi {
	r0 := ecc.NewJacobi()
	r1 := ecc.NewJacobi()
	r1.X.Set(p.X)
	r1.Z.Set(p.Z)

	bl := 0
	for bl = n.BitLen(); bl >= 0; bl-- {
		if n.Bit(bl) == 1 {
			break
		}
	}

	for i := bl; i >= 0; i-- {
		if n.Bit(i) == 0 {
			r1 = c.Add(r0, r1)
			r0 = c.Double(r0)
		} else {
			r0 = c.Add(r0, r1)
			r1 = c.Double(r1)
		}
	}

	return r0
}

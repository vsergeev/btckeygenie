/* gobtcaddr v1.0
 * vsergeev
 * https://github.com/vsergeev/gobtcaddr
 * MIT Licensed
 */

package btckey

import (
	"fmt"
	"math/big"
)

/* We gotta do a lot ourselves because golang's crypto/elliptic uses curves
 * with a = -3 hardcoded */

/* See SEC2 pg.9 http://www.secg.org/collateral/sec2_final.pdf */

// Point represents a point on an EllipticCurve.
type Point struct {
	X *big.Int
	Y *big.Int
}

/* y**2 = x**3 + a*x + b */
// EllipticCurve represents the parameters of an elliptic curve.
type EllipticCurve struct {
	A *big.Int
	B *big.Int
	P *big.Int
	G Point
	N *big.Int
	H *big.Int
}

// dump dumps the bytes of a point for debugging.
func (p *Point) dump() {
	fmt.Printf("X: ")
	for _, v := range p.X.Bytes() {
		fmt.Printf("%02x ", v)
	}
	fmt.Println()

	fmt.Printf("Y: ")
	for _, v := range p.Y.Bytes() {
		fmt.Printf("%02x ", v)
	}
	fmt.Println()
}

/*** Modular Arithmetic ***/

/* NOTE: Returning a new z each time below is very space inefficient, but the
 * alternate accumulator based design makes the point arithmetic functions look
 * absolutely hideous. I may still change this in the future. */

// addMod computes z = (x + y) % p.
func addMod(x *big.Int, y *big.Int, p *big.Int) (z *big.Int) {
	z = new(big.Int).Add(x, y)
	z.Mod(z, p)
	return z
}

// subMod computes z = (x - y) % p.
func subMod(x *big.Int, y *big.Int, p *big.Int) (z *big.Int) {
	z = new(big.Int).Sub(x, y)
	z.Mod(z, p)
	return z
}

// mulMod computes z = (x * y) % p.
func mulMod(x *big.Int, y *big.Int, p *big.Int) (z *big.Int) {
	n := new(big.Int).Set(x)
	z = big.NewInt(0)

	for i := 0; i < y.BitLen(); i++ {
		if y.Bit(i) == 1 {
			z = addMod(z, n, p)
		}
		n = addMod(n, n, p)
	}

	return z
}

// invMod computes z = (1/x) % p.
func invMod(x *big.Int, p *big.Int) (z *big.Int) {
	z = new(big.Int).ModInverse(x, p)
	return z
}

// expMod computes z = (x^e) % p.
func expMod(x *big.Int, y *big.Int, p *big.Int) (z *big.Int) {
	z = new(big.Int).Exp(x, y, p)
	return z
}

// sqrtMod computes z = sqrt(x) % p.
func sqrtMod(x *big.Int, p *big.Int) (z *big.Int) {
	/* assert that p % 4 == 3 */
	if new(big.Int).Mod(p, big.NewInt(4)).Cmp(big.NewInt(3)) != 0 {
		panic("p is not equal to 3 mod 4!")
	}

	/* z = sqrt(x) % p = x^((p+1)/4) % p */

	/* e = (p+1)/4 */
	e := new(big.Int).Add(p, big.NewInt(1))
	e = e.Rsh(e, 2)

	z = expMod(x, e, p)
	return z
}

/*** Point Arithmetic on Curve ***/

// IsOnCurve checks if point P is on EllipticCurve ec.
func (ec *EllipticCurve) IsOnCurve(P Point) bool {
	/* y**2 = x**3 + a*x + b  % p */
	lhs := mulMod(P.Y, P.Y, ec.P)
	rhs := addMod(
		addMod(
			expMod(P.X, big.NewInt(3), ec.P),
			mulMod(ec.A, P.X, ec.P), ec.P),
		ec.B, ec.P)

	if lhs.Cmp(rhs) == 0 {
		return true
	}

	return false
}

// Add computes R = P + Q on EllipticCurve ec.
func (ec *EllipticCurve) Add(P, Q Point) (R Point) {
	/* See SEC1 pg.7 http://www.secg.org/collateral/sec1_final.pdf */

	if P.X.BitLen() == 0 && P.Y.BitLen() == 0 {
		/* Identity */
		/* R = 0 + Q = Q */

		R.X = new(big.Int).Set(Q.X)
		R.Y = new(big.Int).Set(Q.Y)

	} else if Q.X.BitLen() == 0 && Q.Y.BitLen() == 0 {
		/* Identity */
		/* R = P + 0 = P */

		R.X = new(big.Int).Set(P.X)
		R.Y = new(big.Int).Set(P.Y)

	} else if P.X.Cmp(Q.X) == 0 && P.Y.Cmp(Q.Y) == 0 {
		/* Point doubling */
		/* R = P + P */

		/* Lambda = (3*P.X*P.X + a) / (2*P.Y) */
		num := addMod(
			mulMod(big.NewInt(3),
				mulMod(P.X, P.X, ec.P), ec.P),
			ec.A, ec.P)
		den := invMod(mulMod(big.NewInt(2), P.Y, ec.P), ec.P)
		lambda := mulMod(num, den, ec.P)

		/* R.X = lambda*lambda - 2*P.X */
		R.X = subMod(
			mulMod(lambda, lambda, ec.P),
			mulMod(big.NewInt(2), P.X, ec.P),
			ec.P)
		/* R.Y = lambda*(P.X - R.X) - P.Y */
		R.Y = subMod(
			mulMod(lambda, subMod(P.X, R.X, ec.P), ec.P),
			P.Y, ec.P)

	} else {
		/* Point addition */
		/* R = P + Q */

		/* Lambda = (Q.Y - P.Y) / (Q.X - P.X) */
		num := subMod(Q.Y, P.Y, ec.P)
		den := invMod(subMod(Q.X, P.X, ec.P), ec.P)
		lambda := mulMod(num, den, ec.P)

		/* R.X = lambda*lambda - P.X - Q.X */
		R.X = subMod(
			subMod(
				mulMod(lambda, lambda, ec.P),
				P.X, ec.P),
			Q.X, ec.P)

		/* R.Y = lambda*(P.X - R.X) - P.Y */
		R.Y = subMod(
			mulMod(lambda,
				subMod(P.X, R.X, ec.P), ec.P),
			P.Y, ec.P)
	}

	return R
}

// ScalarBaseMult computes Q = k * G on EllipticCurve ec.
func (ec *EllipticCurve) ScalarBaseMult(k *big.Int) (Q Point) {
	return ec.ScalarMult(k, ec.G)
}

// ScalarMult computes Q = k * P on EllipticCurve ec.
func (ec *EllipticCurve) ScalarMult(k *big.Int, P Point) (Q Point) {
	/* Montgomery Ladder Point Multiplication for constant time operation.
	 *
	 * Implementation based on pseudocode here:
	 * See https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication#Montgomery_ladder */

	var R0 Point
	var R1 Point

	R0.X = big.NewInt(0)
	R0.Y = big.NewInt(0)
	R1.X = new(big.Int).Set(P.X)
	R1.Y = new(big.Int).Set(P.Y)

	for i := ec.N.BitLen() - 1; i >= 0; i-- {
		if k.Bit(i) == 0 {
			R1 = ec.Add(R0, R1)
			R0 = ec.Add(R0, R0)
		} else {
			R0 = ec.Add(R0, R1)
			R1 = ec.Add(R1, R1)
		}
	}

	return R0
}

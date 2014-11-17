/* gobtcaddr v1.0
 * vsergeev
 * https://github.com/vsergeev/gimme-bitcoin-address
 * MIT Licensed
 */

package btcaddr

import (
	"fmt"
	"math/big"
)

/* We gotta do a lot ourselves because golang's crypto/elliptic uses curves
 * with a = -3 hardcoded */

/* See SEC2 pg.9 http://www.secg.org/collateral/sec2_final.pdf */

// Point represents a point on an EllipticCurve
type Point struct {
	X *big.Int
	Y *big.Int
}

/* y**2 = x**3 + a*x + b */
// EllipticCurve represents the parameters of an elliptic curve
type EllipticCurve struct {
	A *big.Int
	B *big.Int
	P *big.Int
	G Point
	N *big.Int
	H *big.Int
}

// dump dumps the bytes of a point for debugging
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

/* README: Some of the arithmetic routines below, used during the ECDSA public
 * key computation, may be vulnerable to timing attacks. Use at your own risk
 * in a public facing setting (e.g. web). If you have some experience or
 * thoughts on this matter, please let me know. */

/*** Element Arithmetic on Finite Field ***/

/* NOTE: Returning a new z each time in these element arithmetic is very
 * space inefficient, but the alternate accumulator based design makes the
 * higher level point arithmetic functions look absolutely hideous. I may still
 * change this in the future. */

// elemAdd computes z = (x + y) % p.
func (ec *EllipticCurve) elemAdd(x *big.Int, y *big.Int) (z *big.Int) {
	z = new(big.Int)
	z.Add(x, y)
	z.Mod(z, ec.P)
	return z
}

// elemSub computes z = (x - y) % p.
func (ec *EllipticCurve) elemSub(x *big.Int, y *big.Int) (z *big.Int) {
	z = new(big.Int)

	/* x > y */
	if x.Cmp(y) > 0 {
		z.Sub(x, y)

		/* x <= y */
	} else {
		z.Add(x, ec.P)
		z.Sub(z, y)
	}

	return z
}

// elemMul computes z = (x * y) % p.
func (ec *EllipticCurve) elemMul(x *big.Int, y *big.Int) (z *big.Int) {
	n := new(big.Int).Set(x)
	z = big.NewInt(0)

	for i := 0; i < y.BitLen(); i++ {
		if y.Bit(i) == 1 {
			z = ec.elemAdd(z, n)
		}
		n = ec.elemAdd(n, n)
	}

	return z
}

/*** Point Arithmetic on Curve ***/

// IsOnCurve checks if point P is on EllipticCurve ec.
func (ec *EllipticCurve) IsOnCurve(P Point) bool {
	/* y**2 = x**3 + a*x + b */
	lhs := ec.elemMul(P.Y, P.Y)
	rhs := ec.elemAdd(
		ec.elemAdd(
			ec.elemMul(
				ec.elemMul(P.X, P.X),
				P.X),
			ec.elemMul(ec.A, P.X)),
		ec.B)

	if lhs.Cmp(rhs) == 0 {
		return true
	}

	return false
}

// PointAdd computes R = P + Q on EllipticCurve ec.
func (ec *EllipticCurve) PointAdd(P Point, Q Point) (R Point) {
	/* See SEC1 pg.7 http://www.secg.org/collateral/sec1_final.pdf */

	/* Identity */
	/* R = 0 + Q = Q */
	if P.X.BitLen() == 0 && P.Y.BitLen() == 0 {
		R.X = new(big.Int).Set(Q.X)
		R.Y = new(big.Int).Set(Q.Y)

		/* Identity */
		/* R = P + 0 = P */
	} else if Q.X.BitLen() == 0 && Q.Y.BitLen() == 0 {
		R.X = new(big.Int).Set(P.X)
		R.Y = new(big.Int).Set(P.Y)

		/* Point doubling */
		/* R = P + P */
	} else if P.X.Cmp(Q.X) == 0 && P.Y.Cmp(Q.Y) == 0 {
		/* Lambda = (3*P.X*P.X + a) / (2*P.Y) */

		num := ec.elemAdd(
			ec.elemMul(big.NewInt(3),
				ec.elemMul(P.X, P.X)),
			ec.A)
		den := ec.elemMul(big.NewInt(2), P.Y)
		den.ModInverse(den, ec.P)

		lambda := ec.elemMul(num, den)

		/* R.X = lambda*lambda - 2*P.X */
		R.X = ec.elemSub(
			ec.elemMul(lambda, lambda),
			ec.elemMul(big.NewInt(2), P.X))
		/* R.Y = lambda*(P.X - R.X) - P.Y */
		R.Y = ec.elemSub(
			ec.elemMul(lambda, ec.elemSub(P.X, R.X)),
			P.Y)

		/* Point addition */
		/* R = P + Q */
	} else {
		/* Lambda = (Q.Y - P.Y) / (Q.X - P.X) */

		num := ec.elemSub(Q.Y, P.Y)
		den := ec.elemSub(Q.X, P.X)
		den.ModInverse(den, ec.P)

		lambda := ec.elemMul(num, den)

		/* R.X = lambda*lambda - P.X - Q.X */
		R.X = ec.elemSub(
			ec.elemSub(
				ec.elemMul(lambda, lambda),
				P.X),
			Q.X)
		/* R.Y = lambda*(P.X - R.X) - P.Y */
		R.Y = ec.elemSub(
			ec.elemMul(lambda,
				ec.elemSub(P.X, R.X)),
			P.Y)
	}
	return R
}

// PointScalarMultiply computes Q = k * P on EllipticCurve ec.
func (ec *EllipticCurve) PointScalarMultiply(k *big.Int, P Point) (Q Point) {
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
			R1 = ec.PointAdd(R0, R1)
			R0 = ec.PointAdd(R0, R0)
		} else {
			R0 = ec.PointAdd(R0, R1)
			R1 = ec.PointAdd(R1, R1)
		}
	}

	return R0
}

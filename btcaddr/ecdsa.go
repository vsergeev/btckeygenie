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

/******************************************************************************/
/* Elliptic Curve Business */
/******************************************************************************/

/* We gotta do a lot ourselves because golang's crypto/elliptic uses curves
 * with a = -3 hardcoded */

type Point struct {
	X *big.Int
	Y *big.Int
}

/* y**2 = x**3 + a*x + b */
type EllipticCurve struct {
	a *big.Int
	b *big.Int
	p *big.Int
	G Point
	n *big.Int
	h *big.Int
}

/* Dump a Point for debugging */
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

/* z = (x + y) % p */
func (ec *EllipticCurve) elem_add(x *big.Int, y *big.Int) (z *big.Int) {
	z = new(big.Int)
	z.Add(x, y)
	z.Mod(z, ec.p)
	return z
}

/* z = (x - y) % p */
func (ec *EllipticCurve) elem_sub(x *big.Int, y *big.Int) (z *big.Int) {
	z = new(big.Int)

	/* x > y */
	if x.Cmp(y) > 0 {
		z.Sub(x, y)

		/* x <= y */
	} else {
		z.Add(x, ec.p)
		z.Sub(z, y)
	}

	return z
}

/* z = (x * y) % p */
func (ec *EllipticCurve) elem_mul(x *big.Int, y *big.Int) (z *big.Int) {
	n := new(big.Int).Set(x)
	z = big.NewInt(0)

	for i := 0; i < y.BitLen(); i++ {
		if y.Bit(i) == 1 {
			z = ec.elem_add(z, n)
		}
		n = ec.elem_add(n, n)
	}

	return z
}

/*** Point Arithmetic on Curve ***/

/* P on Curve? */
func (ec *EllipticCurve) isOnCurve(P Point) bool {
	/* y**2 = x**3 + a*x + b */
	lhs := ec.elem_mul(P.Y, P.Y)
	rhs := ec.elem_add(
		ec.elem_add(
			ec.elem_mul(
				ec.elem_mul(P.X, P.X),
				P.X),
			ec.elem_mul(ec.a, P.X)),
		ec.b)

	if lhs.Cmp(rhs) == 0 {
		return true
	}

	return false
}

/* R = P + Q */
func (ec *EllipticCurve) point_add(P Point, Q Point) (R Point) {
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

		num := ec.elem_add(
			ec.elem_mul(big.NewInt(3),
				ec.elem_mul(P.X, P.X)),
			ec.a)
		den := ec.elem_mul(big.NewInt(2), P.Y)
		den.ModInverse(den, ec.p)

		lambda := ec.elem_mul(num, den)

		/* R.X = lambda*lambda - 2*P.X */
		R.X = ec.elem_sub(
			ec.elem_mul(lambda, lambda),
			ec.elem_mul(big.NewInt(2), P.X))
		/* R.Y = lambda*(P.X - R.X) - P.Y */
		R.Y = ec.elem_sub(
			ec.elem_mul(lambda, ec.elem_sub(P.X, R.X)),
			P.Y)

		/* Point addition */
		/* R = P + Q */
	} else {
		/* Lambda = (Q.Y - P.Y) / (Q.X - P.X) */

		num := ec.elem_sub(Q.Y, P.Y)
		den := ec.elem_sub(Q.X, P.X)
		den.ModInverse(den, ec.p)

		lambda := ec.elem_mul(num, den)

		/* R.X = lambda*lambda - P.X - Q.X */
		R.X = ec.elem_sub(
			ec.elem_sub(
				ec.elem_mul(lambda, lambda),
				P.X),
			Q.X)
		/* R.Y = lambda*(P.X - R.X) - P.Y */
		R.Y = ec.elem_sub(
			ec.elem_mul(lambda,
				ec.elem_sub(P.X, R.X)),
			P.Y)
	}
	return R
}

/* Q = k * P */
func (ec *EllipticCurve) point_scalar_multiply(k *big.Int, P Point) (Q Point) {
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

	for i := ec.n.BitLen() - 1; i >= 0; i-- {
		if k.Bit(i) == 0 {
			R1 = ec.point_add(R0, R1)
			R0 = ec.point_add(R0, R0)
		} else {
			R0 = ec.point_add(R0, R1)
			R1 = ec.point_add(R1, R1)
		}
	}

	return R0
}

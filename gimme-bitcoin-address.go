/*
 * gimme-bitcoin-address v1.0 - Vanya A. Sergeev - vsergeev at gmail
 *
 * Bitcoin keypair generator written in Go. See README.md for more information.
 * MIT licensed.
 */

package main

import (
    "fmt"
    "time"
    "math/big"
    "crypto/sha256"
    "crypto/rand"
    "log"
    "os"

    "code.google.com/p/go.crypto/ripemd160"
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
        z.Sub(x,y)

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
func (ec *EllipticCurve) isOnCurve(P Point) (bool) {
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

    for i := ec.n.BitLen()-1; i >= 0; i-- {
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

/******************************************************************************/
/* Bitcoin Keypair Generation */
/******************************************************************************/

/* We make our own Bitcoin Private Key and Public Key structs here so no one
 * tries to use this code with crypto/ecdsa, which doesn't support the
 * secp256k1 elliptic curve that bitcoin uses */

type BitcoinPrivateKey struct {
    D *big.Int
}

type BitcoinPublicKey struct {
    X, Y *big.Int
}

func Bitcoin_GenerateKeypair() (prikey BitcoinPrivateKey, pubkey BitcoinPublicKey, err error) {
    /* See SEC2 pg.9 http://www.secg.org/collateral/sec2_final.pdf */

    /* secp256k1 elliptic curve parameters */
    var curve = &EllipticCurve{}
    curve.p, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
    curve.a, _ = new(big.Int).SetString("0000000000000000000000000000000000000000000000000000000000000000", 16)
    curve.b, _ = new(big.Int).SetString("0000000000000000000000000000000000000000000000000000000000000007", 16)
    curve.G.X, _ = new(big.Int).SetString("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16)
    curve.G.Y, _ = new(big.Int).SetString("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
    curve.n, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
    curve.h, _ = new(big.Int).SetString("01", 16)

    /* See SEC1 pg.23 http://www.secg.org/collateral/sec1_final.pdf */

    /* Select private key d randomly from [1, n) */
    /* Random integer uniformly selected from [0, n-1) range */
    d, err := rand.Int(rand.Reader, new(big.Int).Sub(curve.n, big.NewInt(1)))
    if err != nil {
        return prikey, pubkey, fmt.Errorf("Error: generating random priviate key.")
    }
    /* Add one to shift d to [1, n) range */
    d.Add(d, big.NewInt(1))

    /* Derive public key from Q = d*G */
    Q := curve.point_scalar_multiply(d, curve.G)

    /* Check that Q is on the curve */
    if !curve.isOnCurve(Q) {
        return prikey, pubkey, fmt.Errorf("Error: catastrophic math failure.")
    }

    prikey.D = d
    pubkey.X = Q.X
    pubkey.Y = Q.Y

    return prikey, pubkey, nil
}

/******************************************************************************/
/* Bitcoin Public and Private Key Export Mechanics */
/******************************************************************************/

func Bitcoin_Base58(b []byte) (s string) {
    /* See https://en.bitcoin.it/wiki/Base58Check_encoding */

    const BITCOIN_BASE58_TABLE = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

    /* Initialize */
    x := new(big.Int).SetBytes(b)
    r := new(big.Int)
    m := big.NewInt(58)
    zero := big.NewInt(0)
    s = ""

    /* While x > 0 */
    for x.Cmp(zero) > 0 {
        /* x, r = (x / 58, x % 58) */
        x.QuoRem(x, m, r)
        /* Prepend ASCII character */
        s = string(BITCOIN_BASE58_TABLE[r.Int64()]) + s
    }

    /* For number of leading 0's in bytes, prepend 1 */
    for _, v := range b {
        if v != 0 {
            break
        }
        s = string(BITCOIN_BASE58_TABLE[0]) + s
    }

    return s
}

func Bitcoin_Prikey2WIF(prikey BitcoinPrivateKey) (wifstr string) {
    /* See https://en.bitcoin.it/wiki/Wallet_import_format */

    /* Create a new SHA256 context */
    sha256_h := sha256.New()

    /* Convert the private key to a byte sequence */
    prikey_bytes := prikey.D.Bytes()

    /* 1. Prepend 0x80 */
    wif_bytes := append([]byte{0x80}, prikey_bytes...)

    /* 2. SHA256 Hash */
    sha256_h.Reset()
    sha256_h.Write(wif_bytes)
    prikey_hash_1 := sha256_h.Sum(nil)

    /* 3. SHA256 Hash */
    sha256_h.Reset()
    sha256_h.Write(prikey_hash_1)
    prikey_hash_2 := sha256_h.Sum(nil)

    /* 4. Checksum is first 4 bytes of second hash */
    checksum := prikey_hash_2[0:4]

    /* 5. Append the checksum */
    wif_bytes = append(wif_bytes, checksum...)

    /* 6. Base58 the byte sequence */
    wifstr = Bitcoin_Base58(wif_bytes)

    return wifstr
}

func Bitcoin_Pubkey2Address(pubkey BitcoinPublicKey, version uint8) (address string) {
    /* See https://en.bitcoin.it/wiki/Technical_background_of_Bitcoin_addresses */

    /* Create a new SHA256 context */
    sha256_h := sha256.New()
    /* Create a new RIPEMD160 Context */
    ripemd160_h := ripemd160.New()

    /* Convert the public key to a byte sequence */
    pubkey_bytes := pubkey.X.Bytes()
    pubkey_bytes = append(pubkey_bytes, pubkey.Y.Bytes()...)

    /* 1. Prepend 0x04 */
    pubkey_bytes = append([]byte{0x04}, pubkey_bytes...)

    /* 2. SHA256 Hash */
    sha256_h.Reset()
    sha256_h.Write(pubkey_bytes)
    pubkey_hash_1 := sha256_h.Sum(nil)

    /* 3. RIPEMD-160 Hash */
    ripemd160_h.Reset()
    ripemd160_h.Write(pubkey_hash_1)
    pubkey_hash_2 := ripemd160_h.Sum(nil)

    /* Prepend version byte */
    pubkey_hash_2 = append([]byte{version}, pubkey_hash_2...)

    /* 4. SHA256 Hash */
    sha256_h.Reset()
    sha256_h.Write(pubkey_hash_2)
    pubkey_hash_3 := sha256_h.Sum(nil)

    /* 5. SHA256 Hash */
    sha256_h.Reset()
    sha256_h.Write(pubkey_hash_3)
    pubkey_hash_4 := sha256_h.Sum(nil)

    /* 6. Checksum is first 4 bytes of previous hash */
    checksum := pubkey_hash_4[0:4]

    /* 7. Add checksum to extended RIPEMD-160 hash */
    address_bytes := append(pubkey_hash_2, checksum...)

    /* 8. Base58 the byte sequence */
    address = Bitcoin_Base58(address_bytes)

    return address
}

/******************************************************************************/
/* Writing Bitcoin Private Key to File */
/******************************************************************************/

func Write_Prikey(prikey BitcoinPrivateKey, dir string, label string) (err error) {
    var filename string

    /* Check that the private key directory is a directory and exists */
    fi, err := os.Stat(dir)
    if dir == "" || (err == nil && !fi.IsDir()) {
        return fmt.Errorf("Error: private key directory path not a directory.")
    } else if err != nil && os.IsNotExist(err) {
        return fmt.Errorf("Error: private key directory path does not exist.")
    } else if err != nil {
        return fmt.Errorf("Error stat'ing private key directory path: %s", err)
    }

    /* Add a path separator to the end of our directory string */
    if dir[len(dir)-1] != os.PathSeparator {
        dir += string(os.PathSeparator)
    }

    /* Prefix the label with a _ to make the filename pretty */
    if label != "" {
        label = "_" + label
    }

    /* Keep trying until we find an unused filename */
    for {
        time_now := time.Now()
        /* Filename format is YYYY-MM-DD_UnixTimestamp_PID_Label.txt */
        filename = fmt.Sprintf("%04d-%02d-%02d_%d_%d%s.txt", time_now.Year(), time_now.Month(), time_now.Day(), time_now.UnixNano(), os.Getpid(), label)

        _, err := os.Stat(dir + filename)
        /* If we had a weird stat'ing error (permissions?) */
        if err != nil && !os.IsNotExist(err) {
            return fmt.Errorf("Error: stat'ing new private key file: %s", err)
        /* Break if we found a non-existent filename */
        } else if err != nil && os.IsNotExist(err) {
            break
        }
    }

    /* Create the private key file */
    keyfile, err := os.Create(filename)
    if err != nil {
       return fmt.Errorf("Error opening private key file for writing: %s", err)
    }
    defer keyfile.Close()

    /* Write the WIF encoded private key */
    _, err = keyfile.WriteString(Bitcoin_Prikey2WIF(prikey))
    if err != nil {
        return fmt.Errorf("Error writing to private key file: %s", err)
    }

    return nil
}

/******************************************************************************/
/******************************************************************************/

func main() {
    /* Usage */
    if len(os.Args) < 2 {
        fmt.Printf("Usage: %s <private key directory path> [label]\n\n", os.Args[0])
        fmt.Printf("v1.0 | https://github.com/vsergeev/gimme-bitcoin-address\n")
        os.Exit(1)
    }

    /* Redirect fatal errors to stderr */
    log.SetOutput(os.Stderr)

    /* Extract directory argument */
    dir := os.Args[1]
    /* Extract label argument */
    label := ""
    if len(os.Args) > 2 {
        label = os.Args[2]
    }

    /* Generate a new ECDSA keypair */
    prikey, pubkey, err := Bitcoin_GenerateKeypair()
    if err != nil {
        log.Fatalf("%s\n", err)
    }

    /* Write the private key to a file */
    err = Write_Prikey(prikey, dir, label)
    if err != nil {
        log.Fatalf("%s\n", err)
    }

    /* Convert the public key to a bitcoin network address */
    address := Bitcoin_Pubkey2Address(pubkey, 0x00)

    /* Print bitcoin address */
    fmt.Println(address)
}


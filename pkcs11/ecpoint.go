package pkcs11

import (
	"crypto/elliptic"
	"math/big"
)

// marshalECPoint encodes an elliptic curve point in uncompressed form
// per SEC 1, Version 2.0, Section 2.3.3:
//
//	0x04 || x || y
//
// where x and y are zero-padded big-endian to the field element byte length.
func marshalECPoint(curve elliptic.Curve, x, y *big.Int) []byte {
	byteLen := (curve.Params().BitSize + 7) / 8
	buf := make([]byte, 1+2*byteLen)
	buf[0] = 4 // uncompressed
	x.FillBytes(buf[1 : 1+byteLen])
	y.FillBytes(buf[1+byteLen:])
	return buf
}

// unmarshalECPoint decodes an elliptic curve point from uncompressed form
// per SEC 1, Version 2.0, Section 2.3.3. Returns nil if the encoding is
// malformed or the point is not on the curve.
//
// Validates the Weierstrass equation y^2 = x^3 + ax + b (mod p) directly
// rather than using the deprecated elliptic.Unmarshal.
func unmarshalECPoint(curve elliptic.Curve, data []byte) (x, y *big.Int) {
	params := curve.Params()
	byteLen := (params.BitSize + 7) / 8
	if len(data) != 1+2*byteLen || data[0] != 4 {
		return nil, nil
	}

	x = new(big.Int).SetBytes(data[1 : 1+byteLen])
	y = new(big.Int).SetBytes(data[1+byteLen:])

	if x.Cmp(params.P) >= 0 || y.Cmp(params.P) >= 0 {
		return nil, nil
	}

	if !isOnCurve(params, x, y) {
		return nil, nil
	}
	return x, y
}

// isOnCurve checks that (x, y) satisfies the short Weierstrass curve equation
// y^2 = x^3 + ax + b (mod p).
//
// The 'a' coefficient is not exposed by elliptic.CurveParams, so it is
// derived from the curve name:
//   - NIST P-224, P-256, P-384, P-521: a = -3 (mod p), per FIPS 186-4 Section D.1
//   - secp256k1: a = 0, per SEC 2, Version 2.0, Section 2.4.1
func isOnCurve(params *elliptic.CurveParams, x, y *big.Int) bool {
	var a big.Int
	switch params.Name {
	case "P-224", "P-256", "P-384", "P-521":
		a.Sub(params.P, big.NewInt(3))
	case "secp256k1":
		// a = 0, zero value is correct
	default:
		return false
	}

	p := params.P

	// lhs = y^2 mod p
	var lhs big.Int
	lhs.Mul(y, y)
	lhs.Mod(&lhs, p)

	// rhs = (x^3 + ax + b) mod p
	var x2, rhs big.Int
	x2.Mul(x, x)
	x2.Mod(&x2, p)
	rhs.Mul(&x2, x)
	rhs.Mod(&rhs, p)

	var ax big.Int
	ax.Mul(&a, x)
	rhs.Add(&rhs, &ax)
	rhs.Add(&rhs, params.B)
	rhs.Mod(&rhs, p)

	return lhs.Cmp(&rhs) == 0
}

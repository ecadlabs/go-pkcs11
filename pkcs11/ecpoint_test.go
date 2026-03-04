package pkcs11

import (
	"crypto/elliptic"
	"math/big"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testCurves = []struct {
	name  string
	curve elliptic.Curve
}{
	{"P-224", elliptic.P224()},
	{"P-256", elliptic.P256()},
	{"P-384", elliptic.P384()},
	{"P-521", elliptic.P521()},
	{"secp256k1", secp256k1.S256()},
}

func TestMarshalUnmarshalRoundTrip(t *testing.T) {
	for _, tc := range testCurves {
		t.Run(tc.name, func(t *testing.T) {
			params := tc.curve.Params()
			byteLen := (params.BitSize + 7) / 8

			// Use the curve's generator point as a known-valid test vector
			buf := marshalECPoint(tc.curve, params.Gx, params.Gy)
			require.Len(t, buf, 1+2*byteLen)
			assert.Equal(t, byte(4), buf[0], "uncompressed prefix")

			x, y := unmarshalECPoint(tc.curve, buf)
			require.NotNil(t, x, "unmarshal returned nil x")
			require.NotNil(t, y, "unmarshal returned nil y")
			assert.Equal(t, 0, x.Cmp(params.Gx), "x mismatch")
			assert.Equal(t, 0, y.Cmp(params.Gy), "y mismatch")
		})
	}
}

func TestMarshalZeroPadding(t *testing.T) {
	// Verify that small coordinates are properly zero-padded
	curve := elliptic.P256()
	byteLen := (curve.Params().BitSize + 7) / 8

	// Use x=1 (needs 31 bytes of zero padding for P-256)
	// We can't test unmarshal here since (1, ?) is unlikely on any curve,
	// but we can verify the marshal output format.
	x := big.NewInt(1)
	y := big.NewInt(2)
	buf := marshalECPoint(curve, x, y)

	assert.Equal(t, 1+2*byteLen, len(buf))
	assert.Equal(t, byte(4), buf[0])
	// x field: 31 zero bytes followed by 0x01
	for i := 1; i < byteLen; i++ {
		assert.Equal(t, byte(0), buf[i], "expected zero padding at byte %d", i)
	}
	assert.Equal(t, byte(1), buf[byteLen])
}

func TestUnmarshalRejectsInvalidPrefix(t *testing.T) {
	for _, tc := range testCurves {
		t.Run(tc.name, func(t *testing.T) {
			params := tc.curve.Params()
			buf := marshalECPoint(tc.curve, params.Gx, params.Gy)

			// Compressed form prefix (not supported)
			buf[0] = 2
			x, y := unmarshalECPoint(tc.curve, buf)
			assert.Nil(t, x)
			assert.Nil(t, y)

			// Garbage prefix
			buf[0] = 0xFF
			x, y = unmarshalECPoint(tc.curve, buf)
			assert.Nil(t, x)
			assert.Nil(t, y)
		})
	}
}

func TestUnmarshalRejectsWrongLength(t *testing.T) {
	for _, tc := range testCurves {
		t.Run(tc.name, func(t *testing.T) {
			params := tc.curve.Params()
			buf := marshalECPoint(tc.curve, params.Gx, params.Gy)

			// Too short
			x, y := unmarshalECPoint(tc.curve, buf[:len(buf)-1])
			assert.Nil(t, x)
			assert.Nil(t, y)

			// Too long
			x, y = unmarshalECPoint(tc.curve, append(buf, 0))
			assert.Nil(t, x)
			assert.Nil(t, y)

			// Empty
			x, y = unmarshalECPoint(tc.curve, nil)
			assert.Nil(t, x)
			assert.Nil(t, y)
		})
	}
}

func TestUnmarshalRejectsOffCurvePoint(t *testing.T) {
	for _, tc := range testCurves {
		t.Run(tc.name, func(t *testing.T) {
			params := tc.curve.Params()
			buf := marshalECPoint(tc.curve, params.Gx, params.Gy)

			// Corrupt y coordinate: flip last byte
			buf[len(buf)-1] ^= 0x01
			x, y := unmarshalECPoint(tc.curve, buf)
			assert.Nil(t, x)
			assert.Nil(t, y)
		})
	}
}

func TestUnmarshalRejectsCoordinateGteP(t *testing.T) {
	for _, tc := range testCurves {
		t.Run(tc.name, func(t *testing.T) {
			params := tc.curve.Params()
			byteLen := (params.BitSize + 7) / 8

			// x = p (invalid: must be < p)
			buf := make([]byte, 1+2*byteLen)
			buf[0] = 4
			params.P.FillBytes(buf[1 : 1+byteLen])
			big.NewInt(0).FillBytes(buf[1+byteLen:])

			x, y := unmarshalECPoint(tc.curve, buf)
			assert.Nil(t, x)
			assert.Nil(t, y)
		})
	}
}

func TestIsOnCurveGeneratorPoints(t *testing.T) {
	for _, tc := range testCurves {
		t.Run(tc.name, func(t *testing.T) {
			params := tc.curve.Params()
			assert.True(t, isOnCurve(params, params.Gx, params.Gy))
		})
	}
}

func TestIsOnCurveRejectsOrigin(t *testing.T) {
	for _, tc := range testCurves {
		t.Run(tc.name, func(t *testing.T) {
			params := tc.curve.Params()
			// (0, 0) is not on any of these curves (b != 0 for all)
			assert.False(t, isOnCurve(params, big.NewInt(0), big.NewInt(0)))
		})
	}
}

func TestIsOnCurveRejectsUnknownCurve(t *testing.T) {
	fake := &elliptic.CurveParams{Name: "unknown"}
	assert.False(t, isOnCurve(fake, big.NewInt(1), big.NewInt(1)))
}

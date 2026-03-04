package pkcs11

/*
#include "platform.h"
*/
import "C"
import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/subtle"
	asn1enc "encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"runtime"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/ecadlabs/go-pkcs11/pkcs11/attr"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

var (
	CurveP224 = asn1enc.ObjectIdentifier{1, 3, 132, 0, 33}
	CurveP256 = asn1enc.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	CurveP384 = asn1enc.ObjectIdentifier{1, 3, 132, 0, 34}
	CurveP521 = asn1enc.ObjectIdentifier{1, 3, 132, 0, 35}
	CurveS256 = asn1enc.ObjectIdentifier{1, 3, 132, 0, 10} // http://www.secg.org/sec2-v2.pdf
)

func oidToCurve(oid asn1enc.ObjectIdentifier) elliptic.Curve {
	switch {
	case oid.Equal(CurveP224):
		return elliptic.P224()
	case oid.Equal(CurveP256):
		return elliptic.P256()
	case oid.Equal(CurveP384):
		return elliptic.P384()
	case oid.Equal(CurveP521):
		return elliptic.P521()
	case oid.Equal(CurveS256):
		return secp256k1.S256()
	default:
		return nil
	}
}

func curveToOID(crv elliptic.Curve) asn1enc.ObjectIdentifier {
	switch {
	case curveEq(crv, elliptic.P224()):
		return CurveP224
	case curveEq(crv, elliptic.P256()):
		return CurveP256
	case curveEq(crv, elliptic.P384()):
		return CurveP384
	case curveEq(crv, elliptic.P521()):
		return CurveP521
	case curveEq(crv, secp256k1.S256()):
		return CurveS256
	default:
		return nil
	}
}

func decodeOID(src []byte) asn1enc.ObjectIdentifier {
	x := cryptobyte.String(src)
	var oid asn1enc.ObjectIdentifier
	if !x.ReadASN1ObjectIdentifier(&oid) {
		return nil
	}
	return oid
}

type ECDSAPrivateKey struct {
	o   *Object
	oid asn1enc.ObjectIdentifier
}

type ECDSAPrivateKeyEx struct {
	ecdsa.PublicKey
	ECDSAPrivateKey
}

func (e *ECDSAPrivateKeyEx) Public() crypto.PublicKey { return &e.PublicKey }

var _ crypto.Signer = (*ECDSAPrivateKeyEx)(nil)

func newECDSAPrivateKey(o *Object, oid asn1enc.ObjectIdentifier) (PrivateKey, error) {
	if oid == nil {
		var ecParams attr.AttrECParams
		if err := o.GetAttributes(&ecParams); err != nil {
			return nil, err
		}
		if oid = decodeOID(ecParams.Value); oid == nil {
			return nil, errors.New("pkcs11: error decoding curve OID")
		}
	}

	if pub, err := newECDSAPublicKey(o, oid); err == nil {
		return &ECDSAPrivateKeyEx{
			PublicKey: pub.PublicKey,
			ECDSAPrivateKey: ECDSAPrivateKey{
				o:   o,
				oid: oid,
			},
		}, nil
	}
	return &ECDSAPrivateKey{
		o:   o,
		oid: oid,
	}, nil
}

func (e *ECDSAPrivateKey) Object() *Object               { return e.o }
func (e *ECDSAPrivateKey) OID() asn1enc.ObjectIdentifier { return e.oid }

// Curve returns nil if the private key has unknown OID
func (e *ECDSAPrivateKey) Curve() elliptic.Curve { return oidToCurve(e.oid) }

func (e *ECDSAPrivateKey) ecParams() []byte {
	var b cryptobyte.Builder
	b.AddASN1ObjectIdentifier(e.oid)
	return b.BytesOrPanic()
}

func (e *ECDSAPrivateKey) kt() attr.KType { return attr.KeyEC }
func (e *ECDSAPrivateKey) pubFilter() []attr.Attribute {
	return []attr.Attribute{attr.ECParams(e.ecParams())}
}

func (e *ECDSAPrivateKey) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	// http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cs01/pkcs11-curr-v2.40-cs01.html#_Toc399398884
	m := C.CK_MECHANISM{
		mechanism: C.CKM_ECDSA,
	}

	sig, err := e.o.sign(&m, digest)
	if err != nil {
		return nil, err
	}
	r := new(big.Int).SetBytes(sig[:len(sig)/2])
	s := new(big.Int).SetBytes(sig[len(sig)/2:])

	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1BigInt(r)
		b.AddASN1BigInt(s)
	})

	return b.Bytes()
}

func (*ECDSAPrivateKey) Extractable() {}

func curveEq(a, b elliptic.Curve) bool {
	ap, bp := a.Params(), b.Params()
	pOk := subtle.ConstantTimeCompare(ap.P.Bytes(), bp.P.Bytes()) == 1
	nOk := subtle.ConstantTimeCompare(ap.N.Bytes(), bp.N.Bytes()) == 1
	bOk := subtle.ConstantTimeCompare(ap.B.Bytes(), bp.B.Bytes()) == 1
	gxOk := subtle.ConstantTimeCompare(ap.Gx.Bytes(), bp.Gx.Bytes()) == 1
	gyOk := subtle.ConstantTimeCompare(ap.Gy.Bytes(), bp.Gy.Bytes()) == 1
	return ap.BitSize == bp.BitSize && pOk && nOk && bOk && gxOk && gyOk
}

type ECDSAPublicKey struct {
	ecdsa.PublicKey
	o *Object
}

func newECDSAPublicKey(o *Object, oid asn1enc.ObjectIdentifier) (*ECDSAPublicKey, error) {
	// http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cs01/pkcs11-curr-v2.40-cs01.html#_Toc399398881
	var ecPoint attr.AttrECPoint
	if err := o.GetAttributes(&ecPoint); err != nil {
		return nil, err
	}
	if oid == nil {
		var ecParams attr.AttrECParams
		if err := o.GetAttributes(&ecParams); err != nil {
			return nil, err
		}
		if oid = decodeOID(ecParams.Value); oid == nil {
			return nil, errors.New("pkcs11: error decoding curve OID")
		}
	}
	curve := oidToCurve(oid)
	if curve == nil {
		return nil, fmt.Errorf("pkcs11: unsupported curve %v", oid)
	}

	pt := decodeOctetString(ecPoint.Value)
	if pt == nil {
		return nil, fmt.Errorf("pkcs11: error decoding EC point")
	}

	x, y := unmarshalECPoint(curve, pt)
	if x == nil {
		return nil, errors.New("pkcs11: invalid EC point format")
	}
	return &ECDSAPublicKey{
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
		},
		o: o,
	}, nil
}

func (k *ECDSAPublicKey) Object() *Object          { return k.o }
func (k *ECDSAPublicKey) Public() crypto.PublicKey { return &k.PublicKey }

func (s *Session) GenerateECDSAKeyPair(oid asn1enc.ObjectIdentifier, pubOpt []attr.Attribute, privOpt []attr.Attribute) (*ECDSAPublicKey, *ECDSAPrivateKey, error) {
	var pinner runtime.Pinner
	defer pinner.Unpin()

	var oidBuilder cryptobyte.Builder
	oidBuilder.AddASN1ObjectIdentifier(oid)
	ecParam, _ := oidBuilder.Bytes()

	privOpt = append(privOpt,
		attr.Private(1),
		attr.Sensitive(1),
		attr.Sign(1),
	)
	privTpl := buildTemplate(privOpt, &pinner)

	pubOpt = append(pubOpt,
		attr.ECParams(ecParam),
		attr.Verify(1),
	)
	pubTpl := buildTemplate(pubOpt, &pinner)

	mechanism := C.CK_MECHANISM{
		mechanism: C.CKM_EC_KEY_PAIR_GEN,
	}
	var (
		pubH  C.CK_OBJECT_HANDLE
		privH C.CK_OBJECT_HANDLE
	)
	err := s.ft.C_GenerateKeyPair(
		s.h, &mechanism,
		&pubTpl[0], C.CK_ULONG(len(pubTpl)),
		&privTpl[0], C.CK_ULONG(len(privTpl)),
		&pubH, &privH,
	)

	if err != nil {
		return nil, nil, err
	}

	pubObj, err := s.newObject(pubH)
	if err != nil {
		return nil, nil, err
	}
	pub, err := newECDSAPublicKey(pubObj, oid)
	if err != nil {
		return nil, nil, err
	}
	privObj, err := s.newObject(privH)
	if err != nil {
		return nil, nil, err
	}
	priv, err := newECDSAPrivateKey(privObj, oid)
	if err != nil {
		return nil, nil, err
	}

	var rawPriv *ECDSAPrivateKey
	switch p := priv.(type) {
	case *ECDSAPrivateKey:
		rawPriv = p
	case *ECDSAPrivateKeyEx:
		rawPriv = &p.ECDSAPrivateKey
	default:
		panic(fmt.Sprintf("pkcs11: unexpected key type %T", priv))
	}
	return pub, rawPriv, nil
}

func (s *Session) CreateECDSAPublicKey(src *ecdsa.PublicKey, attrs ...attr.Attribute) (*ECDSAPublicKey, error) {
	var pinner runtime.Pinner
	defer pinner.Unpin()

	oid := curveToOID(src.Curve)
	if oid == nil {
		return nil, fmt.Errorf("pkcs11: unsupported curve %T", src.Curve)
	}
	var oidBuilder cryptobyte.Builder
	oidBuilder.AddASN1ObjectIdentifier(oid)
	ecParam, _ := oidBuilder.Bytes()
	ecPoint := encodeOctetString(marshalECPoint(src.Curve, src.X, src.Y))
	attrs = append(attrs,
		attr.Class(attr.ClassPublicKey),
		attr.KeyType(attr.KeyEC),
		attr.ECParams(ecParam),
		attr.ECPoint(ecPoint),
		attr.Verify(1),
	)
	tpl := buildTemplate(attrs, &pinner)
	var handle C.CK_OBJECT_HANDLE
	if err := s.ft.C_CreateObject(s.h, &tpl[0], C.CK_ULONG(len(tpl)), &handle); err != nil {
		return nil, err
	}
	obj, err := s.newObject(handle)
	if err != nil {
		return nil, err
	}
	return &ECDSAPublicKey{
		PublicKey: *src,
		o:         obj,
	}, nil
}

package pkcs11

/*
#include "platform.h"
*/
import "C"
import (
	"crypto"
	"crypto/ed25519"
	"fmt"
	"io"
	"runtime"

	"github.com/ecadlabs/go-pkcs11/pkcs11/attr"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

func decodePrintable(src []byte) (string, bool) {
	x := cryptobyte.String(src)
	var curve cryptobyte.String
	if !x.ReadASN1(&curve, asn1.PrintableString) {
		return "", false
	}
	return string(curve), true
}

const ed25519Curve = "edwards25519"

type Ed25519PrivateKey Object

type Ed25519PrivateKeyEx struct {
	ed25519.PublicKey
	*Ed25519PrivateKey
}

func (e *Ed25519PrivateKeyEx) Public() crypto.PublicKey { return e.PublicKey }

var _ crypto.Signer = (*Ed25519PrivateKeyEx)(nil)

func encodePrintable(src string) []byte {
	var b cryptobyte.Builder
	b.AddASN1(asn1.PrintableString, func(child *cryptobyte.Builder) {
		child.AddBytes([]byte(src))
	})
	return b.BytesOrPanic()
}

func newEd25519PrivateKey(o *Object, checkECParams bool) (PrivateKey, error) {
	if checkECParams {
		var ecParams attr.AttrECParams
		if err := o.GetAttributes(&ecParams); err != nil {
			return nil, err
		}
		curve, ok := decodePrintable(ecParams.Value)
		if !ok {
			return nil, fmt.Errorf("pkcs11: error decoding curve ID")
		}
		if curve != ed25519Curve {
			return nil, fmt.Errorf("pkcs11: unsupported curve %s", string(curve))
		}
	}
	if pub, err := newEd25519PublicKey(o, false); err == nil {
		return &Ed25519PrivateKeyEx{
			PublicKey:         pub.PublicKey,
			Ed25519PrivateKey: (*Ed25519PrivateKey)(o),
		}, nil
	}
	return (*Ed25519PrivateKey)(o), nil
}

func (e *Ed25519PrivateKey) Object() *Object { return (*Object)(e) }

func (e *Ed25519PrivateKey) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	m := C.CK_MECHANISM{
		mechanism: C.CKM_EDDSA,
	}
	return (*Object)(e).sign(&m, digest)
}

func (*Ed25519PrivateKey) Extractable() {}

func (e *Ed25519PrivateKey) kt() attr.KType { return attr.KeyECEdwards }
func (e *Ed25519PrivateKey) pubFilter() []attr.Attribute {
	return []attr.Attribute{attr.ECParams(encodePrintable(ed25519Curve))}
}

type Ed25519PublicKey struct {
	ed25519.PublicKey
	o *Object
}

func newEd25519PublicKey(o *Object, checkECParams bool) (*Ed25519PublicKey, error) {
	if checkECParams {
		var ecParams attr.AttrECParams
		if err := o.GetAttributes(&ecParams); err != nil {
			return nil, err
		}
		curve, ok := decodePrintable(ecParams.Value)
		if !ok {
			return nil, fmt.Errorf("pkcs11: error decoding curve ID")
		}
		if curve != ed25519Curve {
			return nil, fmt.Errorf("pkcs11: unsupported curve %s", string(curve))
		}
	}

	var ecPoint attr.AttrECPoint
	if err := o.GetAttributes(&ecPoint); err != nil {
		return nil, err
	}

	pt := decodeOctetString(ecPoint.Value)
	if pt == nil {
		return nil, fmt.Errorf("pkcs11: error decoding EC point")
	}
	if len(pt) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("pkcs11: invalid Ed25519 public key length %d", len(pt))
	}

	return &Ed25519PublicKey{
		PublicKey: ed25519.PublicKey(pt),
		o:         o,
	}, nil
}

func (e *Ed25519PublicKey) Object() *Object          { return e.o }
func (e *Ed25519PublicKey) Public() crypto.PublicKey { return e.PublicKey }

func (s *Session) GenerateEd25519KeyPair(pubOpt, privOpt []attr.Attribute) (*Ed25519PublicKey, *Ed25519PrivateKey, error) {
	var pinner runtime.Pinner
	defer pinner.Unpin()

	privOpt = append(privOpt,
		attr.Private(1),
		attr.Sensitive(1),
		attr.Sign(1),
	)
	privTmpl := buildTemplate(privOpt, &pinner)

	ecParam := encodePrintable("edwards25519")
	pubOpt = append(pubOpt,
		attr.ECParams(ecParam),
		attr.Verify(1),
	)
	pubTmpl := buildTemplate(pubOpt, &pinner)

	mechanism := C.CK_MECHANISM{
		mechanism: C.CKM_EC_EDWARDS_KEY_PAIR_GEN,
	}
	var (
		pubH  C.CK_OBJECT_HANDLE
		privH C.CK_OBJECT_HANDLE
	)

	err := s.ft.C_GenerateKeyPair(
		s.h, &mechanism,
		&pubTmpl[0], C.CK_ULONG(len(pubTmpl)),
		&privTmpl[0], C.CK_ULONG(len(privTmpl)),
		&pubH, &privH,
	)

	if err != nil {
		return nil, nil, err
	}

	pubObj, err := s.newObject(pubH)
	if err != nil {
		return nil, nil, err
	}
	pub, err := newEd25519PublicKey(pubObj, false)
	if err != nil {
		return nil, nil, err
	}
	privObj, err := s.newObject(privH)
	if err != nil {
		return nil, nil, err
	}
	priv, err := newEd25519PrivateKey(privObj, false)
	if err != nil {
		return nil, nil, err
	}

	var rawPriv *Ed25519PrivateKey
	switch p := priv.(type) {
	case *Ed25519PrivateKey:
		rawPriv = p
	case *Ed25519PrivateKeyEx:
		rawPriv = p.Ed25519PrivateKey
	default:
		panic(fmt.Sprintf("pkcs11: unexpected key type %T", priv))
	}
	return pub, rawPriv, nil
}

func (s *Session) CreateEd25519PublicKey(src ed25519.PublicKey, opt ...attr.Attribute) (*Ed25519PublicKey, error) {
	var pinner runtime.Pinner
	defer pinner.Unpin()

	ecParam := encodePrintable("edwards25519")
	ecPoint := encodeOctetString(src)

	opt = append(opt,
		attr.Class(attr.ClassPublicKey),
		attr.KeyType(attr.KeyECEdwards),
		attr.ECParams(ecParam),
		attr.ECPoint(ecPoint),
		attr.Verify(1),
	)
	tpl := buildTemplate(opt, &pinner)

	var handle C.CK_OBJECT_HANDLE
	if err := s.ft.C_CreateObject(s.h, &tpl[0], C.CK_ULONG(len(tpl)), &handle); err != nil {
		return nil, err
	}
	obj, err := s.newObject(handle)
	if err != nil {
		return nil, err
	}
	return &Ed25519PublicKey{
		PublicKey: src,
		o:         obj,
	}, nil
}

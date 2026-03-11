package pkcs11

/*
#include "platform.h"
*/
import "C"
import (
	"runtime"

	"github.com/ecadlabs/go-pkcs11/pkcs11/attr"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

func FindMatchingPublicKey(priv PrivateKey, flags MatchFlags) (PublicKey, error) {
	o := priv.Object()
	kt := priv.kt()
	optFilter := priv.pubFilter()
	fl := make([]attr.Attribute, 0, 4+len(optFilter))
	fl = append(fl,
		attr.Class(attr.ClassPublicKey),
		attr.KeyType(kt),
	)
	if flags&MatchLabel != 0 && len(o.label) != 0 {
		fl = append(fl, attr.Label(o.label))
	}
	if flags&MatchID != 0 && len(o.id) != 0 {
		fl = append(fl, attr.ID(o.id))
	}
	fl = append(fl, optFilter...)

	objects, err := o.slot.Objects(fl...)
	if err != nil {
		return nil, err
	}
	if len(objects) == 0 {
		return nil, ErrPublicKey
	} else if len(objects) > 1 {
		return nil, ErrNonUnique
	}
	return newPublicKey(objects[0], kt)
}

func decodeOctetString(src []byte) []byte {
	x := cryptobyte.String(src)
	var pt cryptobyte.String
	if !x.ReadASN1(&pt, asn1.OCTET_STRING) {
		return nil
	}
	return pt
}

func encodeOctetString(src []byte) []byte {
	var b cryptobyte.Builder
	b.AddASN1OctetString(src)
	return b.BytesOrPanic()
}

// bytePtr returns a CK_BYTE pointer to the first element of buf, or nil if
// buf is empty. Prevents index-out-of-range panics at the C boundary.
func bytePtr(buf []byte) *C.CK_BYTE {
	if len(buf) == 0 {
		return nil
	}
	return (*C.CK_BYTE)(&buf[0])
}

func buildTemplate(attrs []attr.Attribute, pinner *runtime.Pinner) []C.CK_ATTRIBUTE {
	out := make([]C.CK_ATTRIBUTE, len(attrs))
	for i, a := range attrs {
		p := a.Ptr()
		if p != nil {
			pinner.Pin(p)
		}
		out[i] = C.CK_ATTRIBUTE{
			_type:      C.CK_ATTRIBUTE_TYPE(a.Type()),
			pValue:     C.CK_VOID_PTR(p),
			ulValueLen: C.CK_ULONG(a.Len()),
		}
	}
	return out
}

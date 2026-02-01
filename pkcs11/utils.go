package pkcs11

import (
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

func FindMatchingPublicKey(priv PrivateKey, flags MatchFlags) (PublicKey, error) {
	o := priv.Object()
	kt := priv.kt()
	optFilter := priv.pubFilter()
	fl := make([]TypeValue, 0, 4+len(optFilter))
	fl = append(fl, TypeValue{AttributeClass, NewScalarV(ClassPublicKey)}, TypeValue{AttributeKeyType, NewScalarV(kt)})
	if flags&MatchLabel != 0 && len(o.label) != 0 {
		fl = append(fl, TypeValue{AttributeLabel, NewArray(o.label)})
	}
	if flags&MatchID != 0 && len(o.id) != 0 {
		fl = append(fl, TypeValue{AttributeID, NewArray(o.id)})
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
	return objects[0].publicKey(kt)
}

func decodeOctetString(src []byte) []byte {
	x := cryptobyte.String(src)
	var pt cryptobyte.String
	if !x.ReadASN1(&pt, asn1.OCTET_STRING) {
		return nil
	}
	return pt
}

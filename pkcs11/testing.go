package pkcs11

/*
#include "platform.h"
*/
import "C"
import (
	"crypto/elliptic"
	"crypto/x509"
	asn1enc "encoding/asn1"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"unsafe"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

type createSlotOptions struct {
	SecurityOfficerPIN string
	UserPIN            string
	Label              string
}

// createSlot configures a slot object. Internally this calls C_InitToken and
// C_InitPIN to set the admin and user PIN on the slot.
func (m *Module) createSlot(id uint, opts createSlotOptions) error {
	if opts.Label == "" {
		return errors.New("no label provided")
	}
	if opts.UserPIN == "" {
		return errors.New("no user pin provided")
	}
	if opts.SecurityOfficerPIN == "" {
		return errors.New("no admin pin provided")
	}

	var cLabel [32]C.CK_UTF8CHAR
	if !ckStringPadded(cLabel[:], opts.Label) {
		return errors.New("label is too long")
	}

	cPIN := []C.CK_UTF8CHAR(opts.SecurityOfficerPIN)
	cPINLen := C.CK_ULONG(len(cPIN))

	err := m.ft.C_InitToken(
		C.CK_SLOT_ID(id),
		&cPIN[0],
		cPINLen,
		&cLabel[0],
	)
	if err != nil {
		return err
	}

	s, err := m.Slot(id, OptSecurityOfficerPIN(opts.SecurityOfficerPIN), OptReadWrite)
	if err != nil {
		return fmt.Errorf("getting slot: %w", err)
	}
	defer s.Close()

	cUserPIN := []C.CK_UTF8CHAR(opts.UserPIN)
	cUserPINLen := C.CK_ULONG(len(cUserPIN))
	if err := s.ft.C_InitPIN(s.h, &cUserPIN[0], cUserPINLen); err != nil {
		return fmt.Errorf("configuring user pin: %w", err)
	}
	if err := s.ft.C_Logout(s.h); err != nil {
		return fmt.Errorf("logout: %w", err)
	}
	return nil
}

type createCertificateOptions struct {
	Label           string
	X509Certificate *x509.Certificate
}

// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#_Toc416959709
func (s *Slot) createX509Certificate(opts createCertificateOptions) (*Object, error) {
	if opts.X509Certificate == nil {
		return nil, errors.New("no certificate provided")
	}

	objClass := C.CK_OBJECT_CLASS(C.CKO_CERTIFICATE)
	ct := C.CK_CERTIFICATE_TYPE(C.CKC_X_509)

	var pinner runtime.Pinner
	defer pinner.Unpin()
	pinner.Pin(&objClass)
	pinner.Pin(&ct)
	pinner.Pin(&opts.X509Certificate.RawSubject[0])
	pinner.Pin(&opts.X509Certificate.Raw[0])

	attrs := []C.CK_ATTRIBUTE{
		{C.CKA_CLASS, C.CK_VOID_PTR(&objClass), C.CK_ULONG(unsafe.Sizeof(objClass))},
		{C.CKA_CERTIFICATE_TYPE, C.CK_VOID_PTR(&ct), C.CK_ULONG(unsafe.Sizeof(ct))},
		{C.CKA_SUBJECT, C.CK_VOID_PTR(&opts.X509Certificate.RawSubject[0]), C.CK_ULONG(len(opts.X509Certificate.RawSubject))},
		{C.CKA_VALUE, C.CK_VOID_PTR(&opts.X509Certificate.Raw[0]), C.CK_ULONG(len(opts.X509Certificate.Raw))},
	}

	if opts.Label != "" {
		cs := []byte(opts.Label)
		pinner.Pin(&cs[0])
		attrs = append(attrs, C.CK_ATTRIBUTE{
			C.CKA_LABEL,
			C.CK_VOID_PTR(&cs[0]),
			C.CK_ULONG(len(opts.Label)),
		})
	}

	var h C.CK_OBJECT_HANDLE
	if err := s.ft.C_CreateObject(s.h, &attrs[0], C.CK_ULONG(len(attrs)), &h); err != nil {
		return nil, err
	}
	obj, err := s.newObject(h)
	if err != nil {
		return nil, err
	}
	return obj, nil
}

// ecdsaKeyOptions holds parameters used for generating a private key.
type ecdsaKeyOptions struct {
	// Curve indicates that the generated key should be an ECDSA key and
	// identifies the curve used to generate the key.
	Curve elliptic.Curve

	// Label for the final object.
	LabelPublic  string
	LabelPrivate string
}

// generateECDSA implements the CKM_ECDSA_KEY_PAIR_GEN mechanism.
//
// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#_Toc416959719
// https://datatracker.ietf.org/doc/html/rfc5480#section-2.1.1.1
// http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/os/pkcs11-curr-v2.40-os.html#_Toc416960014
func (s *Slot) generateECDSA(o *ecdsaKeyOptions) (PrivateKey, error) {
	if o.Curve == nil {
		return nil, errors.New("no curve provided")
	}

	var pinner runtime.Pinner
	defer pinner.Unpin()

	var oid asn1enc.ObjectIdentifier
	curveName := o.Curve.Params().Name
	switch {
	case o.Curve == elliptic.P224() || curveName == "P-224":
		oid = oidCurveP224
	case o.Curve == elliptic.P256() || curveName == "P-256":
		oid = oidCurveP256
	case o.Curve == elliptic.P384() || curveName == "P-384":
		oid = oidCurveP384
	case o.Curve == elliptic.P521() || curveName == "P-512":
		oid = oidCurveP521
	case o.Curve == secp256k1.S256() || strings.EqualFold(curveName, "secp256k1") || strings.EqualFold(curveName, "P-256k1"):
		oid = oidCurveS256
	default:
		return nil, errors.New("unsupported ECDSA curve")
	}

	var oidBuilder cryptobyte.Builder
	oidBuilder.AddASN1ObjectIdentifier(oid)
	ecParam, _ := oidBuilder.Bytes()
	pinner.Pin(&ecParam[0])

	cTrue := C.CK_BBOOL(C.CK_TRUE)
	cFalse := C.CK_BBOOL(C.CK_FALSE)
	pinner.Pin(&cTrue)
	pinner.Pin(&cFalse)

	privTmpl := []C.CK_ATTRIBUTE{
		{C.CKA_PRIVATE, C.CK_VOID_PTR(&cTrue), C.CK_ULONG(unsafe.Sizeof(cTrue))},
		{C.CKA_SENSITIVE, C.CK_VOID_PTR(&cTrue), C.CK_ULONG(unsafe.Sizeof(cTrue))},
		{C.CKA_SIGN, C.CK_VOID_PTR(&cTrue), C.CK_ULONG(unsafe.Sizeof(cTrue))},
	}

	if o.LabelPrivate != "" {
		cs := []byte(o.LabelPrivate)
		pinner.Pin(&cs[0])

		privTmpl = append(privTmpl, C.CK_ATTRIBUTE{
			C.CKA_LABEL,
			C.CK_VOID_PTR(&cs[0]),
			C.CK_ULONG(len(o.LabelPrivate)),
		})
	}

	pubTmpl := []C.CK_ATTRIBUTE{
		{C.CKA_EC_PARAMS, C.CK_VOID_PTR(&ecParam[0]), C.CK_ULONG(len(ecParam))},
		{C.CKA_VERIFY, C.CK_VOID_PTR(&cTrue), C.CK_ULONG(unsafe.Sizeof(cTrue))},
	}
	if o.LabelPublic != "" {
		cs := []byte(o.LabelPublic)
		pinner.Pin(&cs[0])

		pubTmpl = append(pubTmpl, C.CK_ATTRIBUTE{
			C.CKA_LABEL,
			C.CK_VOID_PTR(&cs[0]),
			C.CK_ULONG(len(o.LabelPublic)),
		})
	}

	mechanism := C.CK_MECHANISM{
		mechanism: C.CKM_EC_KEY_PAIR_GEN,
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
		return nil, err
	}

	privObj, err := s.newObject(privH)
	if err != nil {
		return nil, fmt.Errorf("private key object: %w", err)
	}
	priv, err := privObj.PrivateKey()
	if err != nil {
		return nil, fmt.Errorf("parsing private key: %w", err)
	}
	return priv, nil
}

type ed25519KeyOptions struct {
	LabelPublic  string
	LabelPrivate string
}

func (s *Slot) generateEd25519(o *ed25519KeyOptions) (PrivateKey, error) {
	var pinner runtime.Pinner
	defer pinner.Unpin()

	var paramBuilder cryptobyte.Builder
	paramBuilder.AddASN1(asn1.PrintableString, func(c *cryptobyte.Builder) {
		c.AddBytes([]byte("edwards25519"))
	})
	ecParam, _ := paramBuilder.Bytes()
	pinner.Pin(&ecParam[0])

	cTrue := C.CK_BBOOL(C.CK_TRUE)
	cFalse := C.CK_BBOOL(C.CK_FALSE)
	pinner.Pin(&cTrue)
	pinner.Pin(&cFalse)

	privTmpl := []C.CK_ATTRIBUTE{
		{C.CKA_PRIVATE, C.CK_VOID_PTR(&cTrue), C.CK_ULONG(unsafe.Sizeof(cTrue))},
		{C.CKA_SENSITIVE, C.CK_VOID_PTR(&cTrue), C.CK_ULONG(unsafe.Sizeof(cTrue))},
		{C.CKA_SIGN, C.CK_VOID_PTR(&cTrue), C.CK_ULONG(unsafe.Sizeof(cTrue))},
	}

	if o.LabelPrivate != "" {
		cs := []byte(o.LabelPrivate)
		pinner.Pin(&cs[0])

		privTmpl = append(privTmpl, C.CK_ATTRIBUTE{
			C.CKA_LABEL,
			C.CK_VOID_PTR(&cs[0]),
			C.CK_ULONG(len(o.LabelPrivate)),
		})
	}

	pubTmpl := []C.CK_ATTRIBUTE{
		{C.CKA_EC_PARAMS, C.CK_VOID_PTR(&ecParam[0]), C.CK_ULONG(len(ecParam))},
		{C.CKA_VERIFY, C.CK_VOID_PTR(&cTrue), C.CK_ULONG(unsafe.Sizeof(cTrue))},
	}
	if o.LabelPublic != "" {
		cs := []byte(o.LabelPublic)
		pinner.Pin(&cs[0])

		pubTmpl = append(pubTmpl, C.CK_ATTRIBUTE{
			C.CKA_LABEL,
			C.CK_VOID_PTR(&cs[0]),
			C.CK_ULONG(len(o.LabelPublic)),
		})
	}

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
		return nil, err
	}

	privObj, err := s.newObject(privH)
	if err != nil {
		return nil, fmt.Errorf("private key object: %w", err)
	}
	priv, err := privObj.PrivateKey()
	if err != nil {
		return nil, fmt.Errorf("parsing private key: %w", err)
	}
	return priv, nil
}

// ckStringPadded copies a string into b, padded with ' '. If the string is larger
// than the provided buffer, this function returns false.
func ckStringPadded(b []C.CK_UTF8CHAR, s string) bool {
	if len(s) > len(b) {
		return false
	}
	copy(b, []C.CK_UTF8CHAR(s))
	for i := len(s); i < len(b); i++ {
		b[i] = ' '
	}
	return true
}

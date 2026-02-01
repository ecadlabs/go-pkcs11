package pkcs11

/*
#include "platform.h"
*/
import "C"
import (
	"crypto/x509"
	"errors"
	"fmt"
	"runtime"
	"unsafe"
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

	s, err := m.NewSession(id, OptSecurityOfficerPIN(opts.SecurityOfficerPIN), OptReadWrite)
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
func (s *Session) createX509Certificate(opts createCertificateOptions) (*Object, error) {
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

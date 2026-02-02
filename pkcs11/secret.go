package pkcs11

/*
#include "platform.h"
*/
import "C"
import (
	"runtime"

	"github.com/ecadlabs/go-pkcs11/pkcs11/attr"
)

type GenericSecretKey struct {
	lenBytes int
	o        *Object
}

func (g *GenericSecretKey) Len() int        { return g.lenBytes }
func (g *GenericSecretKey) Object() *Object { return g.o }
func (*GenericSecretKey) Extractable()      {}

func (s *Session) GenerateGenericSecretKey(keyLen int, opt ...attr.Attribute) (*GenericSecretKey, error) {
	var pinner runtime.Pinner
	defer pinner.Unpin()

	opt = append(opt,
		attr.Private(1),
		attr.Sensitive(1),
		attr.Derive(1),
		attr.ValueLen(attr.Uint(keyLen)),
	)
	tpl := buildTemplate(opt, &pinner)
	mechanism := C.CK_MECHANISM{
		mechanism: C.CKM_GENERIC_SECRET_KEY_GEN,
	}
	var handle C.CK_OBJECT_HANDLE
	if err := s.ft.C_GenerateKey(s.h, &mechanism, &tpl[0], C.CK_ULONG(len(tpl)), &handle); err != nil {
		return nil, err
	}
	obj, err := s.newObject(handle)
	if err != nil {
		return nil, err
	}
	return &GenericSecretKey{
		lenBytes: keyLen,
		o:        obj,
	}, nil
}

type AESSecretKey GenericSecretKey

func (g *AESSecretKey) Len() int        { return g.lenBytes }
func (g *AESSecretKey) Object() *Object { return g.o }
func (*AESSecretKey) Extractable()      {}

func (s *Session) GenerateAESSecretKey(keyLen int, opt ...attr.Attribute) (*AESSecretKey, error) {
	var pinner runtime.Pinner
	defer pinner.Unpin()

	opt = append(opt,
		attr.Private(1),
		attr.Sensitive(1),
		attr.Encrypt(1),
		attr.Decrypt(1),
		attr.ValueLen(attr.Uint(keyLen)),
	)
	tpl := buildTemplate(opt, &pinner)
	mechanism := C.CK_MECHANISM{
		mechanism: C.CKM_AES_KEY_GEN,
	}
	var handle C.CK_OBJECT_HANDLE
	if err := s.ft.C_GenerateKey(s.h, &mechanism, &tpl[0], C.CK_ULONG(len(tpl)), &handle); err != nil {
		return nil, err
	}
	obj, err := s.newObject(handle)
	if err != nil {
		return nil, err
	}
	return &AESSecretKey{
		lenBytes: keyLen,
		o:        obj,
	}, nil
}

package pkcs11

/*
#include "platform.h"
*/
import "C"
import (
	"crypto"
	"crypto/rsa"
	"fmt"
	"io"
	"math/big"
	"runtime"
	"unsafe"

	"github.com/ecadlabs/go-pkcs11/pkcs11/attr"
)

type RSAPrivateKey struct {
	rsa.PublicKey
	o *Object
}

func (r *RSAPrivateKey) Object() *Object          { return r.o }
func (r *RSAPrivateKey) Private() PrivateKey      { return r }
func (r *RSAPrivateKey) Public() crypto.PublicKey { return r.PublicKey }

func hashMechanism(h crypto.Hash) (C.CK_MECHANISM_TYPE, C.CK_RSA_PKCS_MGF_TYPE, error) {
	switch h {
	case crypto.SHA1:
		return C.CKM_SHA_1, C.CKG_MGF1_SHA1, nil
	case crypto.SHA224:
		return C.CKM_SHA224, C.CKG_MGF1_SHA224, nil
	case crypto.SHA256:
		return C.CKM_SHA256, C.CKG_MGF1_SHA256, nil
	case crypto.SHA384:
		return C.CKM_SHA384, C.CKG_MGF1_SHA384, nil
	case crypto.SHA512:
		return C.CKM_SHA512, C.CKG_MGF1_SHA512, nil
	case crypto.SHA3_224:
		return C.CKM_SHA3_224, C.CKG_MGF1_SHA3_224, nil
	case crypto.SHA3_256:
		return C.CKM_SHA3_256, C.CKG_MGF1_SHA3_256, nil
	case crypto.SHA3_384:
		return C.CKM_SHA3_384, C.CKG_MGF1_SHA3_384, nil
	case crypto.SHA3_512:
		return C.CKM_SHA3_512, C.CKG_MGF1_SHA3_512, nil
	default:
		return 0, 0, fmt.Errorf("pkcs11: unknown hash function %v", h)
	}
}

func (r *RSAPrivateKey) SignPSS(hash crypto.Hash, digest []byte, saltLength int) ([]byte, error) {
	m := C.CK_MECHANISM{
		mechanism: C.CKM_RSA_PKCS_PSS,
	}
	params := C.CK_RSA_PKCS_PSS_PARAMS{
		sLen: C.CK_ULONG(saltLength),
	}
	var err error
	params.hashAlg, params.mgf, err = hashMechanism(hash)
	if err != nil {
		return nil, err
	}
	var pinner runtime.Pinner
	defer pinner.Unpin()
	pinner.Pin(&params)

	m.pParameter = C.CK_VOID_PTR(&params)
	m.ulParameterLen = C.CK_ULONG(unsafe.Sizeof(params))
	return r.o.sign(&m, digest)
}

func (r *RSAPrivateKey) SignPKCS1v15(digest []byte) ([]byte, error) {
	m := C.CK_MECHANISM{
		mechanism: C.CKM_RSA_PKCS,
	}
	return r.o.sign(&m, digest)
}

func (r *RSAPrivateKey) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if pssOpts, ok := opts.(*rsa.PSSOptions); ok {
		return r.SignPSS(pssOpts.Hash, digest, pssOpts.SaltLength)
	}
	return r.SignPKCS1v15(digest)
}

func (r *RSAPrivateKey) DecryptOAEP(hash crypto.Hash, ciphertext []byte, label []byte) ([]byte, error) {
	m := C.CK_MECHANISM{
		mechanism: C.CKM_RSA_PKCS_OAEP,
	}
	var pinner runtime.Pinner
	defer pinner.Unpin()
	params := C.CK_RSA_PKCS_OAEP_PARAMS{
		source: C.CKZ_DATA_SPECIFIED, // SoftSHM2 requires this field to be always set
	}
	if label != nil {
		params.pSourceData = C.CK_VOID_PTR(&label[0])
		params.ulSourceDataLen = C.CK_ULONG(len(label))
		pinner.Pin(&label[0])
	}
	var err error
	params.hashAlg, params.mgf, err = hashMechanism(hash)
	if err != nil {
		return nil, err
	}
	pinner.Pin(&params)
	m.pParameter = C.CK_VOID_PTR(&params)
	m.ulParameterLen = C.CK_ULONG(unsafe.Sizeof(params))
	return r.o.decrypt(&m, ciphertext)
}

func (r *RSAPrivateKey) DecryptPKCS1v15(ciphertext []byte) ([]byte, error) {
	m := C.CK_MECHANISM{
		mechanism: C.CKM_RSA_PKCS,
	}
	return r.o.decrypt(&m, ciphertext)
}

func (r *RSAPrivateKey) Decrypt(_ io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) (plaintext []byte, err error) {
	if oaepOpts, ok := opts.(*rsa.OAEPOptions); ok {
		return r.DecryptOAEP(oaepOpts.Hash, ciphertext, oaepOpts.Label)
	}
	return r.DecryptPKCS1v15(ciphertext)
}

func (*RSAPrivateKey) Extractable() {}

var _ crypto.Decrypter = (*RSAPrivateKey)(nil)

func (r *RSAPrivateKey) kt() attr.KType { return attr.KeyRSA }
func (r *RSAPrivateKey) pubFilter() []attr.Attribute {
	return []attr.Attribute{
		attr.Modulus(r.N.Bytes()),
		attr.PublicExponent(big.NewInt(int64(r.E)).Bytes()),
	}
}

func newRSAPrivateKey(o *Object) (*RSAPrivateKey, error) {
	var (
		mod attr.AttrModulus
		exp attr.AttrPublicExponent
	)
	if err := o.GetAttributes(&mod, &exp); err != nil {
		return nil, err
	}
	return &RSAPrivateKey{
		PublicKey: rsa.PublicKey{
			N: new(big.Int).SetBytes(mod.Value),
			E: int(new(big.Int).SetBytes(exp.Value).Int64()),
		},
		o: o,
	}, nil
}

var _ crypto.Signer = (*RSAPrivateKey)(nil)

type RSAPublicKey RSAPrivateKey

func (r *RSAPublicKey) Object() *Object          { return r.o }
func (r *RSAPublicKey) Public() crypto.PublicKey { return &r.PublicKey }

func initOAEP(hash crypto.Hash, label []byte, pinner *runtime.Pinner) (*C.CK_MECHANISM, error) {
	m := C.CK_MECHANISM{
		mechanism: C.CKM_RSA_PKCS_OAEP,
	}
	params := C.CK_RSA_PKCS_OAEP_PARAMS{
		source: C.CKZ_DATA_SPECIFIED, // SoftSHM2 requires this field to be always set
	}
	if label != nil {
		params.pSourceData = C.CK_VOID_PTR(&label[0])
		params.ulSourceDataLen = C.CK_ULONG(len(label))
		pinner.Pin(&label[0])
	}
	var err error
	params.hashAlg, params.mgf, err = hashMechanism(hash)
	if err != nil {
		return nil, err
	}
	pinner.Pin(&params)
	m.pParameter = C.CK_VOID_PTR(&params)
	m.ulParameterLen = C.CK_ULONG(unsafe.Sizeof(params))
	return &m, nil
}

func (r *RSAPublicKey) EncryptOAEP(hash crypto.Hash, msg []byte, label []byte) ([]byte, error) {
	var pinner runtime.Pinner
	defer pinner.Unpin()
	m, err := initOAEP(hash, label, &pinner)
	if err != nil {
		return nil, err
	}
	return r.o.encrypt(m, msg)
}

func (r *RSAPublicKey) EncryptPKCS1v15(msg []byte) ([]byte, error) {
	m := C.CK_MECHANISM{
		mechanism: C.CKM_RSA_PKCS,
	}
	return r.o.encrypt(&m, msg)
}

func (r *RSAPublicKey) WrapOAEP(k Extractable, hash crypto.Hash, label []byte) ([]byte, error) {
	var pinner runtime.Pinner
	defer pinner.Unpin()
	m, err := initOAEP(hash, label, &pinner)
	if err != nil {
		return nil, err
	}
	return r.o.wrap(m, k.Object())
}

func (r *RSAPublicKey) WrapPKCS1v15(k Extractable) ([]byte, error) {
	m := C.CK_MECHANISM{
		mechanism: C.CKM_RSA_PKCS,
	}
	return r.o.wrap(&m, k.Object())
}

func (s *Session) GenerateRSAKeyPair(bits, exp int, pubOpt, privOpt []attr.Attribute) (*RSAPublicKey, *RSAPrivateKey, error) {
	if exp == 0 {
		exp = 0x10001 // PKCS#11 default value
	}

	var pinner runtime.Pinner
	defer pinner.Unpin()

	privOpt = append(privOpt,
		attr.Private(1),
		attr.Sensitive(1),
		attr.Sign(1),
		attr.Decrypt(1),
		attr.Unwrap(1),
	)
	privTmpl := buildTemplate(privOpt, &pinner)

	pubOpt = append(pubOpt,
		attr.ModulusBits(attr.Uint(bits)),
		attr.PublicExponent(big.NewInt(int64(exp)).Bytes()),
		attr.Verify(1),
		attr.Encrypt(1),
		attr.Wrap(1),
	)
	pubTmpl := buildTemplate(pubOpt, &pinner)

	mechanism := C.CK_MECHANISM{
		mechanism: C.CKM_RSA_PKCS_KEY_PAIR_GEN,
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
	pub, err := newRSAPrivateKey(pubObj)
	if err != nil {
		return nil, nil, err
	}
	privObj, err := s.newObject(privH)
	if err != nil {
		return nil, nil, err
	}
	priv, err := newRSAPrivateKey(privObj)
	if err != nil {
		return nil, nil, err
	}

	return (*RSAPublicKey)(pub), priv, nil
}

func (s *Session) CreateRSAPublicKey(src *rsa.PublicKey, opt ...attr.Attribute) (*RSAPublicKey, error) {
	var pinner runtime.Pinner
	defer pinner.Unpin()

	opt = append(opt,
		attr.Class(attr.ClassPublicKey),
		attr.KeyType(attr.KeyRSA),
		attr.Modulus(src.N.Bytes()),
		attr.PublicExponent(big.NewInt(int64(src.E)).Bytes()),
		attr.Encrypt(1),
		attr.Wrap(1),
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
	return &RSAPublicKey{
		PublicKey: *src,
		o:         obj,
	}, nil
}

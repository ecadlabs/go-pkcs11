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
)

func (s *Session) GenerateRSAKeyPair(bits, exp int, pubOpt, privOpt *KeyOptions) (*RSAPublicKey, *RSAPrivateKey, error) {
	if exp == 0 {
		exp = 0x10001 // PKCS#11 default value
	}

	var pinner runtime.Pinner
	defer pinner.Unpin()

	cTrue := C.CK_BBOOL(C.CK_TRUE)
	cFalse := C.CK_BBOOL(C.CK_FALSE)
	pinner.Pin(&cTrue)
	pinner.Pin(&cFalse)

	privTmpl := []C.CK_ATTRIBUTE{
		{C.CKA_PRIVATE, C.CK_VOID_PTR(&cTrue), C.CK_ULONG(unsafe.Sizeof(cTrue))},
		{C.CKA_SENSITIVE, C.CK_VOID_PTR(&cTrue), C.CK_ULONG(unsafe.Sizeof(cTrue))},
		{C.CKA_SIGN, C.CK_VOID_PTR(&cTrue), C.CK_ULONG(unsafe.Sizeof(cTrue))},
		{C.CKA_DECRYPT, C.CK_VOID_PTR(&cTrue), C.CK_ULONG(unsafe.Sizeof(cTrue))},
		{C.CKA_UNWRAP, C.CK_VOID_PTR(&cTrue), C.CK_ULONG(unsafe.Sizeof(cTrue))},
	}
	if privOpt != nil {
		privOpt.fillTemplate(&privTmpl, &pinner)
	}

	cBits := C.CK_ULONG(bits)
	cExp := big.NewInt(int64(exp)).Bytes()
	pinner.Pin(&cBits)
	pinner.Pin(&cExp[0])

	pubTmpl := []C.CK_ATTRIBUTE{
		{C.CKA_MODULUS_BITS, C.CK_VOID_PTR(&cBits), C.CK_ULONG(unsafe.Sizeof(cBits))},
		{C.CKA_PUBLIC_EXPONENT, C.CK_VOID_PTR(&cExp[0]), C.CK_ULONG(len(cExp))},
		{C.CKA_VERIFY, C.CK_VOID_PTR(&cTrue), C.CK_ULONG(unsafe.Sizeof(cTrue))},
		{C.CKA_ENCRYPT, C.CK_VOID_PTR(&cTrue), C.CK_ULONG(unsafe.Sizeof(cTrue))},
		{C.CKA_WRAP, C.CK_VOID_PTR(&cTrue), C.CK_ULONG(unsafe.Sizeof(cTrue))},
	}
	if pubOpt != nil {
		pubOpt.fillTemplate(&pubTmpl, &pinner)
	}

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

var _ crypto.Decrypter = (*RSAPrivateKey)(nil)

func (r *RSAPrivateKey) kt() KeyType { return KeyRSA }
func (r *RSAPrivateKey) pubFilter() []TypeValue {
	return []TypeValue{
		{AttributeModulus, NewArray(r.N.Bytes())},
		{AttributePublicExponent, NewArray(big.NewInt(int64(r.E)).Bytes())},
	}
}

func newRSAPrivateKey(o *Object) (*RSAPrivateKey, error) {
	mod := NewArray[[]byte](nil)
	exp := NewArray[[]byte](nil)
	if err := o.GetAttributes(TypeValue{AttributeModulus, mod}, TypeValue{AttributePublicExponent, exp}); err != nil {
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
func (r *RSAPublicKey) Public() crypto.PublicKey { return r.PublicKey }

func (r *RSAPublicKey) EncryptOAEP(hash crypto.Hash, msg []byte, label []byte) ([]byte, error) {
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
	return r.o.encrypt(&m, msg)
}

func (r *RSAPublicKey) EncryptPKCS1v15(msg []byte) ([]byte, error) {
	m := C.CK_MECHANISM{
		mechanism: C.CKM_RSA_PKCS,
	}
	return r.o.encrypt(&m, msg)
}

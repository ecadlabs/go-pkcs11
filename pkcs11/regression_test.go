package pkcs11

import (
	"crypto"
	"crypto/rsa"
	"math/big"
	"runtime"
	"testing"
	"unsafe"

	"github.com/ecadlabs/go-pkcs11/pkcs11/attr"
	"github.com/stretchr/testify/require"
)

func TestSlotIDsHandlesZeroSlotsWithoutPanic(t *testing.T) {
	mod := &Module{api: &panicTestAPIMock}
	var (
		ids []uint
		err error
	)

	require.NotPanics(t, func() {
		ids, err = mod.SlotIDs()
	})
	require.NoError(t, err)
	require.Empty(t, ids)
}

func newMockObject(api pkcs11API) *Object {
	return &Object{
		slot: &Session{
			mod: &Module{api: api},
			h:   1,
		},
		h: 1,
	}
}

func TestGetAttributesNoArgumentsDoesNotPanic(t *testing.T) {
	obj := newMockObject(&panicTestAPIMock)
	var err error
	require.NotPanics(t, func() {
		err = obj.GetAttributes()
	})
	require.NoError(t, err)
}

func TestGetAttributesZeroLengthDestinationDoesNotPanic(t *testing.T) {
	obj := newMockObject(&panicTestAPIMock)
	v := new(attr.AttrLabel)

	var err error
	require.NotPanics(t, func() {
		err = obj.GetAttributes(v)
	})
	require.NoError(t, err)
}

func TestBuildTemplateZeroLengthValueDoesNotPanic(t *testing.T) {
	var pinner runtime.Pinner
	defer pinner.Unpin()

	require.NotPanics(t, func() {
		buildTemplate([]attr.Attribute{attr.Label(attr.String{})}, &pinner)
	})
}

func TestDecryptOAEPEmptyLabelDoesNotPanic(t *testing.T) {
	obj := newMockObject(&panicTestAPIMock)
	priv := &RSAPrivateKey{o: obj}

	require.NotPanics(t, func() {
		_, _ = priv.DecryptOAEP(crypto.SHA256, []byte{1}, []byte{})
	})
}

func TestEncryptOAEPEmptyLabelDoesNotPanic(t *testing.T) {
	obj := newMockObject(&panicTestAPIMock)
	pub := &RSAPublicKey{o: obj}

	require.NotPanics(t, func() {
		_, _ = pub.EncryptOAEP(crypto.SHA256, []byte{1}, []byte{})
	})
}

func TestSignEmptyBufferDoesNotPanic(t *testing.T) {
	obj := newMockObject(&panicTestAPIMock)
	require.NotPanics(t, func() {
		m := _Ctype_CK_MECHANISM{mechanism: _Ciconst_CKM_RSA_PKCS}
		_, _ = obj.sign(&m, []byte{})
	})
}

func TestEncryptEmptyBufferDoesNotPanic(t *testing.T) {
	obj := newMockObject(&panicTestAPIMock)
	require.NotPanics(t, func() {
		m := _Ctype_CK_MECHANISM{mechanism: _Ciconst_CKM_RSA_PKCS}
		_, _ = obj.encrypt(&m, []byte{})
	})
}

func TestDecryptEmptyBufferDoesNotPanic(t *testing.T) {
	obj := newMockObject(&panicTestAPIMock)
	require.NotPanics(t, func() {
		m := _Ctype_CK_MECHANISM{mechanism: _Ciconst_CKM_RSA_PKCS}
		_, _ = obj.decrypt(&m, []byte{})
	})
}

func TestWrapZeroLengthBufferDoesNotPanic(t *testing.T) {
	obj := newMockObject(&panicTestAPIMock)
	require.NotPanics(t, func() {
		m := _Ctype_CK_MECHANISM{mechanism: _Ciconst_CKM_RSA_PKCS}
		_, _ = obj.wrap(&m, obj)
	})
}

func TestSignPSSZeroValueOptionsDoesNotPanic(t *testing.T) {
	obj := newMockObject(&panicTestAPIMock)
	key := &RSAPrivateKey{
		PublicKey: rsa.PublicKey{N: big.NewInt(1), E: 65537},
		o:         obj,
	}

	var err error
	require.NotPanics(t, func() {
		// Zero-value PSSOptions has Hash=0 and SaltLength=PSSSaltLengthAuto.
		// crypto.Hash(0).Size() panics, so resolvePSSSaltLength must
		// validate the hash before calling Size().
		_, err = key.Sign(nil, []byte{0}, &rsa.PSSOptions{})
	})
	require.Error(t, err)
}

func TestSignPSSUnsupportedNonZeroHashReturnsError(t *testing.T) {
	obj := newMockObject(&panicTestAPIMock)
	key := &RSAPrivateKey{
		PublicKey: rsa.PublicKey{N: big.NewInt(1), E: 65537},
		o:         obj,
	}

	_, err := key.Sign(nil, []byte{0}, &rsa.PSSOptions{
		Hash:       crypto.Hash(9999),
		SaltLength: rsa.PSSSaltLengthAuto,
	})
	require.Error(t, err)
}

var panicTestAPIMock = apiMock{
	_C_GetSlotList: func(tokenPresent _Ctype_CK_BBOOL, pSlotList _Ctype_CK_SLOT_ID_PTR, pulCount _Ctype_CK_ULONG_PTR) error {
		*pulCount = 0
		return nil
	},

	_C_GetAttributeValue: func(hSession _Ctype_CK_SESSION_HANDLE, hObject _Ctype_CK_OBJECT_HANDLE, pTemplate _Ctype_CK_ATTRIBUTE_PTR, ulCount _Ctype_CK_ULONG) error {
		tpl := unsafe.Slice((*_Ctype_CK_ATTRIBUTE)(unsafe.Pointer(pTemplate)), int(ulCount))
		for i := range tpl {
			tpl[i].ulValueLen = 0
		}
		return nil
	},

	_C_Sign: func(hSession _Ctype_CK_SESSION_HANDLE, pData _Ctype_CK_BYTE_PTR, ulDataLen _Ctype_CK_ULONG, pSignature _Ctype_CK_BYTE_PTR, pulSignatureLen _Ctype_CK_ULONG_PTR) error {
		if pSignature == nil {
			*pulSignatureLen = 64
		} else if *pulSignatureLen != 0 {
			buf := unsafe.Slice((*byte)(unsafe.Pointer(pSignature)), int(*pulSignatureLen))
			for i := range buf {
				buf[i] = 0
			}
		}
		return nil
	},

	_C_SignFinal: func(hSession _Ctype_CK_SESSION_HANDLE, pSignature _Ctype_CK_BYTE_PTR, pulSignatureLen _Ctype_CK_ULONG_PTR) error {
		return nil
	},

	_C_SignInit: func(hSession _Ctype_CK_SESSION_HANDLE, pMechanism _Ctype_CK_MECHANISM_PTR, hKey _Ctype_CK_OBJECT_HANDLE) error {
		return nil
	},

	_C_Encrypt: func(hSession _Ctype_CK_SESSION_HANDLE, pData _Ctype_CK_BYTE_PTR, ulDataLen _Ctype_CK_ULONG, pEncryptedData _Ctype_CK_BYTE_PTR, pulEncryptedDataLen _Ctype_CK_ULONG_PTR) error {
		if pEncryptedData == nil {
			*pulEncryptedDataLen = ulDataLen
		} else if *pulEncryptedDataLen != 0 {
			buf := unsafe.Slice((*byte)(unsafe.Pointer(pEncryptedData)), int(*pulEncryptedDataLen))
			for i := range buf {
				buf[i] = 0
			}
		}
		return nil
	},

	_C_EncryptFinal: func(hSession _Ctype_CK_SESSION_HANDLE, pLastEncryptedPart _Ctype_CK_BYTE_PTR, pulLastEncryptedPartLen _Ctype_CK_ULONG_PTR) error {
		return nil
	},

	_C_EncryptInit: func(hSession _Ctype_CK_SESSION_HANDLE, pMechanism _Ctype_CK_MECHANISM_PTR, hKey _Ctype_CK_OBJECT_HANDLE) error {
		return nil
	},

	_C_Decrypt: func(hSession _Ctype_CK_SESSION_HANDLE, pEncryptedData _Ctype_CK_BYTE_PTR, ulEncryptedDataLen _Ctype_CK_ULONG, pData _Ctype_CK_BYTE_PTR, pulDataLen _Ctype_CK_ULONG_PTR) error {
		if pData == nil {
			*pulDataLen = ulEncryptedDataLen
		} else if *pulDataLen != 0 {
			buf := unsafe.Slice((*byte)(unsafe.Pointer(pData)), int(*pulDataLen))
			for i := range buf {
				buf[i] = 0
			}
		}
		return nil
	},

	_C_DecryptFinal: func(hSession _Ctype_CK_SESSION_HANDLE, pLastPart _Ctype_CK_BYTE_PTR, pulLastPartLen _Ctype_CK_ULONG_PTR) error {
		return nil
	},

	_C_DecryptInit: func(hSession _Ctype_CK_SESSION_HANDLE, pMechanism _Ctype_CK_MECHANISM_PTR, hKey _Ctype_CK_OBJECT_HANDLE) error {
		return nil
	},

	_C_WrapKey: func(hSession _Ctype_CK_SESSION_HANDLE, pMechanism _Ctype_CK_MECHANISM_PTR, hWrappingKey _Ctype_CK_OBJECT_HANDLE, hKey _Ctype_CK_OBJECT_HANDLE, pWrappedKey _Ctype_CK_BYTE_PTR, pulWrappedKeyLen _Ctype_CK_ULONG_PTR) error {
		if pWrappedKey == nil {
			*pulWrappedKeyLen = 0
		}
		return nil
	},
}

func TestGetAttributesScalarLengthMismatchReturnsError(t *testing.T) {
	obj := newMockObject(&apiMock{
		_C_GetAttributeValue: func(hSession, hObject _Ctype_CK_OBJECT_HANDLE, pTemplate _Ctype_CK_ATTRIBUTE_PTR, ulCount _Ctype_CK_ULONG) error {
			if pTemplate == nil || ulCount == 0 {
				return &Error{
					code:   _Ciconst_CKR_ARGUMENTS_BAD,
					fnName: "C_GetAttributeValue",
				}
			}
			tpl := unsafe.Slice((*_Ctype_CK_ATTRIBUTE)(unsafe.Pointer(pTemplate)), int(ulCount))
			if tpl[0].pValue == nil {
				tpl[0].ulValueLen = _Ctype_CK_ULONG(sizeof[_Ctype_CK_OBJECT_CLASS]()) + 1
			}
			return nil
		},
	})
	var class attr.AttrClass
	err := obj.GetAttributes(&class)
	require.Error(t, err)
}

func TestGetAttributesHugeLengthDoesNotPanicAndReturnsError(t *testing.T) {
	obj := newMockObject(&apiMock{
		_C_GetAttributeValue: func(hSession, hObject _Ctype_CK_OBJECT_HANDLE, pTemplate _Ctype_CK_ATTRIBUTE_PTR, ulCount _Ctype_CK_ULONG) error {
			if pTemplate == nil || ulCount == 0 {
				return &Error{
					code:   _Ciconst_CKR_ARGUMENTS_BAD,
					fnName: "C_GetAttributeValue",
				}
			}
			tpl := unsafe.Slice((*_Ctype_CK_ATTRIBUTE)(unsafe.Pointer(pTemplate)), int(ulCount))
			if tpl[0].pValue == nil {
				tpl[0].ulValueLen = ^_Ctype_CK_ULONG(0) - 1
			}
			return nil
		},
	})
	var label attr.AttrLabel
	var err error
	require.NotPanics(t, func() {
		err = obj.GetAttributes(&label)
	})
	require.Error(t, err)
}

func TestGetAttributesRejectsOversizedLength(t *testing.T) {
	obj := newMockObject(&apiMock{
		_C_GetAttributeValue: func(hSession, hObject _Ctype_CK_OBJECT_HANDLE, pTemplate _Ctype_CK_ATTRIBUTE_PTR, ulCount _Ctype_CK_ULONG) error {
			if pTemplate == nil || ulCount == 0 {
				return &Error{
					code:   _Ciconst_CKR_ARGUMENTS_BAD,
					fnName: "C_GetAttributeValue",
				}
			}
			tpl := unsafe.Slice((*_Ctype_CK_ATTRIBUTE)(unsafe.Pointer(pTemplate)), int(ulCount))
			if tpl[0].pValue == nil {
				tpl[0].ulValueLen = 2 << 20
			}
			return nil
		},
	})
	var label attr.AttrLabel
	err := obj.GetAttributes(&label)
	require.Error(t, err)
}

func TestSignRejectsOversizedSignatureLength(t *testing.T) {
	obj := newMockObject(&apiMock{
		_C_SignInit: func(hSession _Ctype_CK_SESSION_HANDLE, pMechanism _Ctype_CK_MECHANISM_PTR, hKey _Ctype_CK_OBJECT_HANDLE) error {
			return nil
		},
		_C_Sign: func(hSession _Ctype_CK_SESSION_HANDLE, pData _Ctype_CK_BYTE_PTR, ulDataLen _Ctype_CK_ULONG, pSignature _Ctype_CK_BYTE_PTR, pulSignatureLen _Ctype_CK_ULONG_PTR) error {
			if pulSignatureLen == nil {
				return &Error{
					code:   _Ciconst_CKR_ARGUMENTS_BAD,
					fnName: "C_Sign",
				}
			}
			if pSignature == nil {
				*pulSignatureLen = 2 << 20
			} else if *pulSignatureLen != 0 {
				buf := unsafe.Slice((*byte)(unsafe.Pointer(pSignature)), int(*pulSignatureLen))
				for i := range buf {
					buf[i] = 0
				}
			}
			return nil
		},
	})
	key := &RSAPrivateKey{o: obj}

	sig, err := key.SignPKCS1v15([]byte{1})
	require.Error(t, err, "token-reported oversized signature length should be rejected")
	require.Nil(t, sig)
}

//go:build testharness

package pkcs11

import (
	"crypto"
	"crypto/rsa"
	"math/big"
	"runtime"
	"testing"

	"github.com/ecadlabs/go-pkcs11/pkcs11/attr"
	"github.com/stretchr/testify/require"
)

func TestSlotIDsHandlesZeroSlotsWithoutPanic(t *testing.T) {
	mod := &Module{ft: panicTestFunctionTable()}

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

func TestGetAttributesNoArgumentsDoesNotPanic(t *testing.T) {
	obj := panicTestObject()

	var err error
	require.NotPanics(t, func() {
		err = obj.GetAttributes()
	})
	require.NoError(t, err)
}

func TestGetAttributesZeroLengthDestinationDoesNotPanic(t *testing.T) {
	obj := panicTestObject()
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
	obj := panicTestObject()
	priv := &RSAPrivateKey{o: obj}

	require.NotPanics(t, func() {
		_, _ = priv.DecryptOAEP(crypto.SHA256, []byte{1}, []byte{})
	})
}

func TestEncryptOAEPEmptyLabelDoesNotPanic(t *testing.T) {
	obj := panicTestObject()
	pub := &RSAPublicKey{o: obj}

	require.NotPanics(t, func() {
		_, _ = pub.EncryptOAEP(crypto.SHA256, []byte{1}, []byte{})
	})
}

func TestSignEmptyBufferDoesNotPanic(t *testing.T) {
	obj := panicTestObject()
	require.NotPanics(t, func() {
		panicTestSignEmpty(obj)
	})
}

func TestEncryptEmptyBufferDoesNotPanic(t *testing.T) {
	obj := panicTestObject()

	require.NotPanics(t, func() {
		panicTestEncryptEmpty(obj)
	})
}

func TestDecryptEmptyBufferDoesNotPanic(t *testing.T) {
	obj := panicTestObject()

	require.NotPanics(t, func() {
		panicTestDecryptEmpty(obj)
	})
}

func TestWrapZeroLengthBufferDoesNotPanic(t *testing.T) {
	obj := panicTestObject()

	require.NotPanics(t, func() {
		panicTestWrapEmptyResult(obj)
	})
}

func TestSignPSSZeroValueOptionsDoesNotPanic(t *testing.T) {
	obj := panicTestObject()
	key := &RSAPrivateKey{
		PublicKey: rsa.PublicKey{N: big.NewInt(1), E: 65537},
		o:        obj,
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

func TestSignPSSNegativeSaltLengthReturnsError(t *testing.T) {
	obj := panicTestObject()
	key := &RSAPrivateKey{
		PublicKey: rsa.PublicKey{N: big.NewInt(1), E: 65537},
		o:        obj,
	}

	_, err := key.SignPSS(crypto.SHA256, []byte{0}, -42)
	require.Error(t, err)
}

func TestSignPSSUnsupportedNonZeroHashReturnsError(t *testing.T) {
	obj := panicTestObject()
	key := &RSAPrivateKey{
		PublicKey: rsa.PublicKey{N: big.NewInt(1), E: 65537},
		o:        obj,
	}

	_, err := key.Sign(nil, []byte{0}, &rsa.PSSOptions{
		Hash:       crypto.Hash(9999),
		SaltLength: rsa.PSSSaltLengthAuto,
	})
	require.Error(t, err)
}

func TestResolvePSSSaltLengthAutoTooSmallKeyReturnsError(t *testing.T) {
	// 256-bit key with SHA-512 gives maxSalt = 32 - 64 - 2 < 0.
	_, err := resolvePSSSaltLength(rsa.PSSSaltLengthAuto, crypto.SHA512, 256)
	require.Error(t, err)
}

func TestSlotIDsZeroSlotsReturnsNonNilSlice(t *testing.T) {
	mod := &Module{ft: panicTestFunctionTable()}
	ids, err := mod.SlotIDs()
	require.NoError(t, err)
	require.NotNil(t, ids)
	require.Empty(t, ids)
}

func TestGetAttributesScalarLengthMismatchReturnsError(t *testing.T) {
	obj := mismatchLenObject()

	var class attr.AttrClass
	err := obj.GetAttributes(&class)
	require.Error(t, err)
}

func TestGetAttributesHugeLengthDoesNotPanicAndReturnsError(t *testing.T) {
	obj := hugeLenObject()
	var label attr.AttrLabel

	var err error
	require.NotPanics(t, func() {
		err = obj.GetAttributes(&label)
	})
	require.Error(t, err)
}

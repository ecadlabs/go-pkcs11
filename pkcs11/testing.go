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

	err := m.api.C_InitToken(
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
	if err := s.mod.api.C_InitPIN(s.h, &cUserPIN[0], cUserPINLen); err != nil {
		return fmt.Errorf("configuring user pin: %w", err)
	}
	if err := s.mod.api.C_Logout(s.h); err != nil {
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
	if err := s.mod.api.C_CreateObject(s.h, &attrs[0], C.CK_ULONG(len(attrs)), &h); err != nil {
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

type apiMock struct {
	_C_Initialize func(
		pInitArgs C.CK_VOID_PTR,
	) error
	_C_Finalize func(
		pReserved C.CK_VOID_PTR,
	) error
	_C_GetInfo func(
		pInfo C.CK_INFO_PTR,
	) error
	_C_GetFunctionList func(
		ppFunctionList C.CK_FUNCTION_LIST_PTR_PTR,
	) error
	_C_GetSlotList func(
		tokenPresent C.CK_BBOOL,
		pSlotList C.CK_SLOT_ID_PTR,
		pulCount C.CK_ULONG_PTR,
	) error
	_C_GetSlotInfo func(
		slotID C.CK_SLOT_ID,
		pInfo C.CK_SLOT_INFO_PTR,
	) error
	_C_GetTokenInfo func(
		slotID C.CK_SLOT_ID,
		pInfo C.CK_TOKEN_INFO_PTR,
	) error
	_C_GetMechanismList func(
		slotID C.CK_SLOT_ID,
		pMechanismList C.CK_MECHANISM_TYPE_PTR,
		pulCount C.CK_ULONG_PTR,
	) error
	_C_GetMechanismInfo func(
		slotID C.CK_SLOT_ID,
		_type C.CK_MECHANISM_TYPE,
		pInfo C.CK_MECHANISM_INFO_PTR,
	) error
	_C_InitToken func(
		slotID C.CK_SLOT_ID,
		pPin C.CK_UTF8CHAR_PTR,
		ulPinLen C.CK_ULONG,
		pLabel C.CK_UTF8CHAR_PTR,
	) error
	_C_InitPIN func(
		hSession C.CK_SESSION_HANDLE,
		pPin C.CK_UTF8CHAR_PTR,
		ulPinLen C.CK_ULONG,
	) error
	_C_SetPIN func(
		hSession C.CK_SESSION_HANDLE,
		pOldPin C.CK_UTF8CHAR_PTR,
		ulOldLen C.CK_ULONG,
		pNewPin C.CK_UTF8CHAR_PTR,
		ulNewLen C.CK_ULONG,
	) error
	_C_OpenSession func(
		slotID C.CK_SLOT_ID,
		flags C.CK_FLAGS,
		pApplication C.CK_VOID_PTR,
		Notify C.CK_NOTIFY,
		phSession C.CK_SESSION_HANDLE_PTR,
	) error
	_C_CloseSession func(
		hSession C.CK_SESSION_HANDLE,
	) error
	_C_CloseAllSessions func(
		slotID C.CK_SLOT_ID,
	) error
	_C_GetSessionInfo func(
		hSession C.CK_SESSION_HANDLE,
		pInfo C.CK_SESSION_INFO_PTR,
	) error
	_C_GetOperationState func(
		hSession C.CK_SESSION_HANDLE,
		pOperationState C.CK_BYTE_PTR,
		pulOperationStateLen C.CK_ULONG_PTR,
	) error
	_C_SetOperationState func(
		hSession C.CK_SESSION_HANDLE,
		pOperationState C.CK_BYTE_PTR,
		ulOperationStateLen C.CK_ULONG,
		hEncryptionKey C.CK_OBJECT_HANDLE,
		hAuthenticationKey C.CK_OBJECT_HANDLE,
	) error
	_C_Login func(
		hSession C.CK_SESSION_HANDLE,
		userType C.CK_USER_TYPE,
		pPin C.CK_UTF8CHAR_PTR,
		ulPinLen C.CK_ULONG,
	) error
	_C_Logout func(
		hSession C.CK_SESSION_HANDLE,
	) error
	_C_CreateObject func(
		hSession C.CK_SESSION_HANDLE,
		pTemplate C.CK_ATTRIBUTE_PTR,
		ulCount C.CK_ULONG,
		phObject C.CK_OBJECT_HANDLE_PTR,
	) error
	_C_CopyObject func(
		hSession C.CK_SESSION_HANDLE,
		hObject C.CK_OBJECT_HANDLE,
		pTemplate C.CK_ATTRIBUTE_PTR,
		ulCount C.CK_ULONG,
		phNewObject C.CK_OBJECT_HANDLE_PTR,
	) error
	_C_DestroyObject func(
		hSession C.CK_SESSION_HANDLE,
		hObject C.CK_OBJECT_HANDLE,
	) error
	_C_GetObjectSize func(
		hSession C.CK_SESSION_HANDLE,
		hObject C.CK_OBJECT_HANDLE,
		pulSize C.CK_ULONG_PTR,
	) error
	_C_GetAttributeValue func(
		hSession C.CK_SESSION_HANDLE,
		hObject C.CK_OBJECT_HANDLE,
		pTemplate C.CK_ATTRIBUTE_PTR,
		ulCount C.CK_ULONG,
	) error
	_C_SetAttributeValue func(
		hSession C.CK_SESSION_HANDLE,
		hObject C.CK_OBJECT_HANDLE,
		pTemplate C.CK_ATTRIBUTE_PTR,
		ulCount C.CK_ULONG,
	) error
	_C_FindObjectsInit func(
		hSession C.CK_SESSION_HANDLE,
		pTemplate C.CK_ATTRIBUTE_PTR,
		ulCount C.CK_ULONG,
	) error
	_C_FindObjects func(
		hSession C.CK_SESSION_HANDLE,
		phObject C.CK_OBJECT_HANDLE_PTR,
		ulMaxObjectCount C.CK_ULONG,
		pulObjectCount C.CK_ULONG_PTR,
	) error
	_C_FindObjectsFinal func(
		hSession C.CK_SESSION_HANDLE,
	) error
	_C_EncryptInit func(
		hSession C.CK_SESSION_HANDLE,
		pMechanism C.CK_MECHANISM_PTR,
		hKey C.CK_OBJECT_HANDLE,
	) error
	_C_Encrypt func(
		hSession C.CK_SESSION_HANDLE,
		pData C.CK_BYTE_PTR,
		ulDataLen C.CK_ULONG,
		pEncryptedData C.CK_BYTE_PTR,
		pulEncryptedDataLen C.CK_ULONG_PTR,
	) error
	_C_EncryptUpdate func(
		hSession C.CK_SESSION_HANDLE,
		pPart C.CK_BYTE_PTR,
		ulPartLen C.CK_ULONG,
		pEncryptedPart C.CK_BYTE_PTR,
		pulEncryptedPartLen C.CK_ULONG_PTR,
	) error
	_C_EncryptFinal func(
		hSession C.CK_SESSION_HANDLE,
		pLastEncryptedPart C.CK_BYTE_PTR,
		pulLastEncryptedPartLen C.CK_ULONG_PTR,
	) error
	_C_DecryptInit func(
		hSession C.CK_SESSION_HANDLE,
		pMechanism C.CK_MECHANISM_PTR,
		hKey C.CK_OBJECT_HANDLE,
	) error
	_C_Decrypt func(
		hSession C.CK_SESSION_HANDLE,
		pEncryptedData C.CK_BYTE_PTR,
		ulEncryptedDataLen C.CK_ULONG,
		pData C.CK_BYTE_PTR,
		pulDataLen C.CK_ULONG_PTR,
	) error
	_C_DecryptUpdate func(
		hSession C.CK_SESSION_HANDLE,
		pEncryptedPart C.CK_BYTE_PTR,
		ulEncryptedPartLen C.CK_ULONG,
		pPart C.CK_BYTE_PTR,
		pulPartLen C.CK_ULONG_PTR,
	) error
	_C_DecryptFinal func(
		hSession C.CK_SESSION_HANDLE,
		pLastPart C.CK_BYTE_PTR,
		pulLastPartLen C.CK_ULONG_PTR,
	) error
	_C_DigestInit func(
		hSession C.CK_SESSION_HANDLE,
		pMechanism C.CK_MECHANISM_PTR,
	) error
	_C_Digest func(
		hSession C.CK_SESSION_HANDLE,
		pData C.CK_BYTE_PTR,
		ulDataLen C.CK_ULONG,
		pDigest C.CK_BYTE_PTR,
		pulDigestLen C.CK_ULONG_PTR,
	) error
	_C_DigestUpdate func(
		hSession C.CK_SESSION_HANDLE,
		pPart C.CK_BYTE_PTR,
		ulPartLen C.CK_ULONG,
	) error
	_C_DigestKey func(
		hSession C.CK_SESSION_HANDLE,
		hKey C.CK_OBJECT_HANDLE,
	) error
	_C_DigestFinal func(
		hSession C.CK_SESSION_HANDLE,
		pDigest C.CK_BYTE_PTR,
		pulDigestLen C.CK_ULONG_PTR,
	) error
	_C_SignInit func(
		hSession C.CK_SESSION_HANDLE,
		pMechanism C.CK_MECHANISM_PTR,
		hKey C.CK_OBJECT_HANDLE,
	) error
	_C_Sign func(
		hSession C.CK_SESSION_HANDLE,
		pData C.CK_BYTE_PTR,
		ulDataLen C.CK_ULONG,
		pSignature C.CK_BYTE_PTR,
		pulSignatureLen C.CK_ULONG_PTR,
	) error
	_C_SignUpdate func(
		hSession C.CK_SESSION_HANDLE,
		pPart C.CK_BYTE_PTR,
		ulPartLen C.CK_ULONG,
	) error
	_C_SignFinal func(
		hSession C.CK_SESSION_HANDLE,
		pSignature C.CK_BYTE_PTR,
		pulSignatureLen C.CK_ULONG_PTR,
	) error
	_C_SignRecoverInit func(
		hSession C.CK_SESSION_HANDLE,
		pMechanism C.CK_MECHANISM_PTR,
		hKey C.CK_OBJECT_HANDLE,
	) error
	_C_SignRecover func(
		hSession C.CK_SESSION_HANDLE,
		pData C.CK_BYTE_PTR,
		ulDataLen C.CK_ULONG,
		pSignature C.CK_BYTE_PTR,
		pulSignatureLen C.CK_ULONG_PTR,
	) error
	_C_VerifyInit func(
		hSession C.CK_SESSION_HANDLE,
		pMechanism C.CK_MECHANISM_PTR,
		hKey C.CK_OBJECT_HANDLE,
	) error
	_C_Verify func(
		hSession C.CK_SESSION_HANDLE,
		pData C.CK_BYTE_PTR,
		ulDataLen C.CK_ULONG,
		pSignature C.CK_BYTE_PTR,
		ulSignatureLen C.CK_ULONG,
	) error
	_C_VerifyUpdate func(
		hSession C.CK_SESSION_HANDLE,
		pPart C.CK_BYTE_PTR,
		ulPartLen C.CK_ULONG,
	) error
	_C_VerifyFinal func(
		hSession C.CK_SESSION_HANDLE,
		pSignature C.CK_BYTE_PTR,
		ulSignatureLen C.CK_ULONG,
	) error
	_C_VerifyRecoverInit func(
		hSession C.CK_SESSION_HANDLE,
		pMechanism C.CK_MECHANISM_PTR,
		hKey C.CK_OBJECT_HANDLE,
	) error
	_C_VerifyRecover func(
		hSession C.CK_SESSION_HANDLE,
		pSignature C.CK_BYTE_PTR,
		ulSignatureLen C.CK_ULONG,
		pData C.CK_BYTE_PTR,
		pulDataLen C.CK_ULONG_PTR,
	) error
	_C_DigestEncryptUpdate func(
		hSession C.CK_SESSION_HANDLE,
		pPart C.CK_BYTE_PTR,
		ulPartLen C.CK_ULONG,
		pEncryptedPart C.CK_BYTE_PTR,
		pulEncryptedPartLen C.CK_ULONG_PTR,
	) error
	_C_DecryptDigestUpdate func(
		hSession C.CK_SESSION_HANDLE,
		pEncryptedPart C.CK_BYTE_PTR,
		ulEncryptedPartLen C.CK_ULONG,
		pPart C.CK_BYTE_PTR,
		pulPartLen C.CK_ULONG_PTR,
	) error
	_C_SignEncryptUpdate func(
		hSession C.CK_SESSION_HANDLE,
		pPart C.CK_BYTE_PTR,
		ulPartLen C.CK_ULONG,
		pEncryptedPart C.CK_BYTE_PTR,
		pulEncryptedPartLen C.CK_ULONG_PTR,
	) error
	_C_DecryptVerifyUpdate func(
		hSession C.CK_SESSION_HANDLE,
		pEncryptedPart C.CK_BYTE_PTR,
		ulEncryptedPartLen C.CK_ULONG,
		pPart C.CK_BYTE_PTR,
		pulPartLen C.CK_ULONG_PTR,
	) error
	_C_GenerateKey func(
		hSession C.CK_SESSION_HANDLE,
		pMechanism C.CK_MECHANISM_PTR,
		pTemplate C.CK_ATTRIBUTE_PTR,
		ulCount C.CK_ULONG,
		phKey C.CK_OBJECT_HANDLE_PTR,
	) error
	_C_GenerateKeyPair func(
		hSession C.CK_SESSION_HANDLE,
		pMechanism C.CK_MECHANISM_PTR,
		pPublicKeyTemplate C.CK_ATTRIBUTE_PTR,
		ulPublicKeyAttributeCount C.CK_ULONG,
		pPrivateKeyTemplate C.CK_ATTRIBUTE_PTR,
		ulPrivateKeyAttributeCount C.CK_ULONG,
		phPublicKey C.CK_OBJECT_HANDLE_PTR,
		phPrivateKey C.CK_OBJECT_HANDLE_PTR,
	) error
	_C_WrapKey func(
		hSession C.CK_SESSION_HANDLE,
		pMechanism C.CK_MECHANISM_PTR,
		hWrappingKey C.CK_OBJECT_HANDLE,
		hKey C.CK_OBJECT_HANDLE,
		pWrappedKey C.CK_BYTE_PTR,
		pulWrappedKeyLen C.CK_ULONG_PTR,
	) error
	_C_UnwrapKey func(
		hSession C.CK_SESSION_HANDLE,
		pMechanism C.CK_MECHANISM_PTR,
		hUnwrappingKey C.CK_OBJECT_HANDLE,
		pWrappedKey C.CK_BYTE_PTR,
		ulWrappedKeyLen C.CK_ULONG,
		pTemplate C.CK_ATTRIBUTE_PTR,
		ulAttributeCount C.CK_ULONG,
		phKey C.CK_OBJECT_HANDLE_PTR,
	) error
	_C_DeriveKey func(
		hSession C.CK_SESSION_HANDLE,
		pMechanism C.CK_MECHANISM_PTR,
		hBaseKey C.CK_OBJECT_HANDLE,
		pTemplate C.CK_ATTRIBUTE_PTR,
		ulAttributeCount C.CK_ULONG,
		phKey C.CK_OBJECT_HANDLE_PTR,
	) error
	_C_SeedRandom func(
		hSession C.CK_SESSION_HANDLE,
		pSeed C.CK_BYTE_PTR,
		ulSeedLen C.CK_ULONG,
	) error
	_C_GenerateRandom func(
		hSession C.CK_SESSION_HANDLE,
		RandomData C.CK_BYTE_PTR,
		ulRandomLen C.CK_ULONG,
	) error
	_C_GetFunctionStatus func(
		hSession C.CK_SESSION_HANDLE,
	) error
	_C_CancelFunction func(
		hSession C.CK_SESSION_HANDLE,
	) error
	_C_WaitForSlotEvent func(
		flags C.CK_FLAGS,
		pSlot C.CK_SLOT_ID_PTR,
		pRserved C.CK_VOID_PTR,
	) error
}

// C_CancelFunction implements [pkcs11API].
func (a *apiMock) C_CancelFunction(hSession C.CK_SESSION_HANDLE) error {
	return a._C_CancelFunction(hSession)
}

// C_CloseAllSessions implements [pkcs11API].
func (a *apiMock) C_CloseAllSessions(slotID C.CK_SLOT_ID) error {
	return a._C_CloseAllSessions(slotID)
}

// C_CloseSession implements [pkcs11API].
func (a *apiMock) C_CloseSession(hSession C.CK_SESSION_HANDLE) error {
	return a._C_CloseSession(hSession)
}

// C_CopyObject implements [pkcs11API].
func (a *apiMock) C_CopyObject(hSession C.CK_SESSION_HANDLE, hObject C.CK_OBJECT_HANDLE, pTemplate C.CK_ATTRIBUTE_PTR, ulCount C.CK_ULONG, phNewObject C.CK_OBJECT_HANDLE_PTR) error {
	return a._C_CopyObject(hSession, hObject, pTemplate, ulCount, phNewObject)
}

// C_CreateObject implements [pkcs11API].
func (a *apiMock) C_CreateObject(hSession C.CK_SESSION_HANDLE, pTemplate C.CK_ATTRIBUTE_PTR, ulCount C.CK_ULONG, phObject C.CK_OBJECT_HANDLE_PTR) error {
	return a._C_CreateObject(hSession, pTemplate, ulCount, phObject)
}

// C_Decrypt implements [pkcs11API].
func (a *apiMock) C_Decrypt(hSession C.CK_SESSION_HANDLE, pEncryptedData C.CK_BYTE_PTR, ulEncryptedDataLen C.CK_ULONG, pData C.CK_BYTE_PTR, pulDataLen C.CK_ULONG_PTR) error {
	return a._C_Decrypt(hSession, pEncryptedData, ulEncryptedDataLen, pData, pulDataLen)
}

// C_DecryptDigestUpdate implements [pkcs11API].
func (a *apiMock) C_DecryptDigestUpdate(hSession C.CK_SESSION_HANDLE, pEncryptedPart C.CK_BYTE_PTR, ulEncryptedPartLen C.CK_ULONG, pPart C.CK_BYTE_PTR, pulPartLen C.CK_ULONG_PTR) error {
	return a._C_DecryptDigestUpdate(hSession, pEncryptedPart, ulEncryptedPartLen, pPart, pulPartLen)
}

// C_DecryptFinal implements [pkcs11API].
func (a *apiMock) C_DecryptFinal(hSession C.CK_SESSION_HANDLE, pLastPart C.CK_BYTE_PTR, pulLastPartLen C.CK_ULONG_PTR) error {
	return a._C_DecryptFinal(hSession, pLastPart, pulLastPartLen)
}

// C_DecryptInit implements [pkcs11API].
func (a *apiMock) C_DecryptInit(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hKey C.CK_OBJECT_HANDLE) error {
	return a._C_DecryptInit(hSession, pMechanism, hKey)
}

// C_DecryptUpdate implements [pkcs11API].
func (a *apiMock) C_DecryptUpdate(hSession C.CK_SESSION_HANDLE, pEncryptedPart C.CK_BYTE_PTR, ulEncryptedPartLen C.CK_ULONG, pPart C.CK_BYTE_PTR, pulPartLen C.CK_ULONG_PTR) error {
	return a._C_DecryptUpdate(hSession, pEncryptedPart, ulEncryptedPartLen, pPart, pulPartLen)
}

// C_DecryptVerifyUpdate implements [pkcs11API].
func (a *apiMock) C_DecryptVerifyUpdate(hSession C.CK_SESSION_HANDLE, pEncryptedPart C.CK_BYTE_PTR, ulEncryptedPartLen C.CK_ULONG, pPart C.CK_BYTE_PTR, pulPartLen C.CK_ULONG_PTR) error {
	return a._C_DecryptVerifyUpdate(hSession, pEncryptedPart, ulEncryptedPartLen, pPart, pulPartLen)
}

// C_DeriveKey implements [pkcs11API].
func (a *apiMock) C_DeriveKey(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hBaseKey C.CK_OBJECT_HANDLE, pTemplate C.CK_ATTRIBUTE_PTR, ulAttributeCount C.CK_ULONG, phKey C.CK_OBJECT_HANDLE_PTR) error {
	return a._C_DeriveKey(hSession, pMechanism, hBaseKey, pTemplate, ulAttributeCount, phKey)
}

// C_DestroyObject implements [pkcs11API].
func (a *apiMock) C_DestroyObject(hSession C.CK_SESSION_HANDLE, hObject C.CK_OBJECT_HANDLE) error {
	return a._C_DestroyObject(hSession, hObject)
}

// C_Digest implements [pkcs11API].
func (a *apiMock) C_Digest(hSession C.CK_SESSION_HANDLE, pData C.CK_BYTE_PTR, ulDataLen C.CK_ULONG, pDigest C.CK_BYTE_PTR, pulDigestLen C.CK_ULONG_PTR) error {
	return a._C_Digest(hSession, pData, ulDataLen, pDigest, pulDigestLen)
}

// C_DigestEncryptUpdate implements [pkcs11API].
func (a *apiMock) C_DigestEncryptUpdate(hSession C.CK_SESSION_HANDLE, pPart C.CK_BYTE_PTR, ulPartLen C.CK_ULONG, pEncryptedPart C.CK_BYTE_PTR, pulEncryptedPartLen C.CK_ULONG_PTR) error {
	return a._C_DigestEncryptUpdate(hSession, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen)
}

// C_DigestFinal implements [pkcs11API].
func (a *apiMock) C_DigestFinal(hSession C.CK_SESSION_HANDLE, pDigest C.CK_BYTE_PTR, pulDigestLen C.CK_ULONG_PTR) error {
	return a._C_DigestFinal(hSession, pDigest, pulDigestLen)
}

// C_DigestInit implements [pkcs11API].
func (a *apiMock) C_DigestInit(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR) error {
	return a._C_DigestInit(hSession, pMechanism)
}

// C_DigestKey implements [pkcs11API].
func (a *apiMock) C_DigestKey(hSession C.CK_SESSION_HANDLE, hKey C.CK_OBJECT_HANDLE) error {
	return a._C_DigestKey(hSession, hKey)
}

// C_DigestUpdate implements [pkcs11API].
func (a *apiMock) C_DigestUpdate(hSession C.CK_SESSION_HANDLE, pPart C.CK_BYTE_PTR, ulPartLen C.CK_ULONG) error {
	return a._C_DigestUpdate(hSession, pPart, ulPartLen)
}

// C_Encrypt implements [pkcs11API].
func (a *apiMock) C_Encrypt(hSession C.CK_SESSION_HANDLE, pData C.CK_BYTE_PTR, ulDataLen C.CK_ULONG, pEncryptedData C.CK_BYTE_PTR, pulEncryptedDataLen C.CK_ULONG_PTR) error {
	return a._C_Encrypt(hSession, pData, ulDataLen, pEncryptedData, pulEncryptedDataLen)
}

// C_EncryptFinal implements [pkcs11API].
func (a *apiMock) C_EncryptFinal(hSession C.CK_SESSION_HANDLE, pLastEncryptedPart C.CK_BYTE_PTR, pulLastEncryptedPartLen C.CK_ULONG_PTR) error {
	return a._C_EncryptFinal(hSession, pLastEncryptedPart, pulLastEncryptedPartLen)
}

// C_EncryptInit implements [pkcs11API].
func (a *apiMock) C_EncryptInit(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hKey C.CK_OBJECT_HANDLE) error {
	return a._C_EncryptInit(hSession, pMechanism, hKey)
}

// C_EncryptUpdate implements [pkcs11API].
func (a *apiMock) C_EncryptUpdate(hSession C.CK_SESSION_HANDLE, pPart C.CK_BYTE_PTR, ulPartLen C.CK_ULONG, pEncryptedPart C.CK_BYTE_PTR, pulEncryptedPartLen C.CK_ULONG_PTR) error {
	return a._C_EncryptUpdate(hSession, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen)
}

// C_Finalize implements [pkcs11API].
func (a *apiMock) C_Finalize(pReserved C.CK_VOID_PTR) error {
	return a._C_Finalize(pReserved)
}

// C_FindObjects implements [pkcs11API].
func (a *apiMock) C_FindObjects(hSession C.CK_SESSION_HANDLE, phObject C.CK_OBJECT_HANDLE_PTR, ulMaxObjectCount C.CK_ULONG, pulObjectCount C.CK_ULONG_PTR) error {
	return a._C_FindObjects(hSession, phObject, ulMaxObjectCount, pulObjectCount)
}

// C_FindObjectsFinal implements [pkcs11API].
func (a *apiMock) C_FindObjectsFinal(hSession C.CK_SESSION_HANDLE) error {
	return a._C_FindObjectsFinal(hSession)
}

// C_FindObjectsInit implements [pkcs11API].
func (a *apiMock) C_FindObjectsInit(hSession C.CK_SESSION_HANDLE, pTemplate C.CK_ATTRIBUTE_PTR, ulCount C.CK_ULONG) error {
	return a._C_FindObjectsInit(hSession, pTemplate, ulCount)
}

// C_GenerateKey implements [pkcs11API].
func (a *apiMock) C_GenerateKey(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, pTemplate C.CK_ATTRIBUTE_PTR, ulCount C.CK_ULONG, phKey C.CK_OBJECT_HANDLE_PTR) error {
	return a._C_GenerateKey(hSession, pMechanism, pTemplate, ulCount, phKey)
}

// C_GenerateKeyPair implements [pkcs11API].
func (a *apiMock) C_GenerateKeyPair(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, pPublicKeyTemplate C.CK_ATTRIBUTE_PTR, ulPublicKeyAttributeCount C.CK_ULONG, pPrivateKeyTemplate C.CK_ATTRIBUTE_PTR, ulPrivateKeyAttributeCount C.CK_ULONG, phPublicKey C.CK_OBJECT_HANDLE_PTR, phPrivateKey C.CK_OBJECT_HANDLE_PTR) error {
	return a._C_GenerateKeyPair(hSession, pMechanism, pPublicKeyTemplate, ulPublicKeyAttributeCount, pPrivateKeyTemplate, ulPrivateKeyAttributeCount, phPublicKey, phPrivateKey)
}

// C_GenerateRandom implements [pkcs11API].
func (a *apiMock) C_GenerateRandom(hSession C.CK_SESSION_HANDLE, RandomData C.CK_BYTE_PTR, ulRandomLen C.CK_ULONG) error {
	return a._C_GenerateRandom(hSession, RandomData, ulRandomLen)
}

// C_GetAttributeValue implements [pkcs11API].
func (a *apiMock) C_GetAttributeValue(hSession C.CK_SESSION_HANDLE, hObject C.CK_OBJECT_HANDLE, pTemplate C.CK_ATTRIBUTE_PTR, ulCount C.CK_ULONG) error {
	return a._C_GetAttributeValue(hSession, hObject, pTemplate, ulCount)
}

// C_GetFunctionList implements [pkcs11API].
func (a *apiMock) C_GetFunctionList(ppFunctionList C.CK_FUNCTION_LIST_PTR_PTR) error {
	return a._C_GetFunctionList(ppFunctionList)
}

// C_GetFunctionStatus implements [pkcs11API].
func (a *apiMock) C_GetFunctionStatus(hSession C.CK_SESSION_HANDLE) error {
	return a._C_GetFunctionStatus(hSession)
}

// C_GetInfo implements [pkcs11API].
func (a *apiMock) C_GetInfo(pInfo C.CK_INFO_PTR) error {
	return a._C_GetInfo(pInfo)
}

// C_GetMechanismInfo implements [pkcs11API].
func (a *apiMock) C_GetMechanismInfo(slotID C.CK_SLOT_ID, _type C.CK_MECHANISM_TYPE, pInfo C.CK_MECHANISM_INFO_PTR) error {
	return a._C_GetMechanismInfo(slotID, _type, pInfo)
}

// C_GetMechanismList implements [pkcs11API].
func (a *apiMock) C_GetMechanismList(slotID C.CK_SLOT_ID, pMechanismList C.CK_MECHANISM_TYPE_PTR, pulCount C.CK_ULONG_PTR) error {
	return a._C_GetMechanismList(slotID, pMechanismList, pulCount)
}

// C_GetObjectSize implements [pkcs11API].
func (a *apiMock) C_GetObjectSize(hSession C.CK_SESSION_HANDLE, hObject C.CK_OBJECT_HANDLE, pulSize C.CK_ULONG_PTR) error {
	return a._C_GetObjectSize(hSession, hObject, pulSize)
}

// C_GetOperationState implements [pkcs11API].
func (a *apiMock) C_GetOperationState(hSession C.CK_SESSION_HANDLE, pOperationState C.CK_BYTE_PTR, pulOperationStateLen C.CK_ULONG_PTR) error {
	return a._C_GetOperationState(hSession, pOperationState, pulOperationStateLen)
}

// C_GetSessionInfo implements [pkcs11API].
func (a *apiMock) C_GetSessionInfo(hSession C.CK_SESSION_HANDLE, pInfo C.CK_SESSION_INFO_PTR) error {
	return a._C_GetSessionInfo(hSession, pInfo)
}

// C_GetSlotInfo implements [pkcs11API].
func (a *apiMock) C_GetSlotInfo(slotID C.CK_SLOT_ID, pInfo C.CK_SLOT_INFO_PTR) error {
	return a._C_GetSlotInfo(slotID, pInfo)
}

// C_GetSlotList implements [pkcs11API].
func (a *apiMock) C_GetSlotList(tokenPresent C.CK_BBOOL, pSlotList C.CK_SLOT_ID_PTR, pulCount C.CK_ULONG_PTR) error {
	return a._C_GetSlotList(tokenPresent, pSlotList, pulCount)
}

// C_GetTokenInfo implements [pkcs11API].
func (a *apiMock) C_GetTokenInfo(slotID C.CK_SLOT_ID, pInfo C.CK_TOKEN_INFO_PTR) error {
	return a._C_GetTokenInfo(slotID, pInfo)
}

// C_InitPIN implements [pkcs11API].
func (a *apiMock) C_InitPIN(hSession C.CK_SESSION_HANDLE, pPin C.CK_UTF8CHAR_PTR, ulPinLen C.CK_ULONG) error {
	return a._C_InitPIN(hSession, pPin, ulPinLen)
}

// C_InitToken implements [pkcs11API].
func (a *apiMock) C_InitToken(slotID C.CK_SLOT_ID, pPin C.CK_UTF8CHAR_PTR, ulPinLen C.CK_ULONG, pLabel C.CK_UTF8CHAR_PTR) error {
	return a._C_InitToken(slotID, pPin, ulPinLen, pLabel)
}

// C_Initialize implements [pkcs11API].
func (a *apiMock) C_Initialize(pInitArgs C.CK_VOID_PTR) error {
	return a._C_Initialize(pInitArgs)
}

// C_Login implements [pkcs11API].
func (a *apiMock) C_Login(hSession C.CK_SESSION_HANDLE, userType C.CK_USER_TYPE, pPin C.CK_UTF8CHAR_PTR, ulPinLen C.CK_ULONG) error {
	return a._C_Login(hSession, userType, pPin, ulPinLen)
}

// C_Logout implements [pkcs11API].
func (a *apiMock) C_Logout(hSession C.CK_SESSION_HANDLE) error {
	return a._C_Logout(hSession)
}

// C_OpenSession implements [pkcs11API].
func (a *apiMock) C_OpenSession(slotID C.CK_SLOT_ID, flags C.CK_FLAGS, pApplication C.CK_VOID_PTR, Notify C.CK_NOTIFY, phSession C.CK_SESSION_HANDLE_PTR) error {
	return a._C_OpenSession(slotID, flags, pApplication, Notify, phSession)
}

// C_SeedRandom implements [pkcs11API].
func (a *apiMock) C_SeedRandom(hSession C.CK_SESSION_HANDLE, pSeed C.CK_BYTE_PTR, ulSeedLen C.CK_ULONG) error {
	return a._C_SeedRandom(hSession, pSeed, ulSeedLen)
}

// C_SetAttributeValue implements [pkcs11API].
func (a *apiMock) C_SetAttributeValue(hSession C.CK_SESSION_HANDLE, hObject C.CK_OBJECT_HANDLE, pTemplate C.CK_ATTRIBUTE_PTR, ulCount C.CK_ULONG) error {
	return a._C_SetAttributeValue(hSession, hObject, pTemplate, ulCount)
}

// C_SetOperationState implements [pkcs11API].
func (a *apiMock) C_SetOperationState(hSession C.CK_SESSION_HANDLE, pOperationState C.CK_BYTE_PTR, ulOperationStateLen C.CK_ULONG, hEncryptionKey C.CK_OBJECT_HANDLE, hAuthenticationKey C.CK_OBJECT_HANDLE) error {
	return a._C_SetOperationState(hSession, pOperationState, ulOperationStateLen, hEncryptionKey, hAuthenticationKey)
}

// C_SetPIN implements [pkcs11API].
func (a *apiMock) C_SetPIN(hSession C.CK_SESSION_HANDLE, pOldPin C.CK_UTF8CHAR_PTR, ulOldLen C.CK_ULONG, pNewPin C.CK_UTF8CHAR_PTR, ulNewLen C.CK_ULONG) error {
	return a._C_SetPIN(hSession, pOldPin, ulOldLen, pNewPin, ulNewLen)
}

// C_Sign implements [pkcs11API].
func (a *apiMock) C_Sign(hSession C.CK_SESSION_HANDLE, pData C.CK_BYTE_PTR, ulDataLen C.CK_ULONG, pSignature C.CK_BYTE_PTR, pulSignatureLen C.CK_ULONG_PTR) error {
	return a._C_Sign(hSession, pData, ulDataLen, pSignature, pulSignatureLen)
}

// C_SignEncryptUpdate implements [pkcs11API].
func (a *apiMock) C_SignEncryptUpdate(hSession C.CK_SESSION_HANDLE, pPart C.CK_BYTE_PTR, ulPartLen C.CK_ULONG, pEncryptedPart C.CK_BYTE_PTR, pulEncryptedPartLen C.CK_ULONG_PTR) error {
	return a._C_SignEncryptUpdate(hSession, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen)
}

// C_SignFinal implements [pkcs11API].
func (a *apiMock) C_SignFinal(hSession C.CK_SESSION_HANDLE, pSignature C.CK_BYTE_PTR, pulSignatureLen C.CK_ULONG_PTR) error {
	return a._C_SignFinal(hSession, pSignature, pulSignatureLen)
}

// C_SignInit implements [pkcs11API].
func (a *apiMock) C_SignInit(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hKey C.CK_OBJECT_HANDLE) error {
	return a._C_SignInit(hSession, pMechanism, hKey)
}

// C_SignRecover implements [pkcs11API].
func (a *apiMock) C_SignRecover(hSession C.CK_SESSION_HANDLE, pData C.CK_BYTE_PTR, ulDataLen C.CK_ULONG, pSignature C.CK_BYTE_PTR, pulSignatureLen C.CK_ULONG_PTR) error {
	return a._C_SignRecover(hSession, pData, ulDataLen, pSignature, pulSignatureLen)
}

// C_SignRecoverInit implements [pkcs11API].
func (a *apiMock) C_SignRecoverInit(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hKey C.CK_OBJECT_HANDLE) error {
	return a._C_SignRecoverInit(hSession, pMechanism, hKey)
}

// C_SignUpdate implements [pkcs11API].
func (a *apiMock) C_SignUpdate(hSession C.CK_SESSION_HANDLE, pPart C.CK_BYTE_PTR, ulPartLen C.CK_ULONG) error {
	return a._C_SignUpdate(hSession, pPart, ulPartLen)
}

// C_UnwrapKey implements [pkcs11API].
func (a *apiMock) C_UnwrapKey(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hUnwrappingKey C.CK_OBJECT_HANDLE, pWrappedKey C.CK_BYTE_PTR, ulWrappedKeyLen C.CK_ULONG, pTemplate C.CK_ATTRIBUTE_PTR, ulAttributeCount C.CK_ULONG, phKey C.CK_OBJECT_HANDLE_PTR) error {
	return a._C_UnwrapKey(hSession, pMechanism, hUnwrappingKey, pWrappedKey, ulWrappedKeyLen, pTemplate, ulAttributeCount, phKey)
}

// C_Verify implements [pkcs11API].
func (a *apiMock) C_Verify(hSession C.CK_SESSION_HANDLE, pData C.CK_BYTE_PTR, ulDataLen C.CK_ULONG, pSignature C.CK_BYTE_PTR, ulSignatureLen C.CK_ULONG) error {
	return a._C_Verify(hSession, pData, ulDataLen, pSignature, ulSignatureLen)
}

// C_VerifyFinal implements [pkcs11API].
func (a *apiMock) C_VerifyFinal(hSession C.CK_SESSION_HANDLE, pSignature C.CK_BYTE_PTR, ulSignatureLen C.CK_ULONG) error {
	return a._C_VerifyFinal(hSession, pSignature, ulSignatureLen)
}

// C_VerifyInit implements [pkcs11API].
func (a *apiMock) C_VerifyInit(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hKey C.CK_OBJECT_HANDLE) error {
	return a._C_VerifyInit(hSession, pMechanism, hKey)
}

// C_VerifyRecover implements [pkcs11API].
func (a *apiMock) C_VerifyRecover(hSession C.CK_SESSION_HANDLE, pSignature C.CK_BYTE_PTR, ulSignatureLen C.CK_ULONG, pData C.CK_BYTE_PTR, pulDataLen C.CK_ULONG_PTR) error {
	return a._C_VerifyRecover(hSession, pSignature, ulSignatureLen, pData, pulDataLen)
}

// C_VerifyRecoverInit implements [pkcs11API].
func (a *apiMock) C_VerifyRecoverInit(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hKey C.CK_OBJECT_HANDLE) error {
	return a._C_VerifyRecoverInit(hSession, pMechanism, hKey)
}

// C_VerifyUpdate implements [pkcs11API].
func (a *apiMock) C_VerifyUpdate(hSession C.CK_SESSION_HANDLE, pPart C.CK_BYTE_PTR, ulPartLen C.CK_ULONG) error {
	return a._C_VerifyUpdate(hSession, pPart, ulPartLen)
}

// C_WaitForSlotEvent implements [pkcs11API].
func (a *apiMock) C_WaitForSlotEvent(flags C.CK_FLAGS, pSlot C.CK_SLOT_ID_PTR, pRserved C.CK_VOID_PTR) error {
	return a._C_WaitForSlotEvent(flags, pSlot, pRserved)
}

// C_WrapKey implements [pkcs11API].
func (a *apiMock) C_WrapKey(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hWrappingKey C.CK_OBJECT_HANDLE, hKey C.CK_OBJECT_HANDLE, pWrappedKey C.CK_BYTE_PTR, pulWrappedKeyLen C.CK_ULONG_PTR) error {
	return a._C_WrapKey(hSession, pMechanism, hWrappingKey, hKey, pWrappedKey, pulWrappedKeyLen)
}

package pkcs11

// GENERATED, DO NOT EDIT.

/*
#include "platform.h"


CK_RV _C_Initialize(
	CK_FUNCTION_LIST_PTR _funcs,
	CK_VOID_PTR pInitArgs
) {
	return (*_funcs->C_Initialize)(
		pInitArgs
	);
}

CK_RV _C_Finalize(
	CK_FUNCTION_LIST_PTR _funcs,
	CK_VOID_PTR pReserved
) {
	return (*_funcs->C_Finalize)(
		pReserved
	);
}

CK_RV _C_GetInfo(
	CK_FUNCTION_LIST_PTR _funcs,
	CK_INFO_PTR pInfo
) {
	return (*_funcs->C_GetInfo)(
		pInfo
	);
}

CK_RV _C_GetFunctionList(
	CK_FUNCTION_LIST_PTR _funcs,
	CK_FUNCTION_LIST_PTR_PTR ppFunctionList
) {
	return (*_funcs->C_GetFunctionList)(
		ppFunctionList
	);
}

CK_RV _C_GetSlotList(
	CK_FUNCTION_LIST_PTR _funcs,
	CK_BBOOL tokenPresent,
	CK_SLOT_ID_PTR pSlotList,
	CK_ULONG_PTR pulCount
) {
	return (*_funcs->C_GetSlotList)(
		tokenPresent,
		pSlotList,
		pulCount
	);
}

CK_RV _C_GetSlotInfo(
	CK_FUNCTION_LIST_PTR _funcs,
	CK_SLOT_ID slotID,
	CK_SLOT_INFO_PTR pInfo
) {
	return (*_funcs->C_GetSlotInfo)(
		slotID,
		pInfo
	);
}

CK_RV _C_GetTokenInfo(
	CK_FUNCTION_LIST_PTR _funcs,
	CK_SLOT_ID slotID,
	CK_TOKEN_INFO_PTR pInfo
) {
	return (*_funcs->C_GetTokenInfo)(
		slotID,
		pInfo
	);
}

CK_RV _C_GetMechanismList(
	CK_FUNCTION_LIST_PTR _funcs,
	CK_SLOT_ID slotID,
	CK_MECHANISM_TYPE_PTR pMechanismList,
	CK_ULONG_PTR pulCount
) {
	return (*_funcs->C_GetMechanismList)(
		slotID,
		pMechanismList,
		pulCount
	);
}

CK_RV _C_GetMechanismInfo(
	CK_FUNCTION_LIST_PTR _funcs,
	CK_SLOT_ID slotID,
	CK_MECHANISM_TYPE type,
	CK_MECHANISM_INFO_PTR pInfo
) {
	return (*_funcs->C_GetMechanismInfo)(
		slotID,
		type,
		pInfo
	);
}

CK_RV _C_InitToken(
	CK_FUNCTION_LIST_PTR _funcs,
	CK_SLOT_ID slotID,
	CK_UTF8CHAR_PTR pPin,
	CK_ULONG ulPinLen,
	CK_UTF8CHAR_PTR pLabel
) {
	return (*_funcs->C_InitToken)(
		slotID,
		pPin,
		ulPinLen,
		pLabel
	);
}

CK_RV _C_InitPIN(
	CK_FUNCTION_LIST_PTR _funcs,
	CK_SESSION_HANDLE hSession,
	CK_UTF8CHAR_PTR pPin,
	CK_ULONG ulPinLen
) {
	return (*_funcs->C_InitPIN)(
		hSession,
		pPin,
		ulPinLen
	);
}

CK_RV _C_SetPIN(
	CK_FUNCTION_LIST_PTR _funcs,
	CK_SESSION_HANDLE hSession,
	CK_UTF8CHAR_PTR pOldPin,
	CK_ULONG ulOldLen,
	CK_UTF8CHAR_PTR pNewPin,
	CK_ULONG ulNewLen
) {
	return (*_funcs->C_SetPIN)(
		hSession,
		pOldPin,
		ulOldLen,
		pNewPin,
		ulNewLen
	);
}

CK_RV _C_OpenSession(
	CK_FUNCTION_LIST_PTR _funcs,
	CK_SLOT_ID slotID,
	CK_FLAGS flags,
	CK_VOID_PTR pApplication,
	CK_NOTIFY Notify,
	CK_SESSION_HANDLE_PTR phSession
) {
	return (*_funcs->C_OpenSession)(
		slotID,
		flags,
		pApplication,
		Notify,
		phSession
	);
}

CK_RV _C_CloseSession(
	CK_FUNCTION_LIST_PTR _funcs,
	CK_SESSION_HANDLE hSession
) {
	return (*_funcs->C_CloseSession)(
		hSession
	);
}

CK_RV _C_CloseAllSessions(
	CK_FUNCTION_LIST_PTR _funcs,
	CK_SLOT_ID slotID
) {
	return (*_funcs->C_CloseAllSessions)(
		slotID
	);
}

CK_RV _C_GetSessionInfo(
	CK_FUNCTION_LIST_PTR _funcs,
	CK_SESSION_HANDLE hSession,
	CK_SESSION_INFO_PTR pInfo
) {
	return (*_funcs->C_GetSessionInfo)(
		hSession,
		pInfo
	);
}

CK_RV _C_GetOperationState(
	CK_FUNCTION_LIST_PTR _funcs,
	CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pOperationState,
	CK_ULONG_PTR pulOperationStateLen
) {
	return (*_funcs->C_GetOperationState)(
		hSession,
		pOperationState,
		pulOperationStateLen
	);
}

CK_RV _C_SetOperationState(
	CK_FUNCTION_LIST_PTR _funcs,
	CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pOperationState,
	CK_ULONG ulOperationStateLen,
	CK_OBJECT_HANDLE hEncryptionKey,
	CK_OBJECT_HANDLE hAuthenticationKey
) {
	return (*_funcs->C_SetOperationState)(
		hSession,
		pOperationState,
		ulOperationStateLen,
		hEncryptionKey,
		hAuthenticationKey
	);
}

CK_RV _C_Login(
	CK_FUNCTION_LIST_PTR _funcs,
	CK_SESSION_HANDLE hSession,
	CK_USER_TYPE userType,
	CK_UTF8CHAR_PTR pPin,
	CK_ULONG ulPinLen
) {
	return (*_funcs->C_Login)(
		hSession,
		userType,
		pPin,
		ulPinLen
	);
}

CK_RV _C_Logout(
	CK_FUNCTION_LIST_PTR _funcs,
	CK_SESSION_HANDLE hSession
) {
	return (*_funcs->C_Logout)(
		hSession
	);
}

CK_RV _C_CreateObject(
	CK_FUNCTION_LIST_PTR _funcs,
	CK_SESSION_HANDLE hSession,
	CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG ulCount,
	CK_OBJECT_HANDLE_PTR phObject
) {
	return (*_funcs->C_CreateObject)(
		hSession,
		pTemplate,
		ulCount,
		phObject
	);
}

CK_RV _C_CopyObject(
	CK_FUNCTION_LIST_PTR _funcs,
	CK_SESSION_HANDLE hSession,
	CK_OBJECT_HANDLE hObject,
	CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG ulCount,
	CK_OBJECT_HANDLE_PTR phNewObject
) {
	return (*_funcs->C_CopyObject)(
		hSession,
		hObject,
		pTemplate,
		ulCount,
		phNewObject
	);
}

CK_RV _C_DestroyObject(
	CK_FUNCTION_LIST_PTR _funcs,
	CK_SESSION_HANDLE hSession,
	CK_OBJECT_HANDLE hObject
) {
	return (*_funcs->C_DestroyObject)(
		hSession,
		hObject
	);
}

CK_RV _C_GetObjectSize(
	CK_FUNCTION_LIST_PTR _funcs,
	CK_SESSION_HANDLE hSession,
	CK_OBJECT_HANDLE hObject,
	CK_ULONG_PTR pulSize
) {
	return (*_funcs->C_GetObjectSize)(
		hSession,
		hObject,
		pulSize
	);
}

CK_RV _C_GetAttributeValue(
	CK_FUNCTION_LIST_PTR _funcs,
	CK_SESSION_HANDLE hSession,
	CK_OBJECT_HANDLE hObject,
	CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG ulCount
) {
	return (*_funcs->C_GetAttributeValue)(
		hSession,
		hObject,
		pTemplate,
		ulCount
	);
}

CK_RV _C_SetAttributeValue(
	CK_FUNCTION_LIST_PTR _funcs,
	CK_SESSION_HANDLE hSession,
	CK_OBJECT_HANDLE hObject,
	CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG ulCount
) {
	return (*_funcs->C_SetAttributeValue)(
		hSession,
		hObject,
		pTemplate,
		ulCount
	);
}

CK_RV _C_FindObjectsInit(
	CK_FUNCTION_LIST_PTR _funcs,
	CK_SESSION_HANDLE hSession,
	CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG ulCount
) {
	return (*_funcs->C_FindObjectsInit)(
		hSession,
		pTemplate,
		ulCount
	);
}

CK_RV _C_FindObjects(
	CK_FUNCTION_LIST_PTR _funcs,
	CK_SESSION_HANDLE hSession,
	CK_OBJECT_HANDLE_PTR phObject,
	CK_ULONG ulMaxObjectCount,
	CK_ULONG_PTR pulObjectCount
) {
	return (*_funcs->C_FindObjects)(
		hSession,
		phObject,
		ulMaxObjectCount,
		pulObjectCount
	);
}

CK_RV _C_FindObjectsFinal(
	CK_FUNCTION_LIST_PTR _funcs,
	CK_SESSION_HANDLE hSession
) {
	return (*_funcs->C_FindObjectsFinal)(
		hSession
	);
}

CK_RV _C_EncryptInit(
	CK_FUNCTION_LIST_PTR _funcs,
	CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism,
	CK_OBJECT_HANDLE hKey
) {
	return (*_funcs->C_EncryptInit)(
		hSession,
		pMechanism,
		hKey
	);
}

CK_RV _C_Encrypt(
	CK_FUNCTION_LIST_PTR _funcs,
	CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pData,
	CK_ULONG ulDataLen,
	CK_BYTE_PTR pEncryptedData,
	CK_ULONG_PTR pulEncryptedDataLen
) {
	return (*_funcs->C_Encrypt)(
		hSession,
		pData,
		ulDataLen,
		pEncryptedData,
		pulEncryptedDataLen
	);
}

CK_RV _C_EncryptUpdate(
	CK_FUNCTION_LIST_PTR _funcs,
	CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pPart,
	CK_ULONG ulPartLen,
	CK_BYTE_PTR pEncryptedPart,
	CK_ULONG_PTR pulEncryptedPartLen
) {
	return (*_funcs->C_EncryptUpdate)(
		hSession,
		pPart,
		ulPartLen,
		pEncryptedPart,
		pulEncryptedPartLen
	);
}

CK_RV _C_EncryptFinal(
	CK_FUNCTION_LIST_PTR _funcs,
	CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pLastEncryptedPart,
	CK_ULONG_PTR pulLastEncryptedPartLen
) {
	return (*_funcs->C_EncryptFinal)(
		hSession,
		pLastEncryptedPart,
		pulLastEncryptedPartLen
	);
}

CK_RV _C_DecryptInit(
	CK_FUNCTION_LIST_PTR _funcs,
	CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism,
	CK_OBJECT_HANDLE hKey
) {
	return (*_funcs->C_DecryptInit)(
		hSession,
		pMechanism,
		hKey
	);
}

CK_RV _C_Decrypt(
	CK_FUNCTION_LIST_PTR _funcs,
	CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pEncryptedData,
	CK_ULONG ulEncryptedDataLen,
	CK_BYTE_PTR pData,
	CK_ULONG_PTR pulDataLen
) {
	return (*_funcs->C_Decrypt)(
		hSession,
		pEncryptedData,
		ulEncryptedDataLen,
		pData,
		pulDataLen
	);
}

CK_RV _C_DecryptUpdate(
	CK_FUNCTION_LIST_PTR _funcs,
	CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pEncryptedPart,
	CK_ULONG ulEncryptedPartLen,
	CK_BYTE_PTR pPart,
	CK_ULONG_PTR pulPartLen
) {
	return (*_funcs->C_DecryptUpdate)(
		hSession,
		pEncryptedPart,
		ulEncryptedPartLen,
		pPart,
		pulPartLen
	);
}

CK_RV _C_DecryptFinal(
	CK_FUNCTION_LIST_PTR _funcs,
	CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pLastPart,
	CK_ULONG_PTR pulLastPartLen
) {
	return (*_funcs->C_DecryptFinal)(
		hSession,
		pLastPart,
		pulLastPartLen
	);
}

CK_RV _C_DigestInit(
	CK_FUNCTION_LIST_PTR _funcs,
	CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism
) {
	return (*_funcs->C_DigestInit)(
		hSession,
		pMechanism
	);
}

CK_RV _C_Digest(
	CK_FUNCTION_LIST_PTR _funcs,
	CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pData,
	CK_ULONG ulDataLen,
	CK_BYTE_PTR pDigest,
	CK_ULONG_PTR pulDigestLen
) {
	return (*_funcs->C_Digest)(
		hSession,
		pData,
		ulDataLen,
		pDigest,
		pulDigestLen
	);
}

CK_RV _C_DigestUpdate(
	CK_FUNCTION_LIST_PTR _funcs,
	CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pPart,
	CK_ULONG ulPartLen
) {
	return (*_funcs->C_DigestUpdate)(
		hSession,
		pPart,
		ulPartLen
	);
}

CK_RV _C_DigestKey(
	CK_FUNCTION_LIST_PTR _funcs,
	CK_SESSION_HANDLE hSession,
	CK_OBJECT_HANDLE hKey
) {
	return (*_funcs->C_DigestKey)(
		hSession,
		hKey
	);
}

CK_RV _C_DigestFinal(
	CK_FUNCTION_LIST_PTR _funcs,
	CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pDigest,
	CK_ULONG_PTR pulDigestLen
) {
	return (*_funcs->C_DigestFinal)(
		hSession,
		pDigest,
		pulDigestLen
	);
}

CK_RV _C_SignInit(
	CK_FUNCTION_LIST_PTR _funcs,
	CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism,
	CK_OBJECT_HANDLE hKey
) {
	return (*_funcs->C_SignInit)(
		hSession,
		pMechanism,
		hKey
	);
}

CK_RV _C_Sign(
	CK_FUNCTION_LIST_PTR _funcs,
	CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pData,
	CK_ULONG ulDataLen,
	CK_BYTE_PTR pSignature,
	CK_ULONG_PTR pulSignatureLen
) {
	return (*_funcs->C_Sign)(
		hSession,
		pData,
		ulDataLen,
		pSignature,
		pulSignatureLen
	);
}

CK_RV _C_SignUpdate(
	CK_FUNCTION_LIST_PTR _funcs,
	CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pPart,
	CK_ULONG ulPartLen
) {
	return (*_funcs->C_SignUpdate)(
		hSession,
		pPart,
		ulPartLen
	);
}

CK_RV _C_SignFinal(
	CK_FUNCTION_LIST_PTR _funcs,
	CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pSignature,
	CK_ULONG_PTR pulSignatureLen
) {
	return (*_funcs->C_SignFinal)(
		hSession,
		pSignature,
		pulSignatureLen
	);
}

CK_RV _C_SignRecoverInit(
	CK_FUNCTION_LIST_PTR _funcs,
	CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism,
	CK_OBJECT_HANDLE hKey
) {
	return (*_funcs->C_SignRecoverInit)(
		hSession,
		pMechanism,
		hKey
	);
}

CK_RV _C_SignRecover(
	CK_FUNCTION_LIST_PTR _funcs,
	CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pData,
	CK_ULONG ulDataLen,
	CK_BYTE_PTR pSignature,
	CK_ULONG_PTR pulSignatureLen
) {
	return (*_funcs->C_SignRecover)(
		hSession,
		pData,
		ulDataLen,
		pSignature,
		pulSignatureLen
	);
}

CK_RV _C_VerifyInit(
	CK_FUNCTION_LIST_PTR _funcs,
	CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism,
	CK_OBJECT_HANDLE hKey
) {
	return (*_funcs->C_VerifyInit)(
		hSession,
		pMechanism,
		hKey
	);
}

CK_RV _C_Verify(
	CK_FUNCTION_LIST_PTR _funcs,
	CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pData,
	CK_ULONG ulDataLen,
	CK_BYTE_PTR pSignature,
	CK_ULONG ulSignatureLen
) {
	return (*_funcs->C_Verify)(
		hSession,
		pData,
		ulDataLen,
		pSignature,
		ulSignatureLen
	);
}

CK_RV _C_VerifyUpdate(
	CK_FUNCTION_LIST_PTR _funcs,
	CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pPart,
	CK_ULONG ulPartLen
) {
	return (*_funcs->C_VerifyUpdate)(
		hSession,
		pPart,
		ulPartLen
	);
}

CK_RV _C_VerifyFinal(
	CK_FUNCTION_LIST_PTR _funcs,
	CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pSignature,
	CK_ULONG ulSignatureLen
) {
	return (*_funcs->C_VerifyFinal)(
		hSession,
		pSignature,
		ulSignatureLen
	);
}

CK_RV _C_VerifyRecoverInit(
	CK_FUNCTION_LIST_PTR _funcs,
	CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism,
	CK_OBJECT_HANDLE hKey
) {
	return (*_funcs->C_VerifyRecoverInit)(
		hSession,
		pMechanism,
		hKey
	);
}

CK_RV _C_VerifyRecover(
	CK_FUNCTION_LIST_PTR _funcs,
	CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pSignature,
	CK_ULONG ulSignatureLen,
	CK_BYTE_PTR pData,
	CK_ULONG_PTR pulDataLen
) {
	return (*_funcs->C_VerifyRecover)(
		hSession,
		pSignature,
		ulSignatureLen,
		pData,
		pulDataLen
	);
}

CK_RV _C_DigestEncryptUpdate(
	CK_FUNCTION_LIST_PTR _funcs,
	CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pPart,
	CK_ULONG ulPartLen,
	CK_BYTE_PTR pEncryptedPart,
	CK_ULONG_PTR pulEncryptedPartLen
) {
	return (*_funcs->C_DigestEncryptUpdate)(
		hSession,
		pPart,
		ulPartLen,
		pEncryptedPart,
		pulEncryptedPartLen
	);
}

CK_RV _C_DecryptDigestUpdate(
	CK_FUNCTION_LIST_PTR _funcs,
	CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pEncryptedPart,
	CK_ULONG ulEncryptedPartLen,
	CK_BYTE_PTR pPart,
	CK_ULONG_PTR pulPartLen
) {
	return (*_funcs->C_DecryptDigestUpdate)(
		hSession,
		pEncryptedPart,
		ulEncryptedPartLen,
		pPart,
		pulPartLen
	);
}

CK_RV _C_SignEncryptUpdate(
	CK_FUNCTION_LIST_PTR _funcs,
	CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pPart,
	CK_ULONG ulPartLen,
	CK_BYTE_PTR pEncryptedPart,
	CK_ULONG_PTR pulEncryptedPartLen
) {
	return (*_funcs->C_SignEncryptUpdate)(
		hSession,
		pPart,
		ulPartLen,
		pEncryptedPart,
		pulEncryptedPartLen
	);
}

CK_RV _C_DecryptVerifyUpdate(
	CK_FUNCTION_LIST_PTR _funcs,
	CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pEncryptedPart,
	CK_ULONG ulEncryptedPartLen,
	CK_BYTE_PTR pPart,
	CK_ULONG_PTR pulPartLen
) {
	return (*_funcs->C_DecryptVerifyUpdate)(
		hSession,
		pEncryptedPart,
		ulEncryptedPartLen,
		pPart,
		pulPartLen
	);
}

CK_RV _C_GenerateKey(
	CK_FUNCTION_LIST_PTR _funcs,
	CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism,
	CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG ulCount,
	CK_OBJECT_HANDLE_PTR phKey
) {
	return (*_funcs->C_GenerateKey)(
		hSession,
		pMechanism,
		pTemplate,
		ulCount,
		phKey
	);
}

CK_RV _C_GenerateKeyPair(
	CK_FUNCTION_LIST_PTR _funcs,
	CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism,
	CK_ATTRIBUTE_PTR pPublicKeyTemplate,
	CK_ULONG ulPublicKeyAttributeCount,
	CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
	CK_ULONG ulPrivateKeyAttributeCount,
	CK_OBJECT_HANDLE_PTR phPublicKey,
	CK_OBJECT_HANDLE_PTR phPrivateKey
) {
	return (*_funcs->C_GenerateKeyPair)(
		hSession,
		pMechanism,
		pPublicKeyTemplate,
		ulPublicKeyAttributeCount,
		pPrivateKeyTemplate,
		ulPrivateKeyAttributeCount,
		phPublicKey,
		phPrivateKey
	);
}

CK_RV _C_WrapKey(
	CK_FUNCTION_LIST_PTR _funcs,
	CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism,
	CK_OBJECT_HANDLE hWrappingKey,
	CK_OBJECT_HANDLE hKey,
	CK_BYTE_PTR pWrappedKey,
	CK_ULONG_PTR pulWrappedKeyLen
) {
	return (*_funcs->C_WrapKey)(
		hSession,
		pMechanism,
		hWrappingKey,
		hKey,
		pWrappedKey,
		pulWrappedKeyLen
	);
}

CK_RV _C_UnwrapKey(
	CK_FUNCTION_LIST_PTR _funcs,
	CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism,
	CK_OBJECT_HANDLE hUnwrappingKey,
	CK_BYTE_PTR pWrappedKey,
	CK_ULONG ulWrappedKeyLen,
	CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG ulAttributeCount,
	CK_OBJECT_HANDLE_PTR phKey
) {
	return (*_funcs->C_UnwrapKey)(
		hSession,
		pMechanism,
		hUnwrappingKey,
		pWrappedKey,
		ulWrappedKeyLen,
		pTemplate,
		ulAttributeCount,
		phKey
	);
}

CK_RV _C_DeriveKey(
	CK_FUNCTION_LIST_PTR _funcs,
	CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism,
	CK_OBJECT_HANDLE hBaseKey,
	CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG ulAttributeCount,
	CK_OBJECT_HANDLE_PTR phKey
) {
	return (*_funcs->C_DeriveKey)(
		hSession,
		pMechanism,
		hBaseKey,
		pTemplate,
		ulAttributeCount,
		phKey
	);
}

CK_RV _C_SeedRandom(
	CK_FUNCTION_LIST_PTR _funcs,
	CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pSeed,
	CK_ULONG ulSeedLen
) {
	return (*_funcs->C_SeedRandom)(
		hSession,
		pSeed,
		ulSeedLen
	);
}

CK_RV _C_GenerateRandom(
	CK_FUNCTION_LIST_PTR _funcs,
	CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR RandomData,
	CK_ULONG ulRandomLen
) {
	return (*_funcs->C_GenerateRandom)(
		hSession,
		RandomData,
		ulRandomLen
	);
}

CK_RV _C_GetFunctionStatus(
	CK_FUNCTION_LIST_PTR _funcs,
	CK_SESSION_HANDLE hSession
) {
	return (*_funcs->C_GetFunctionStatus)(
		hSession
	);
}

CK_RV _C_CancelFunction(
	CK_FUNCTION_LIST_PTR _funcs,
	CK_SESSION_HANDLE hSession
) {
	return (*_funcs->C_CancelFunction)(
		hSession
	);
}

CK_RV _C_WaitForSlotEvent(
	CK_FUNCTION_LIST_PTR _funcs,
	CK_FLAGS flags,
	CK_SLOT_ID_PTR pSlot,
	CK_VOID_PTR pRserved
) {
	return (*_funcs->C_WaitForSlotEvent)(
		flags,
		pSlot,
		pRserved
	);
}

*/
import "C"

type functionTable struct {
	t *C.CK_FUNCTION_LIST
}


func (f *functionTable) C_Initialize(
	pInitArgs C.CK_VOID_PTR,
) error {
	rv := C._C_Initialize(
		f.t,
		pInitArgs,
	);
	if rv != C.CKR_OK {
		return &Error{fnName: "C_Initialize", code: rValue(rv)}
	}
	return nil
}

func (f *functionTable) C_Finalize(
	pReserved C.CK_VOID_PTR,
) error {
	rv := C._C_Finalize(
		f.t,
		pReserved,
	);
	if rv != C.CKR_OK {
		return &Error{fnName: "C_Finalize", code: rValue(rv)}
	}
	return nil
}

func (f *functionTable) C_GetInfo(
	pInfo C.CK_INFO_PTR,
) error {
	rv := C._C_GetInfo(
		f.t,
		pInfo,
	);
	if rv != C.CKR_OK {
		return &Error{fnName: "C_GetInfo", code: rValue(rv)}
	}
	return nil
}

func (f *functionTable) C_GetFunctionList(
	ppFunctionList C.CK_FUNCTION_LIST_PTR_PTR,
) error {
	rv := C._C_GetFunctionList(
		f.t,
		ppFunctionList,
	);
	if rv != C.CKR_OK {
		return &Error{fnName: "C_GetFunctionList", code: rValue(rv)}
	}
	return nil
}

func (f *functionTable) C_GetSlotList(
	tokenPresent C.CK_BBOOL,
	pSlotList C.CK_SLOT_ID_PTR,
	pulCount C.CK_ULONG_PTR,
) error {
	rv := C._C_GetSlotList(
		f.t,
		tokenPresent,
		pSlotList,
		pulCount,
	);
	if rv != C.CKR_OK {
		return &Error{fnName: "C_GetSlotList", code: rValue(rv)}
	}
	return nil
}

func (f *functionTable) C_GetSlotInfo(
	slotID C.CK_SLOT_ID,
	pInfo C.CK_SLOT_INFO_PTR,
) error {
	rv := C._C_GetSlotInfo(
		f.t,
		slotID,
		pInfo,
	);
	if rv != C.CKR_OK {
		return &Error{fnName: "C_GetSlotInfo", code: rValue(rv)}
	}
	return nil
}

func (f *functionTable) C_GetTokenInfo(
	slotID C.CK_SLOT_ID,
	pInfo C.CK_TOKEN_INFO_PTR,
) error {
	rv := C._C_GetTokenInfo(
		f.t,
		slotID,
		pInfo,
	);
	if rv != C.CKR_OK {
		return &Error{fnName: "C_GetTokenInfo", code: rValue(rv)}
	}
	return nil
}

func (f *functionTable) C_GetMechanismList(
	slotID C.CK_SLOT_ID,
	pMechanismList C.CK_MECHANISM_TYPE_PTR,
	pulCount C.CK_ULONG_PTR,
) error {
	rv := C._C_GetMechanismList(
		f.t,
		slotID,
		pMechanismList,
		pulCount,
	);
	if rv != C.CKR_OK {
		return &Error{fnName: "C_GetMechanismList", code: rValue(rv)}
	}
	return nil
}

func (f *functionTable) C_GetMechanismInfo(
	slotID C.CK_SLOT_ID,
	_type C.CK_MECHANISM_TYPE,
	pInfo C.CK_MECHANISM_INFO_PTR,
) error {
	rv := C._C_GetMechanismInfo(
		f.t,
		slotID,
		_type,
		pInfo,
	);
	if rv != C.CKR_OK {
		return &Error{fnName: "C_GetMechanismInfo", code: rValue(rv)}
	}
	return nil
}

func (f *functionTable) C_InitToken(
	slotID C.CK_SLOT_ID,
	pPin C.CK_UTF8CHAR_PTR,
	ulPinLen C.CK_ULONG,
	pLabel C.CK_UTF8CHAR_PTR,
) error {
	rv := C._C_InitToken(
		f.t,
		slotID,
		pPin,
		ulPinLen,
		pLabel,
	);
	if rv != C.CKR_OK {
		return &Error{fnName: "C_InitToken", code: rValue(rv)}
	}
	return nil
}

func (f *functionTable) C_InitPIN(
	hSession C.CK_SESSION_HANDLE,
	pPin C.CK_UTF8CHAR_PTR,
	ulPinLen C.CK_ULONG,
) error {
	rv := C._C_InitPIN(
		f.t,
		hSession,
		pPin,
		ulPinLen,
	);
	if rv != C.CKR_OK {
		return &Error{fnName: "C_InitPIN", code: rValue(rv)}
	}
	return nil
}

func (f *functionTable) C_SetPIN(
	hSession C.CK_SESSION_HANDLE,
	pOldPin C.CK_UTF8CHAR_PTR,
	ulOldLen C.CK_ULONG,
	pNewPin C.CK_UTF8CHAR_PTR,
	ulNewLen C.CK_ULONG,
) error {
	rv := C._C_SetPIN(
		f.t,
		hSession,
		pOldPin,
		ulOldLen,
		pNewPin,
		ulNewLen,
	);
	if rv != C.CKR_OK {
		return &Error{fnName: "C_SetPIN", code: rValue(rv)}
	}
	return nil
}

func (f *functionTable) C_OpenSession(
	slotID C.CK_SLOT_ID,
	flags C.CK_FLAGS,
	pApplication C.CK_VOID_PTR,
	Notify C.CK_NOTIFY,
	phSession C.CK_SESSION_HANDLE_PTR,
) error {
	rv := C._C_OpenSession(
		f.t,
		slotID,
		flags,
		pApplication,
		Notify,
		phSession,
	);
	if rv != C.CKR_OK {
		return &Error{fnName: "C_OpenSession", code: rValue(rv)}
	}
	return nil
}

func (f *functionTable) C_CloseSession(
	hSession C.CK_SESSION_HANDLE,
) error {
	rv := C._C_CloseSession(
		f.t,
		hSession,
	);
	if rv != C.CKR_OK {
		return &Error{fnName: "C_CloseSession", code: rValue(rv)}
	}
	return nil
}

func (f *functionTable) C_CloseAllSessions(
	slotID C.CK_SLOT_ID,
) error {
	rv := C._C_CloseAllSessions(
		f.t,
		slotID,
	);
	if rv != C.CKR_OK {
		return &Error{fnName: "C_CloseAllSessions", code: rValue(rv)}
	}
	return nil
}

func (f *functionTable) C_GetSessionInfo(
	hSession C.CK_SESSION_HANDLE,
	pInfo C.CK_SESSION_INFO_PTR,
) error {
	rv := C._C_GetSessionInfo(
		f.t,
		hSession,
		pInfo,
	);
	if rv != C.CKR_OK {
		return &Error{fnName: "C_GetSessionInfo", code: rValue(rv)}
	}
	return nil
}

func (f *functionTable) C_GetOperationState(
	hSession C.CK_SESSION_HANDLE,
	pOperationState C.CK_BYTE_PTR,
	pulOperationStateLen C.CK_ULONG_PTR,
) error {
	rv := C._C_GetOperationState(
		f.t,
		hSession,
		pOperationState,
		pulOperationStateLen,
	);
	if rv != C.CKR_OK {
		return &Error{fnName: "C_GetOperationState", code: rValue(rv)}
	}
	return nil
}

func (f *functionTable) C_SetOperationState(
	hSession C.CK_SESSION_HANDLE,
	pOperationState C.CK_BYTE_PTR,
	ulOperationStateLen C.CK_ULONG,
	hEncryptionKey C.CK_OBJECT_HANDLE,
	hAuthenticationKey C.CK_OBJECT_HANDLE,
) error {
	rv := C._C_SetOperationState(
		f.t,
		hSession,
		pOperationState,
		ulOperationStateLen,
		hEncryptionKey,
		hAuthenticationKey,
	);
	if rv != C.CKR_OK {
		return &Error{fnName: "C_SetOperationState", code: rValue(rv)}
	}
	return nil
}

func (f *functionTable) C_Login(
	hSession C.CK_SESSION_HANDLE,
	userType C.CK_USER_TYPE,
	pPin C.CK_UTF8CHAR_PTR,
	ulPinLen C.CK_ULONG,
) error {
	rv := C._C_Login(
		f.t,
		hSession,
		userType,
		pPin,
		ulPinLen,
	);
	if rv != C.CKR_OK {
		return &Error{fnName: "C_Login", code: rValue(rv)}
	}
	return nil
}

func (f *functionTable) C_Logout(
	hSession C.CK_SESSION_HANDLE,
) error {
	rv := C._C_Logout(
		f.t,
		hSession,
	);
	if rv != C.CKR_OK {
		return &Error{fnName: "C_Logout", code: rValue(rv)}
	}
	return nil
}

func (f *functionTable) C_CreateObject(
	hSession C.CK_SESSION_HANDLE,
	pTemplate C.CK_ATTRIBUTE_PTR,
	ulCount C.CK_ULONG,
	phObject C.CK_OBJECT_HANDLE_PTR,
) error {
	rv := C._C_CreateObject(
		f.t,
		hSession,
		pTemplate,
		ulCount,
		phObject,
	);
	if rv != C.CKR_OK {
		return &Error{fnName: "C_CreateObject", code: rValue(rv)}
	}
	return nil
}

func (f *functionTable) C_CopyObject(
	hSession C.CK_SESSION_HANDLE,
	hObject C.CK_OBJECT_HANDLE,
	pTemplate C.CK_ATTRIBUTE_PTR,
	ulCount C.CK_ULONG,
	phNewObject C.CK_OBJECT_HANDLE_PTR,
) error {
	rv := C._C_CopyObject(
		f.t,
		hSession,
		hObject,
		pTemplate,
		ulCount,
		phNewObject,
	);
	if rv != C.CKR_OK {
		return &Error{fnName: "C_CopyObject", code: rValue(rv)}
	}
	return nil
}

func (f *functionTable) C_DestroyObject(
	hSession C.CK_SESSION_HANDLE,
	hObject C.CK_OBJECT_HANDLE,
) error {
	rv := C._C_DestroyObject(
		f.t,
		hSession,
		hObject,
	);
	if rv != C.CKR_OK {
		return &Error{fnName: "C_DestroyObject", code: rValue(rv)}
	}
	return nil
}

func (f *functionTable) C_GetObjectSize(
	hSession C.CK_SESSION_HANDLE,
	hObject C.CK_OBJECT_HANDLE,
	pulSize C.CK_ULONG_PTR,
) error {
	rv := C._C_GetObjectSize(
		f.t,
		hSession,
		hObject,
		pulSize,
	);
	if rv != C.CKR_OK {
		return &Error{fnName: "C_GetObjectSize", code: rValue(rv)}
	}
	return nil
}

func (f *functionTable) C_GetAttributeValue(
	hSession C.CK_SESSION_HANDLE,
	hObject C.CK_OBJECT_HANDLE,
	pTemplate C.CK_ATTRIBUTE_PTR,
	ulCount C.CK_ULONG,
) error {
	rv := C._C_GetAttributeValue(
		f.t,
		hSession,
		hObject,
		pTemplate,
		ulCount,
	);
	if rv != C.CKR_OK {
		return &Error{fnName: "C_GetAttributeValue", code: rValue(rv)}
	}
	return nil
}

func (f *functionTable) C_SetAttributeValue(
	hSession C.CK_SESSION_HANDLE,
	hObject C.CK_OBJECT_HANDLE,
	pTemplate C.CK_ATTRIBUTE_PTR,
	ulCount C.CK_ULONG,
) error {
	rv := C._C_SetAttributeValue(
		f.t,
		hSession,
		hObject,
		pTemplate,
		ulCount,
	);
	if rv != C.CKR_OK {
		return &Error{fnName: "C_SetAttributeValue", code: rValue(rv)}
	}
	return nil
}

func (f *functionTable) C_FindObjectsInit(
	hSession C.CK_SESSION_HANDLE,
	pTemplate C.CK_ATTRIBUTE_PTR,
	ulCount C.CK_ULONG,
) error {
	rv := C._C_FindObjectsInit(
		f.t,
		hSession,
		pTemplate,
		ulCount,
	);
	if rv != C.CKR_OK {
		return &Error{fnName: "C_FindObjectsInit", code: rValue(rv)}
	}
	return nil
}

func (f *functionTable) C_FindObjects(
	hSession C.CK_SESSION_HANDLE,
	phObject C.CK_OBJECT_HANDLE_PTR,
	ulMaxObjectCount C.CK_ULONG,
	pulObjectCount C.CK_ULONG_PTR,
) error {
	rv := C._C_FindObjects(
		f.t,
		hSession,
		phObject,
		ulMaxObjectCount,
		pulObjectCount,
	);
	if rv != C.CKR_OK {
		return &Error{fnName: "C_FindObjects", code: rValue(rv)}
	}
	return nil
}

func (f *functionTable) C_FindObjectsFinal(
	hSession C.CK_SESSION_HANDLE,
) error {
	rv := C._C_FindObjectsFinal(
		f.t,
		hSession,
	);
	if rv != C.CKR_OK {
		return &Error{fnName: "C_FindObjectsFinal", code: rValue(rv)}
	}
	return nil
}

func (f *functionTable) C_EncryptInit(
	hSession C.CK_SESSION_HANDLE,
	pMechanism C.CK_MECHANISM_PTR,
	hKey C.CK_OBJECT_HANDLE,
) error {
	rv := C._C_EncryptInit(
		f.t,
		hSession,
		pMechanism,
		hKey,
	);
	if rv != C.CKR_OK {
		return &Error{fnName: "C_EncryptInit", code: rValue(rv)}
	}
	return nil
}

func (f *functionTable) C_Encrypt(
	hSession C.CK_SESSION_HANDLE,
	pData C.CK_BYTE_PTR,
	ulDataLen C.CK_ULONG,
	pEncryptedData C.CK_BYTE_PTR,
	pulEncryptedDataLen C.CK_ULONG_PTR,
) error {
	rv := C._C_Encrypt(
		f.t,
		hSession,
		pData,
		ulDataLen,
		pEncryptedData,
		pulEncryptedDataLen,
	);
	if rv != C.CKR_OK {
		return &Error{fnName: "C_Encrypt", code: rValue(rv)}
	}
	return nil
}

func (f *functionTable) C_EncryptUpdate(
	hSession C.CK_SESSION_HANDLE,
	pPart C.CK_BYTE_PTR,
	ulPartLen C.CK_ULONG,
	pEncryptedPart C.CK_BYTE_PTR,
	pulEncryptedPartLen C.CK_ULONG_PTR,
) error {
	rv := C._C_EncryptUpdate(
		f.t,
		hSession,
		pPart,
		ulPartLen,
		pEncryptedPart,
		pulEncryptedPartLen,
	);
	if rv != C.CKR_OK {
		return &Error{fnName: "C_EncryptUpdate", code: rValue(rv)}
	}
	return nil
}

func (f *functionTable) C_EncryptFinal(
	hSession C.CK_SESSION_HANDLE,
	pLastEncryptedPart C.CK_BYTE_PTR,
	pulLastEncryptedPartLen C.CK_ULONG_PTR,
) error {
	rv := C._C_EncryptFinal(
		f.t,
		hSession,
		pLastEncryptedPart,
		pulLastEncryptedPartLen,
	);
	if rv != C.CKR_OK {
		return &Error{fnName: "C_EncryptFinal", code: rValue(rv)}
	}
	return nil
}

func (f *functionTable) C_DecryptInit(
	hSession C.CK_SESSION_HANDLE,
	pMechanism C.CK_MECHANISM_PTR,
	hKey C.CK_OBJECT_HANDLE,
) error {
	rv := C._C_DecryptInit(
		f.t,
		hSession,
		pMechanism,
		hKey,
	);
	if rv != C.CKR_OK {
		return &Error{fnName: "C_DecryptInit", code: rValue(rv)}
	}
	return nil
}

func (f *functionTable) C_Decrypt(
	hSession C.CK_SESSION_HANDLE,
	pEncryptedData C.CK_BYTE_PTR,
	ulEncryptedDataLen C.CK_ULONG,
	pData C.CK_BYTE_PTR,
	pulDataLen C.CK_ULONG_PTR,
) error {
	rv := C._C_Decrypt(
		f.t,
		hSession,
		pEncryptedData,
		ulEncryptedDataLen,
		pData,
		pulDataLen,
	);
	if rv != C.CKR_OK {
		return &Error{fnName: "C_Decrypt", code: rValue(rv)}
	}
	return nil
}

func (f *functionTable) C_DecryptUpdate(
	hSession C.CK_SESSION_HANDLE,
	pEncryptedPart C.CK_BYTE_PTR,
	ulEncryptedPartLen C.CK_ULONG,
	pPart C.CK_BYTE_PTR,
	pulPartLen C.CK_ULONG_PTR,
) error {
	rv := C._C_DecryptUpdate(
		f.t,
		hSession,
		pEncryptedPart,
		ulEncryptedPartLen,
		pPart,
		pulPartLen,
	);
	if rv != C.CKR_OK {
		return &Error{fnName: "C_DecryptUpdate", code: rValue(rv)}
	}
	return nil
}

func (f *functionTable) C_DecryptFinal(
	hSession C.CK_SESSION_HANDLE,
	pLastPart C.CK_BYTE_PTR,
	pulLastPartLen C.CK_ULONG_PTR,
) error {
	rv := C._C_DecryptFinal(
		f.t,
		hSession,
		pLastPart,
		pulLastPartLen,
	);
	if rv != C.CKR_OK {
		return &Error{fnName: "C_DecryptFinal", code: rValue(rv)}
	}
	return nil
}

func (f *functionTable) C_DigestInit(
	hSession C.CK_SESSION_HANDLE,
	pMechanism C.CK_MECHANISM_PTR,
) error {
	rv := C._C_DigestInit(
		f.t,
		hSession,
		pMechanism,
	);
	if rv != C.CKR_OK {
		return &Error{fnName: "C_DigestInit", code: rValue(rv)}
	}
	return nil
}

func (f *functionTable) C_Digest(
	hSession C.CK_SESSION_HANDLE,
	pData C.CK_BYTE_PTR,
	ulDataLen C.CK_ULONG,
	pDigest C.CK_BYTE_PTR,
	pulDigestLen C.CK_ULONG_PTR,
) error {
	rv := C._C_Digest(
		f.t,
		hSession,
		pData,
		ulDataLen,
		pDigest,
		pulDigestLen,
	);
	if rv != C.CKR_OK {
		return &Error{fnName: "C_Digest", code: rValue(rv)}
	}
	return nil
}

func (f *functionTable) C_DigestUpdate(
	hSession C.CK_SESSION_HANDLE,
	pPart C.CK_BYTE_PTR,
	ulPartLen C.CK_ULONG,
) error {
	rv := C._C_DigestUpdate(
		f.t,
		hSession,
		pPart,
		ulPartLen,
	);
	if rv != C.CKR_OK {
		return &Error{fnName: "C_DigestUpdate", code: rValue(rv)}
	}
	return nil
}

func (f *functionTable) C_DigestKey(
	hSession C.CK_SESSION_HANDLE,
	hKey C.CK_OBJECT_HANDLE,
) error {
	rv := C._C_DigestKey(
		f.t,
		hSession,
		hKey,
	);
	if rv != C.CKR_OK {
		return &Error{fnName: "C_DigestKey", code: rValue(rv)}
	}
	return nil
}

func (f *functionTable) C_DigestFinal(
	hSession C.CK_SESSION_HANDLE,
	pDigest C.CK_BYTE_PTR,
	pulDigestLen C.CK_ULONG_PTR,
) error {
	rv := C._C_DigestFinal(
		f.t,
		hSession,
		pDigest,
		pulDigestLen,
	);
	if rv != C.CKR_OK {
		return &Error{fnName: "C_DigestFinal", code: rValue(rv)}
	}
	return nil
}

func (f *functionTable) C_SignInit(
	hSession C.CK_SESSION_HANDLE,
	pMechanism C.CK_MECHANISM_PTR,
	hKey C.CK_OBJECT_HANDLE,
) error {
	rv := C._C_SignInit(
		f.t,
		hSession,
		pMechanism,
		hKey,
	);
	if rv != C.CKR_OK {
		return &Error{fnName: "C_SignInit", code: rValue(rv)}
	}
	return nil
}

func (f *functionTable) C_Sign(
	hSession C.CK_SESSION_HANDLE,
	pData C.CK_BYTE_PTR,
	ulDataLen C.CK_ULONG,
	pSignature C.CK_BYTE_PTR,
	pulSignatureLen C.CK_ULONG_PTR,
) error {
	rv := C._C_Sign(
		f.t,
		hSession,
		pData,
		ulDataLen,
		pSignature,
		pulSignatureLen,
	);
	if rv != C.CKR_OK {
		return &Error{fnName: "C_Sign", code: rValue(rv)}
	}
	return nil
}

func (f *functionTable) C_SignUpdate(
	hSession C.CK_SESSION_HANDLE,
	pPart C.CK_BYTE_PTR,
	ulPartLen C.CK_ULONG,
) error {
	rv := C._C_SignUpdate(
		f.t,
		hSession,
		pPart,
		ulPartLen,
	);
	if rv != C.CKR_OK {
		return &Error{fnName: "C_SignUpdate", code: rValue(rv)}
	}
	return nil
}

func (f *functionTable) C_SignFinal(
	hSession C.CK_SESSION_HANDLE,
	pSignature C.CK_BYTE_PTR,
	pulSignatureLen C.CK_ULONG_PTR,
) error {
	rv := C._C_SignFinal(
		f.t,
		hSession,
		pSignature,
		pulSignatureLen,
	);
	if rv != C.CKR_OK {
		return &Error{fnName: "C_SignFinal", code: rValue(rv)}
	}
	return nil
}

func (f *functionTable) C_SignRecoverInit(
	hSession C.CK_SESSION_HANDLE,
	pMechanism C.CK_MECHANISM_PTR,
	hKey C.CK_OBJECT_HANDLE,
) error {
	rv := C._C_SignRecoverInit(
		f.t,
		hSession,
		pMechanism,
		hKey,
	);
	if rv != C.CKR_OK {
		return &Error{fnName: "C_SignRecoverInit", code: rValue(rv)}
	}
	return nil
}

func (f *functionTable) C_SignRecover(
	hSession C.CK_SESSION_HANDLE,
	pData C.CK_BYTE_PTR,
	ulDataLen C.CK_ULONG,
	pSignature C.CK_BYTE_PTR,
	pulSignatureLen C.CK_ULONG_PTR,
) error {
	rv := C._C_SignRecover(
		f.t,
		hSession,
		pData,
		ulDataLen,
		pSignature,
		pulSignatureLen,
	);
	if rv != C.CKR_OK {
		return &Error{fnName: "C_SignRecover", code: rValue(rv)}
	}
	return nil
}

func (f *functionTable) C_VerifyInit(
	hSession C.CK_SESSION_HANDLE,
	pMechanism C.CK_MECHANISM_PTR,
	hKey C.CK_OBJECT_HANDLE,
) error {
	rv := C._C_VerifyInit(
		f.t,
		hSession,
		pMechanism,
		hKey,
	);
	if rv != C.CKR_OK {
		return &Error{fnName: "C_VerifyInit", code: rValue(rv)}
	}
	return nil
}

func (f *functionTable) C_Verify(
	hSession C.CK_SESSION_HANDLE,
	pData C.CK_BYTE_PTR,
	ulDataLen C.CK_ULONG,
	pSignature C.CK_BYTE_PTR,
	ulSignatureLen C.CK_ULONG,
) error {
	rv := C._C_Verify(
		f.t,
		hSession,
		pData,
		ulDataLen,
		pSignature,
		ulSignatureLen,
	);
	if rv != C.CKR_OK {
		return &Error{fnName: "C_Verify", code: rValue(rv)}
	}
	return nil
}

func (f *functionTable) C_VerifyUpdate(
	hSession C.CK_SESSION_HANDLE,
	pPart C.CK_BYTE_PTR,
	ulPartLen C.CK_ULONG,
) error {
	rv := C._C_VerifyUpdate(
		f.t,
		hSession,
		pPart,
		ulPartLen,
	);
	if rv != C.CKR_OK {
		return &Error{fnName: "C_VerifyUpdate", code: rValue(rv)}
	}
	return nil
}

func (f *functionTable) C_VerifyFinal(
	hSession C.CK_SESSION_HANDLE,
	pSignature C.CK_BYTE_PTR,
	ulSignatureLen C.CK_ULONG,
) error {
	rv := C._C_VerifyFinal(
		f.t,
		hSession,
		pSignature,
		ulSignatureLen,
	);
	if rv != C.CKR_OK {
		return &Error{fnName: "C_VerifyFinal", code: rValue(rv)}
	}
	return nil
}

func (f *functionTable) C_VerifyRecoverInit(
	hSession C.CK_SESSION_HANDLE,
	pMechanism C.CK_MECHANISM_PTR,
	hKey C.CK_OBJECT_HANDLE,
) error {
	rv := C._C_VerifyRecoverInit(
		f.t,
		hSession,
		pMechanism,
		hKey,
	);
	if rv != C.CKR_OK {
		return &Error{fnName: "C_VerifyRecoverInit", code: rValue(rv)}
	}
	return nil
}

func (f *functionTable) C_VerifyRecover(
	hSession C.CK_SESSION_HANDLE,
	pSignature C.CK_BYTE_PTR,
	ulSignatureLen C.CK_ULONG,
	pData C.CK_BYTE_PTR,
	pulDataLen C.CK_ULONG_PTR,
) error {
	rv := C._C_VerifyRecover(
		f.t,
		hSession,
		pSignature,
		ulSignatureLen,
		pData,
		pulDataLen,
	);
	if rv != C.CKR_OK {
		return &Error{fnName: "C_VerifyRecover", code: rValue(rv)}
	}
	return nil
}

func (f *functionTable) C_DigestEncryptUpdate(
	hSession C.CK_SESSION_HANDLE,
	pPart C.CK_BYTE_PTR,
	ulPartLen C.CK_ULONG,
	pEncryptedPart C.CK_BYTE_PTR,
	pulEncryptedPartLen C.CK_ULONG_PTR,
) error {
	rv := C._C_DigestEncryptUpdate(
		f.t,
		hSession,
		pPart,
		ulPartLen,
		pEncryptedPart,
		pulEncryptedPartLen,
	);
	if rv != C.CKR_OK {
		return &Error{fnName: "C_DigestEncryptUpdate", code: rValue(rv)}
	}
	return nil
}

func (f *functionTable) C_DecryptDigestUpdate(
	hSession C.CK_SESSION_HANDLE,
	pEncryptedPart C.CK_BYTE_PTR,
	ulEncryptedPartLen C.CK_ULONG,
	pPart C.CK_BYTE_PTR,
	pulPartLen C.CK_ULONG_PTR,
) error {
	rv := C._C_DecryptDigestUpdate(
		f.t,
		hSession,
		pEncryptedPart,
		ulEncryptedPartLen,
		pPart,
		pulPartLen,
	);
	if rv != C.CKR_OK {
		return &Error{fnName: "C_DecryptDigestUpdate", code: rValue(rv)}
	}
	return nil
}

func (f *functionTable) C_SignEncryptUpdate(
	hSession C.CK_SESSION_HANDLE,
	pPart C.CK_BYTE_PTR,
	ulPartLen C.CK_ULONG,
	pEncryptedPart C.CK_BYTE_PTR,
	pulEncryptedPartLen C.CK_ULONG_PTR,
) error {
	rv := C._C_SignEncryptUpdate(
		f.t,
		hSession,
		pPart,
		ulPartLen,
		pEncryptedPart,
		pulEncryptedPartLen,
	);
	if rv != C.CKR_OK {
		return &Error{fnName: "C_SignEncryptUpdate", code: rValue(rv)}
	}
	return nil
}

func (f *functionTable) C_DecryptVerifyUpdate(
	hSession C.CK_SESSION_HANDLE,
	pEncryptedPart C.CK_BYTE_PTR,
	ulEncryptedPartLen C.CK_ULONG,
	pPart C.CK_BYTE_PTR,
	pulPartLen C.CK_ULONG_PTR,
) error {
	rv := C._C_DecryptVerifyUpdate(
		f.t,
		hSession,
		pEncryptedPart,
		ulEncryptedPartLen,
		pPart,
		pulPartLen,
	);
	if rv != C.CKR_OK {
		return &Error{fnName: "C_DecryptVerifyUpdate", code: rValue(rv)}
	}
	return nil
}

func (f *functionTable) C_GenerateKey(
	hSession C.CK_SESSION_HANDLE,
	pMechanism C.CK_MECHANISM_PTR,
	pTemplate C.CK_ATTRIBUTE_PTR,
	ulCount C.CK_ULONG,
	phKey C.CK_OBJECT_HANDLE_PTR,
) error {
	rv := C._C_GenerateKey(
		f.t,
		hSession,
		pMechanism,
		pTemplate,
		ulCount,
		phKey,
	);
	if rv != C.CKR_OK {
		return &Error{fnName: "C_GenerateKey", code: rValue(rv)}
	}
	return nil
}

func (f *functionTable) C_GenerateKeyPair(
	hSession C.CK_SESSION_HANDLE,
	pMechanism C.CK_MECHANISM_PTR,
	pPublicKeyTemplate C.CK_ATTRIBUTE_PTR,
	ulPublicKeyAttributeCount C.CK_ULONG,
	pPrivateKeyTemplate C.CK_ATTRIBUTE_PTR,
	ulPrivateKeyAttributeCount C.CK_ULONG,
	phPublicKey C.CK_OBJECT_HANDLE_PTR,
	phPrivateKey C.CK_OBJECT_HANDLE_PTR,
) error {
	rv := C._C_GenerateKeyPair(
		f.t,
		hSession,
		pMechanism,
		pPublicKeyTemplate,
		ulPublicKeyAttributeCount,
		pPrivateKeyTemplate,
		ulPrivateKeyAttributeCount,
		phPublicKey,
		phPrivateKey,
	);
	if rv != C.CKR_OK {
		return &Error{fnName: "C_GenerateKeyPair", code: rValue(rv)}
	}
	return nil
}

func (f *functionTable) C_WrapKey(
	hSession C.CK_SESSION_HANDLE,
	pMechanism C.CK_MECHANISM_PTR,
	hWrappingKey C.CK_OBJECT_HANDLE,
	hKey C.CK_OBJECT_HANDLE,
	pWrappedKey C.CK_BYTE_PTR,
	pulWrappedKeyLen C.CK_ULONG_PTR,
) error {
	rv := C._C_WrapKey(
		f.t,
		hSession,
		pMechanism,
		hWrappingKey,
		hKey,
		pWrappedKey,
		pulWrappedKeyLen,
	);
	if rv != C.CKR_OK {
		return &Error{fnName: "C_WrapKey", code: rValue(rv)}
	}
	return nil
}

func (f *functionTable) C_UnwrapKey(
	hSession C.CK_SESSION_HANDLE,
	pMechanism C.CK_MECHANISM_PTR,
	hUnwrappingKey C.CK_OBJECT_HANDLE,
	pWrappedKey C.CK_BYTE_PTR,
	ulWrappedKeyLen C.CK_ULONG,
	pTemplate C.CK_ATTRIBUTE_PTR,
	ulAttributeCount C.CK_ULONG,
	phKey C.CK_OBJECT_HANDLE_PTR,
) error {
	rv := C._C_UnwrapKey(
		f.t,
		hSession,
		pMechanism,
		hUnwrappingKey,
		pWrappedKey,
		ulWrappedKeyLen,
		pTemplate,
		ulAttributeCount,
		phKey,
	);
	if rv != C.CKR_OK {
		return &Error{fnName: "C_UnwrapKey", code: rValue(rv)}
	}
	return nil
}

func (f *functionTable) C_DeriveKey(
	hSession C.CK_SESSION_HANDLE,
	pMechanism C.CK_MECHANISM_PTR,
	hBaseKey C.CK_OBJECT_HANDLE,
	pTemplate C.CK_ATTRIBUTE_PTR,
	ulAttributeCount C.CK_ULONG,
	phKey C.CK_OBJECT_HANDLE_PTR,
) error {
	rv := C._C_DeriveKey(
		f.t,
		hSession,
		pMechanism,
		hBaseKey,
		pTemplate,
		ulAttributeCount,
		phKey,
	);
	if rv != C.CKR_OK {
		return &Error{fnName: "C_DeriveKey", code: rValue(rv)}
	}
	return nil
}

func (f *functionTable) C_SeedRandom(
	hSession C.CK_SESSION_HANDLE,
	pSeed C.CK_BYTE_PTR,
	ulSeedLen C.CK_ULONG,
) error {
	rv := C._C_SeedRandom(
		f.t,
		hSession,
		pSeed,
		ulSeedLen,
	);
	if rv != C.CKR_OK {
		return &Error{fnName: "C_SeedRandom", code: rValue(rv)}
	}
	return nil
}

func (f *functionTable) C_GenerateRandom(
	hSession C.CK_SESSION_HANDLE,
	RandomData C.CK_BYTE_PTR,
	ulRandomLen C.CK_ULONG,
) error {
	rv := C._C_GenerateRandom(
		f.t,
		hSession,
		RandomData,
		ulRandomLen,
	);
	if rv != C.CKR_OK {
		return &Error{fnName: "C_GenerateRandom", code: rValue(rv)}
	}
	return nil
}

func (f *functionTable) C_GetFunctionStatus(
	hSession C.CK_SESSION_HANDLE,
) error {
	rv := C._C_GetFunctionStatus(
		f.t,
		hSession,
	);
	if rv != C.CKR_OK {
		return &Error{fnName: "C_GetFunctionStatus", code: rValue(rv)}
	}
	return nil
}

func (f *functionTable) C_CancelFunction(
	hSession C.CK_SESSION_HANDLE,
) error {
	rv := C._C_CancelFunction(
		f.t,
		hSession,
	);
	if rv != C.CKR_OK {
		return &Error{fnName: "C_CancelFunction", code: rValue(rv)}
	}
	return nil
}

func (f *functionTable) C_WaitForSlotEvent(
	flags C.CK_FLAGS,
	pSlot C.CK_SLOT_ID_PTR,
	pRserved C.CK_VOID_PTR,
) error {
	rv := C._C_WaitForSlotEvent(
		f.t,
		flags,
		pSlot,
		pRserved,
	);
	if rv != C.CKR_OK {
		return &Error{fnName: "C_WaitForSlotEvent", code: rValue(rv)}
	}
	return nil
}


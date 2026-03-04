//go:build (linux || darwin || freebsd) && testharness

package pkcs11

/*
#include <string.h>

#include "platform.h"

static CK_RV panic_test_get_slot_list(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount) {
	(void)tokenPresent;
	(void)pSlotList;
	*pulCount = 0;
	return CKR_OK;
}

static CK_RV panic_test_get_attribute_value(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
	(void)hSession;
	(void)hObject;
	for (CK_ULONG i = 0; i < ulCount; i++) {
		pTemplate[i].ulValueLen = 0;
	}
	return CKR_OK;
}

static CK_RV panic_test_sign_init(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
	(void)hSession;
	(void)pMechanism;
	(void)hKey;
	return CKR_OK;
}

static CK_RV panic_test_sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen) {
	(void)hSession;
	(void)pData;
	(void)ulDataLen;
	if (pSignature == NULL) {
		*pulSignatureLen = 64;
		return CKR_OK;
	}
	if (*pulSignatureLen != 0) {
		pSignature[0] = 0;
	}
	return CKR_OK;
}

static CK_RV panic_test_encrypt_init(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
	(void)hSession;
	(void)pMechanism;
	(void)hKey;
	return CKR_OK;
}

static CK_RV panic_test_encrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen) {
	(void)hSession;
	(void)pData;
	(void)ulDataLen;
	if (pEncryptedData == NULL) {
		*pulEncryptedDataLen = 1;
		return CKR_OK;
	}
	if (*pulEncryptedDataLen != 0) {
		pEncryptedData[0] = 0;
	}
	return CKR_OK;
}

static CK_RV panic_test_decrypt_init(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
	(void)hSession;
	(void)pMechanism;
	(void)hKey;
	return CKR_OK;
}

static CK_RV panic_test_decrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen) {
	(void)hSession;
	(void)pEncryptedData;
	(void)ulEncryptedDataLen;
	if (pData == NULL) {
		*pulDataLen = 1;
		return CKR_OK;
	}
	if (*pulDataLen != 0) {
		pData[0] = 0;
	}
	return CKR_OK;
}

static CK_RV panic_test_wrap_key(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen) {
	(void)hSession;
	(void)pMechanism;
	(void)hWrappingKey;
	(void)hKey;
	if (pWrappedKey == NULL) {
		*pulWrappedKeyLen = 0;
		return CKR_OK;
	}
	return CKR_OK;
}

static CK_FUNCTION_LIST panic_test_funcs;
static int panic_test_funcs_init = 0;

static CK_FUNCTION_LIST_PTR panic_test_function_list(void) {
	if (!panic_test_funcs_init) {
		memset(&panic_test_funcs, 0, sizeof(panic_test_funcs));
		panic_test_funcs.version.major = 3;
		panic_test_funcs.version.minor = 1;
		panic_test_funcs.C_GetSlotList = panic_test_get_slot_list;
		panic_test_funcs.C_GetAttributeValue = panic_test_get_attribute_value;
		panic_test_funcs.C_SignInit = panic_test_sign_init;
		panic_test_funcs.C_Sign = panic_test_sign;
		panic_test_funcs.C_EncryptInit = panic_test_encrypt_init;
		panic_test_funcs.C_Encrypt = panic_test_encrypt;
		panic_test_funcs.C_DecryptInit = panic_test_decrypt_init;
		panic_test_funcs.C_Decrypt = panic_test_decrypt;
		panic_test_funcs.C_WrapKey = panic_test_wrap_key;
		panic_test_funcs_init = 1;
	}
	return &panic_test_funcs;
}

static CK_RV mismatch_len_get_attribute_value(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
	(void)hSession;
	(void)hObject;
	if (pTemplate == NULL || ulCount == 0) {
		return CKR_ARGUMENTS_BAD;
	}

	// First pass: report a scalar size larger than the destination type.
	if (pTemplate[0].pValue == NULL) {
		pTemplate[0].ulValueLen = (CK_ULONG)(sizeof(CK_OBJECT_CLASS) + 1);
		return CKR_OK;
	}

	// Second pass: intentionally do nothing to keep the test deterministic and
	// avoid writing out of bounds.
	return CKR_OK;
}

static CK_FUNCTION_LIST mismatch_len_funcs;
static int mismatch_len_funcs_init = 0;

static CK_FUNCTION_LIST_PTR mismatch_len_function_list(void) {
	if (!mismatch_len_funcs_init) {
		memset(&mismatch_len_funcs, 0, sizeof(mismatch_len_funcs));
		mismatch_len_funcs.version.major = 3;
		mismatch_len_funcs.version.minor = 1;
		mismatch_len_funcs.C_GetAttributeValue = mismatch_len_get_attribute_value;
		mismatch_len_funcs_init = 1;
	}
	return &mismatch_len_funcs;
}

static CK_RV huge_len_get_attribute_value(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
	(void)hSession;
	(void)hObject;
	if (pTemplate == NULL || ulCount == 0) {
		return CKR_ARGUMENTS_BAD;
	}
	if (pTemplate[0].pValue == NULL) {
		// Force int overflow without hitting CK_UNAVAILABLE_INFORMATION (~0UL).
		pTemplate[0].ulValueLen = (CK_ULONG)(~(CK_ULONG)0 - 1UL);
		return CKR_OK;
	}
	return CKR_OK;
}

static CK_FUNCTION_LIST huge_len_funcs;
static int huge_len_funcs_init = 0;

static CK_FUNCTION_LIST_PTR huge_len_function_list(void) {
	if (!huge_len_funcs_init) {
		memset(&huge_len_funcs, 0, sizeof(huge_len_funcs));
		huge_len_funcs.version.major = 3;
		huge_len_funcs.version.minor = 1;
		huge_len_funcs.C_GetAttributeValue = huge_len_get_attribute_value;
		huge_len_funcs_init = 1;
	}
	return &huge_len_funcs;
}
*/
import "C"

func panicTestFunctionTable() functionTable {
	return functionTable{t: C.panic_test_function_list()}
}

func panicTestObject() *Object {
	return &Object{
		slot: &Session{
			ft: panicTestFunctionTable(),
			h:  C.CK_SESSION_HANDLE(1),
		},
		h: C.CK_OBJECT_HANDLE(1),
	}
}

func panicTestSignEmpty(obj *Object) {
	m := C.CK_MECHANISM{mechanism: C.CKM_RSA_PKCS}
	_, _ = obj.sign(&m, []byte{})
}

func panicTestEncryptEmpty(obj *Object) {
	m := C.CK_MECHANISM{mechanism: C.CKM_RSA_PKCS}
	_, _ = obj.encrypt(&m, []byte{})
}

func panicTestDecryptEmpty(obj *Object) {
	m := C.CK_MECHANISM{mechanism: C.CKM_RSA_PKCS}
	_, _ = obj.decrypt(&m, []byte{})
}

func panicTestWrapEmptyResult(obj *Object) {
	m := C.CK_MECHANISM{mechanism: C.CKM_RSA_PKCS}
	_, _ = obj.wrap(&m, obj)
}

func mismatchLenFunctionTable() functionTable {
	return functionTable{t: C.mismatch_len_function_list()}
}

func mismatchLenObject() *Object {
	return &Object{
		slot: &Session{
			ft: mismatchLenFunctionTable(),
			h:  C.CK_SESSION_HANDLE(1),
		},
		h: C.CK_OBJECT_HANDLE(1),
	}
}

func hugeLenFunctionTable() functionTable {
	return functionTable{t: C.huge_len_function_list()}
}

func hugeLenObject() *Object {
	return &Object{
		slot: &Session{
			ft: hugeLenFunctionTable(),
			h:  C.CK_SESSION_HANDLE(1),
		},
		h: C.CK_OBJECT_HANDLE(1),
	}
}

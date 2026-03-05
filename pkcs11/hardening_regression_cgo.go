//go:build (linux || darwin || freebsd) && testharness

package pkcs11

/*
#include <string.h>
#include <unistd.h>

#include "platform.h"

static CK_RV concurrent_get_attribute_value(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
	(void)hSession;
	(void)hObject;

	static volatile int inflight = 0;
	if (__sync_add_and_fetch(&inflight, 1) != 1) {
		__sync_sub_and_fetch(&inflight, 1);
		return CKR_OPERATION_ACTIVE;
	}

	usleep(5 * 1000);
	if (pTemplate == NULL || ulCount == 0) {
		__sync_sub_and_fetch(&inflight, 1);
		return CKR_ARGUMENTS_BAD;
	}

	for (CK_ULONG i = 0; i < ulCount; i++) {
		if (pTemplate[i].pValue == NULL) {
			pTemplate[i].ulValueLen = 1;
		} else if (pTemplate[i].ulValueLen > 0) {
			((CK_BYTE_PTR)pTemplate[i].pValue)[0] = 0;
		}
	}

	__sync_sub_and_fetch(&inflight, 1);
	return CKR_OK;
}

static CK_FUNCTION_LIST concurrent_get_attrs_funcs;
static int concurrent_get_attrs_funcs_init = 0;

static CK_FUNCTION_LIST_PTR concurrent_get_attrs_function_list(void) {
	if (!concurrent_get_attrs_funcs_init) {
		memset(&concurrent_get_attrs_funcs, 0, sizeof(concurrent_get_attrs_funcs));
		concurrent_get_attrs_funcs.version.major = 3;
		concurrent_get_attrs_funcs.version.minor = 1;
		concurrent_get_attrs_funcs.C_GetAttributeValue = concurrent_get_attribute_value;
		concurrent_get_attrs_funcs_init = 1;
	}
	return &concurrent_get_attrs_funcs;
}

static CK_RV oversized_attr_get_attribute_value(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
	(void)hSession;
	(void)hObject;

	if (pTemplate == NULL || ulCount == 0) {
		return CKR_ARGUMENTS_BAD;
	}
	if (pTemplate[0].pValue == NULL) {
		pTemplate[0].ulValueLen = (CK_ULONG)(2UL * 1024UL * 1024UL);
	}
	return CKR_OK;
}

static CK_FUNCTION_LIST oversized_attr_funcs;
static int oversized_attr_funcs_init = 0;

static CK_FUNCTION_LIST_PTR oversized_attr_function_list(void) {
	if (!oversized_attr_funcs_init) {
		memset(&oversized_attr_funcs, 0, sizeof(oversized_attr_funcs));
		oversized_attr_funcs.version.major = 3;
		oversized_attr_funcs.version.minor = 1;
		oversized_attr_funcs.C_GetAttributeValue = oversized_attr_get_attribute_value;
		oversized_attr_funcs_init = 1;
	}
	return &oversized_attr_funcs;
}

static CK_RV oversized_sign_init(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
	(void)hSession;
	(void)pMechanism;
	(void)hKey;
	return CKR_OK;
}

static CK_RV oversized_sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen) {
	(void)hSession;
	(void)pData;
	(void)ulDataLen;

	if (pulSignatureLen == NULL) {
		return CKR_ARGUMENTS_BAD;
	}
	if (pSignature == NULL) {
		*pulSignatureLen = (CK_ULONG)(2UL * 1024UL * 1024UL);
		return CKR_OK;
	}
	if (*pulSignatureLen > 0) {
		pSignature[0] = 0;
	}
	return CKR_OK;
}

static CK_FUNCTION_LIST oversized_sign_funcs;
static int oversized_sign_funcs_init = 0;

static CK_FUNCTION_LIST_PTR oversized_sign_function_list(void) {
	if (!oversized_sign_funcs_init) {
		memset(&oversized_sign_funcs, 0, sizeof(oversized_sign_funcs));
		oversized_sign_funcs.version.major = 3;
		oversized_sign_funcs.version.minor = 1;
		oversized_sign_funcs.C_SignInit = oversized_sign_init;
		oversized_sign_funcs.C_Sign = oversized_sign;
		oversized_sign_funcs_init = 1;
	}
	return &oversized_sign_funcs;
}

static int slot_retry_second_pass_calls = 0;

static void slot_retry_reset(void) {
	slot_retry_second_pass_calls = 0;
}

static CK_RV slot_retry_get_slot_list(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount) {
	(void)tokenPresent;

	if (pulCount == NULL) {
		return CKR_ARGUMENTS_BAD;
	}
	if (pSlotList == NULL) {
		*pulCount = 1;
		return CKR_OK;
	}

	slot_retry_second_pass_calls++;
	if (slot_retry_second_pass_calls == 1) {
		*pulCount = 2;
		return CKR_BUFFER_TOO_SMALL;
	}
	if (*pulCount < 2) {
		*pulCount = 2;
		return CKR_BUFFER_TOO_SMALL;
	}

	pSlotList[0] = (CK_SLOT_ID)1;
	pSlotList[1] = (CK_SLOT_ID)2;
	*pulCount = 2;
	return CKR_OK;
}

static CK_FUNCTION_LIST slot_retry_funcs;
static int slot_retry_funcs_init = 0;

static CK_FUNCTION_LIST_PTR slot_retry_function_list(void) {
	if (!slot_retry_funcs_init) {
		memset(&slot_retry_funcs, 0, sizeof(slot_retry_funcs));
		slot_retry_funcs.version.major = 3;
		slot_retry_funcs.version.minor = 1;
		slot_retry_funcs.C_GetSlotList = slot_retry_get_slot_list;
		slot_retry_funcs_init = 1;
	}
	return &slot_retry_funcs;
}
*/
import "C"

func concurrentGetAttrsObject() *Object {
	return &Object{
		slot: &Session{
			ft: functionTable{t: C.concurrent_get_attrs_function_list()},
			h:  C.CK_SESSION_HANDLE(1),
		},
		h: C.CK_OBJECT_HANDLE(1),
	}
}

func oversizedAttrObject() *Object {
	return &Object{
		slot: &Session{
			ft: functionTable{t: C.oversized_attr_function_list()},
			h:  C.CK_SESSION_HANDLE(1),
		},
		h: C.CK_OBJECT_HANDLE(1),
	}
}

func oversizedSignObject() *Object {
	return &Object{
		slot: &Session{
			ft: functionTable{t: C.oversized_sign_function_list()},
			h:  C.CK_SESSION_HANDLE(1),
		},
		h: C.CK_OBJECT_HANDLE(1),
	}
}

func slotRetryModule() *Module {
	C.slot_retry_reset()
	return &Module{
		ft: functionTable{t: C.slot_retry_function_list()},
	}
}

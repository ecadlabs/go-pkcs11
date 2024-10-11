package pkcs11

/*
#include "platform.h"
*/
import "C"
import "fmt"

// Error is returned for cryptokit specific API codes.
type Error struct {
	fnName string
	code   C.CK_RV
}

func (e *Error) Error() string {
	code, ok := ckRVString[e.code]
	if !ok {
		code = fmt.Sprintf("0x%x", e.code)
	}
	return fmt.Sprintf("pkcs11: %s(): %s", e.fnName, code)
}

var ckRVString = map[C.CK_RV]string{
	C.CKR_OK:                               "CKR_OK",
	C.CKR_CANCEL:                           "CKR_CANCEL",
	C.CKR_HOST_MEMORY:                      "CKR_HOST_MEMORY",
	C.CKR_SLOT_ID_INVALID:                  "CKR_SLOT_ID_INVALID",
	C.CKR_GENERAL_ERROR:                    "CKR_GENERAL_ERROR",
	C.CKR_FUNCTION_FAILED:                  "CKR_FUNCTION_FAILED",
	C.CKR_ARGUMENTS_BAD:                    "CKR_ARGUMENTS_BAD",
	C.CKR_NO_EVENT:                         "CKR_NO_EVENT",
	C.CKR_NEED_TO_CREATE_THREADS:           "CKR_NEED_TO_CREATE_THREADS",
	C.CKR_CANT_LOCK:                        "CKR_CANT_LOCK",
	C.CKR_ATTRIBUTE_READ_ONLY:              "CKR_ATTRIBUTE_READ_ONLY",
	C.CKR_ATTRIBUTE_SENSITIVE:              "CKR_ATTRIBUTE_SENSITIVE",
	C.CKR_ATTRIBUTE_TYPE_INVALID:           "CKR_ATTRIBUTE_TYPE_INVALID",
	C.CKR_ATTRIBUTE_VALUE_INVALID:          "CKR_ATTRIBUTE_VALUE_INVALID",
	C.CKR_ACTION_PROHIBITED:                "CKR_ACTION_PROHIBITED",
	C.CKR_DATA_INVALID:                     "CKR_DATA_INVALID",
	C.CKR_DATA_LEN_RANGE:                   "CKR_DATA_LEN_RANGE",
	C.CKR_DEVICE_ERROR:                     "CKR_DEVICE_ERROR",
	C.CKR_DEVICE_MEMORY:                    "CKR_DEVICE_MEMORY",
	C.CKR_DEVICE_REMOVED:                   "CKR_DEVICE_REMOVED",
	C.CKR_ENCRYPTED_DATA_INVALID:           "CKR_ENCRYPTED_DATA_INVALID",
	C.CKR_ENCRYPTED_DATA_LEN_RANGE:         "CKR_ENCRYPTED_DATA_LEN_RANGE",
	C.CKR_AEAD_DECRYPT_FAILED:              "CKR_AEAD_DECRYPT_FAILED",
	C.CKR_FUNCTION_CANCELED:                "CKR_FUNCTION_CANCELED",
	C.CKR_FUNCTION_NOT_PARALLEL:            "CKR_FUNCTION_NOT_PARALLEL",
	C.CKR_FUNCTION_NOT_SUPPORTED:           "CKR_FUNCTION_NOT_SUPPORTED",
	C.CKR_KEY_HANDLE_INVALID:               "CKR_KEY_HANDLE_INVALID",
	C.CKR_KEY_SIZE_RANGE:                   "CKR_KEY_SIZE_RANGE",
	C.CKR_KEY_TYPE_INCONSISTENT:            "CKR_KEY_TYPE_INCONSISTENT",
	C.CKR_KEY_NOT_NEEDED:                   "CKR_KEY_NOT_NEEDED",
	C.CKR_KEY_CHANGED:                      "CKR_KEY_CHANGED",
	C.CKR_KEY_NEEDED:                       "CKR_KEY_NEEDED",
	C.CKR_KEY_INDIGESTIBLE:                 "CKR_KEY_INDIGESTIBLE",
	C.CKR_KEY_FUNCTION_NOT_PERMITTED:       "CKR_KEY_FUNCTION_NOT_PERMITTED",
	C.CKR_KEY_NOT_WRAPPABLE:                "CKR_KEY_NOT_WRAPPABLE",
	C.CKR_KEY_UNEXTRACTABLE:                "CKR_KEY_UNEXTRACTABLE",
	C.CKR_MECHANISM_INVALID:                "CKR_MECHANISM_INVALID",
	C.CKR_MECHANISM_PARAM_INVALID:          "CKR_MECHANISM_PARAM_INVALID",
	C.CKR_OBJECT_HANDLE_INVALID:            "CKR_OBJECT_HANDLE_INVALID",
	C.CKR_OPERATION_ACTIVE:                 "CKR_OPERATION_ACTIVE",
	C.CKR_OPERATION_NOT_INITIALIZED:        "CKR_OPERATION_NOT_INITIALIZED",
	C.CKR_PIN_INCORRECT:                    "CKR_PIN_INCORRECT",
	C.CKR_PIN_INVALID:                      "CKR_PIN_INVALID",
	C.CKR_PIN_LEN_RANGE:                    "CKR_PIN_LEN_RANGE",
	C.CKR_PIN_EXPIRED:                      "CKR_PIN_EXPIRED",
	C.CKR_PIN_LOCKED:                       "CKR_PIN_LOCKED",
	C.CKR_SESSION_CLOSED:                   "CKR_SESSION_CLOSED",
	C.CKR_SESSION_COUNT:                    "CKR_SESSION_COUNT",
	C.CKR_SESSION_HANDLE_INVALID:           "CKR_SESSION_HANDLE_INVALID",
	C.CKR_SESSION_PARALLEL_NOT_SUPPORTED:   "CKR_SESSION_PARALLEL_NOT_SUPPORTED",
	C.CKR_SESSION_READ_ONLY:                "CKR_SESSION_READ_ONLY",
	C.CKR_SESSION_EXISTS:                   "CKR_SESSION_EXISTS",
	C.CKR_SESSION_READ_ONLY_EXISTS:         "CKR_SESSION_READ_ONLY_EXISTS",
	C.CKR_SESSION_READ_WRITE_SO_EXISTS:     "CKR_SESSION_READ_WRITE_SO_EXISTS",
	C.CKR_SIGNATURE_INVALID:                "CKR_SIGNATURE_INVALID",
	C.CKR_SIGNATURE_LEN_RANGE:              "CKR_SIGNATURE_LEN_RANGE",
	C.CKR_TEMPLATE_INCOMPLETE:              "CKR_TEMPLATE_INCOMPLETE",
	C.CKR_TEMPLATE_INCONSISTENT:            "CKR_TEMPLATE_INCONSISTENT",
	C.CKR_TOKEN_NOT_PRESENT:                "CKR_TOKEN_NOT_PRESENT",
	C.CKR_TOKEN_NOT_RECOGNIZED:             "CKR_TOKEN_NOT_RECOGNIZED",
	C.CKR_TOKEN_WRITE_PROTECTED:            "CKR_TOKEN_WRITE_PROTECTED",
	C.CKR_UNWRAPPING_KEY_HANDLE_INVALID:    "CKR_UNWRAPPING_KEY_HANDLE_INVALID",
	C.CKR_UNWRAPPING_KEY_SIZE_RANGE:        "CKR_UNWRAPPING_KEY_SIZE_RANGE",
	C.CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT: "CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT",
	C.CKR_USER_ALREADY_LOGGED_IN:           "CKR_USER_ALREADY_LOGGED_IN",
	C.CKR_USER_NOT_LOGGED_IN:               "CKR_USER_NOT_LOGGED_IN",
	C.CKR_USER_PIN_NOT_INITIALIZED:         "CKR_USER_PIN_NOT_INITIALIZED",
	C.CKR_USER_TYPE_INVALID:                "CKR_USER_TYPE_INVALID",
	C.CKR_USER_ANOTHER_ALREADY_LOGGED_IN:   "CKR_USER_ANOTHER_ALREADY_LOGGED_IN",
	C.CKR_USER_TOO_MANY_TYPES:              "CKR_USER_TOO_MANY_TYPES",
	C.CKR_WRAPPED_KEY_INVALID:              "CKR_WRAPPED_KEY_INVALID",
	C.CKR_WRAPPED_KEY_LEN_RANGE:            "CKR_WRAPPED_KEY_LEN_RANGE",
	C.CKR_WRAPPING_KEY_HANDLE_INVALID:      "CKR_WRAPPING_KEY_HANDLE_INVALID",
	C.CKR_WRAPPING_KEY_SIZE_RANGE:          "CKR_WRAPPING_KEY_SIZE_RANGE",
	C.CKR_WRAPPING_KEY_TYPE_INCONSISTENT:   "CKR_WRAPPING_KEY_TYPE_INCONSISTENT",
	C.CKR_RANDOM_SEED_NOT_SUPPORTED:        "CKR_RANDOM_SEED_NOT_SUPPORTED",
	C.CKR_RANDOM_NO_RNG:                    "CKR_RANDOM_NO_RNG",
	C.CKR_DOMAIN_PARAMS_INVALID:            "CKR_DOMAIN_PARAMS_INVALID",
	C.CKR_CURVE_NOT_SUPPORTED:              "CKR_CURVE_NOT_SUPPORTED",
	C.CKR_BUFFER_TOO_SMALL:                 "CKR_BUFFER_TOO_SMALL",
	C.CKR_SAVED_STATE_INVALID:              "CKR_SAVED_STATE_INVALID",
	C.CKR_INFORMATION_SENSITIVE:            "CKR_INFORMATION_SENSITIVE",
	C.CKR_STATE_UNSAVEABLE:                 "CKR_STATE_UNSAVEABLE",
	C.CKR_CRYPTOKI_NOT_INITIALIZED:         "CKR_CRYPTOKI_NOT_INITIALIZED",
	C.CKR_CRYPTOKI_ALREADY_INITIALIZED:     "CKR_CRYPTOKI_ALREADY_INITIALIZED",
	C.CKR_MUTEX_BAD:                        "CKR_MUTEX_BAD",
	C.CKR_MUTEX_NOT_LOCKED:                 "CKR_MUTEX_NOT_LOCKED",
	C.CKR_NEW_PIN_MODE:                     "CKR_NEW_PIN_MODE",
	C.CKR_NEXT_OTP:                         "CKR_NEXT_OTP",
	C.CKR_EXCEEDED_MAX_ITERATIONS:          "CKR_EXCEEDED_MAX_ITERATIONS",
	C.CKR_FIPS_SELF_TEST_FAILED:            "CKR_FIPS_SELF_TEST_FAILED",
	C.CKR_LIBRARY_LOAD_FAILED:              "CKR_LIBRARY_LOAD_FAILED",
	C.CKR_PIN_TOO_WEAK:                     "CKR_PIN_TOO_WEAK",
	C.CKR_PUBLIC_KEY_INVALID:               "CKR_PUBLIC_KEY_INVALID",
	C.CKR_FUNCTION_REJECTED:                "CKR_FUNCTION_REJECTED",
	C.CKR_TOKEN_RESOURCE_EXCEEDED:          "CKR_TOKEN_RESOURCE_EXCEEDED",
	C.CKR_OPERATION_CANCEL_FAILED:          "CKR_OPERATION_CANCEL_FAILED",
	C.CKR_KEY_EXHAUSTED:                    "CKR_KEY_EXHAUSTED",
	C.CKR_VENDOR_DEFINED:                   "CKR_VENDOR_DEFINED",
}

func (e *Error) Is(target error) bool {
	if t, ok := target.(*Error); ok {
		return e.code == t.code
	}
	return false
}

var (
	ErrCancel                        error = &Error{code: C.CKR_CANCEL}
	ErrHostMemory                    error = &Error{code: C.CKR_HOST_MEMORY}
	ErrSlotIdInvalid                 error = &Error{code: C.CKR_SLOT_ID_INVALID}
	ErrGeneralError                  error = &Error{code: C.CKR_GENERAL_ERROR}
	ErrFunctionFailed                error = &Error{code: C.CKR_FUNCTION_FAILED}
	ErrArgumentsBad                  error = &Error{code: C.CKR_ARGUMENTS_BAD}
	ErrNoEvent                       error = &Error{code: C.CKR_NO_EVENT}
	ErrNeedToCreateThreads           error = &Error{code: C.CKR_NEED_TO_CREATE_THREADS}
	ErrCantLock                      error = &Error{code: C.CKR_CANT_LOCK}
	ErrAttributeReadOnly             error = &Error{code: C.CKR_ATTRIBUTE_READ_ONLY}
	ErrAttributeSensitive            error = &Error{code: C.CKR_ATTRIBUTE_SENSITIVE}
	ErrAttributeTypeInvalid          error = &Error{code: C.CKR_ATTRIBUTE_TYPE_INVALID}
	ErrAttributeValueInvalid         error = &Error{code: C.CKR_ATTRIBUTE_VALUE_INVALID}
	ErrActionProhibited              error = &Error{code: C.CKR_ACTION_PROHIBITED}
	ErrDataInvalid                   error = &Error{code: C.CKR_DATA_INVALID}
	ErrDataLenRange                  error = &Error{code: C.CKR_DATA_LEN_RANGE}
	ErrDeviceError                   error = &Error{code: C.CKR_DEVICE_ERROR}
	ErrDeviceMemory                  error = &Error{code: C.CKR_DEVICE_MEMORY}
	ErrDeviceRemoved                 error = &Error{code: C.CKR_DEVICE_REMOVED}
	ErrEncryptedDataInvalid          error = &Error{code: C.CKR_ENCRYPTED_DATA_INVALID}
	ErrEncryptedDataLenRange         error = &Error{code: C.CKR_ENCRYPTED_DATA_LEN_RANGE}
	ErrAeadDecryptFailed             error = &Error{code: C.CKR_AEAD_DECRYPT_FAILED}
	ErrFunctionCanceled              error = &Error{code: C.CKR_FUNCTION_CANCELED}
	ErrFunctionNotParallel           error = &Error{code: C.CKR_FUNCTION_NOT_PARALLEL}
	ErrFunctionNotSupported          error = &Error{code: C.CKR_FUNCTION_NOT_SUPPORTED}
	ErrKeyHandleInvalid              error = &Error{code: C.CKR_KEY_HANDLE_INVALID}
	ErrKeySizeRange                  error = &Error{code: C.CKR_KEY_SIZE_RANGE}
	ErrKeyTypeInconsistent           error = &Error{code: C.CKR_KEY_TYPE_INCONSISTENT}
	ErrKeyNotNeeded                  error = &Error{code: C.CKR_KEY_NOT_NEEDED}
	ErrKeyChanged                    error = &Error{code: C.CKR_KEY_CHANGED}
	ErrKeyNeeded                     error = &Error{code: C.CKR_KEY_NEEDED}
	ErrKeyIndigestible               error = &Error{code: C.CKR_KEY_INDIGESTIBLE}
	ErrKeyFunctionNotPermitted       error = &Error{code: C.CKR_KEY_FUNCTION_NOT_PERMITTED}
	ErrKeyNotWrappable               error = &Error{code: C.CKR_KEY_NOT_WRAPPABLE}
	ErrKeyUnextractable              error = &Error{code: C.CKR_KEY_UNEXTRACTABLE}
	ErrMechanismInvalid              error = &Error{code: C.CKR_MECHANISM_INVALID}
	ErrMechanismParamInvalid         error = &Error{code: C.CKR_MECHANISM_PARAM_INVALID}
	ErrObjectHandleInvalid           error = &Error{code: C.CKR_OBJECT_HANDLE_INVALID}
	ErrOperationActive               error = &Error{code: C.CKR_OPERATION_ACTIVE}
	ErrOperationNotInitialized       error = &Error{code: C.CKR_OPERATION_NOT_INITIALIZED}
	ErrPinIncorrect                  error = &Error{code: C.CKR_PIN_INCORRECT}
	ErrPinInvalid                    error = &Error{code: C.CKR_PIN_INVALID}
	ErrPinLenRange                   error = &Error{code: C.CKR_PIN_LEN_RANGE}
	ErrPinExpired                    error = &Error{code: C.CKR_PIN_EXPIRED}
	ErrPinLocked                     error = &Error{code: C.CKR_PIN_LOCKED}
	ErrSessionClosed                 error = &Error{code: C.CKR_SESSION_CLOSED}
	ErrSessionCount                  error = &Error{code: C.CKR_SESSION_COUNT}
	ErrSessionHandleInvalid          error = &Error{code: C.CKR_SESSION_HANDLE_INVALID}
	ErrSessionParallelNotSupported   error = &Error{code: C.CKR_SESSION_PARALLEL_NOT_SUPPORTED}
	ErrSessionReadOnly               error = &Error{code: C.CKR_SESSION_READ_ONLY}
	ErrSessionExists                 error = &Error{code: C.CKR_SESSION_EXISTS}
	ErrSessionReadOnlyExists         error = &Error{code: C.CKR_SESSION_READ_ONLY_EXISTS}
	ErrSessionReadWriteSoExists      error = &Error{code: C.CKR_SESSION_READ_WRITE_SO_EXISTS}
	ErrSignatureInvalid              error = &Error{code: C.CKR_SIGNATURE_INVALID}
	ErrSignatureLenRange             error = &Error{code: C.CKR_SIGNATURE_LEN_RANGE}
	ErrTemplateIncomplete            error = &Error{code: C.CKR_TEMPLATE_INCOMPLETE}
	ErrTemplateInconsistent          error = &Error{code: C.CKR_TEMPLATE_INCONSISTENT}
	ErrTokenNotPresent               error = &Error{code: C.CKR_TOKEN_NOT_PRESENT}
	ErrTokenNotRecognized            error = &Error{code: C.CKR_TOKEN_NOT_RECOGNIZED}
	ErrTokenWriteProtected           error = &Error{code: C.CKR_TOKEN_WRITE_PROTECTED}
	ErrUnwrappingKeyHandleInvalid    error = &Error{code: C.CKR_UNWRAPPING_KEY_HANDLE_INVALID}
	ErrUnwrappingKeySizeRange        error = &Error{code: C.CKR_UNWRAPPING_KEY_SIZE_RANGE}
	ErrUnwrappingKeyTypeInconsistent error = &Error{code: C.CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT}
	ErrUserAlreadyLoggedIn           error = &Error{code: C.CKR_USER_ALREADY_LOGGED_IN}
	ErrUserNotLoggedIn               error = &Error{code: C.CKR_USER_NOT_LOGGED_IN}
	ErrUserPinNotInitialized         error = &Error{code: C.CKR_USER_PIN_NOT_INITIALIZED}
	ErrUserTypeInvalid               error = &Error{code: C.CKR_USER_TYPE_INVALID}
	ErrUserAnotherAlreadyLoggedIn    error = &Error{code: C.CKR_USER_ANOTHER_ALREADY_LOGGED_IN}
	ErrUserTooManyTypes              error = &Error{code: C.CKR_USER_TOO_MANY_TYPES}
	ErrWrappedKeyInvalid             error = &Error{code: C.CKR_WRAPPED_KEY_INVALID}
	ErrWrappedKeyLenRange            error = &Error{code: C.CKR_WRAPPED_KEY_LEN_RANGE}
	ErrWrappingKeyHandleInvalid      error = &Error{code: C.CKR_WRAPPING_KEY_HANDLE_INVALID}
	ErrWrappingKeySizeRange          error = &Error{code: C.CKR_WRAPPING_KEY_SIZE_RANGE}
	ErrWrappingKeyTypeInconsistent   error = &Error{code: C.CKR_WRAPPING_KEY_TYPE_INCONSISTENT}
	ErrRandomSeedNotSupported        error = &Error{code: C.CKR_RANDOM_SEED_NOT_SUPPORTED}
	ErrRandomNoRNG                   error = &Error{code: C.CKR_RANDOM_NO_RNG}
	ErrDomainParamsInvalid           error = &Error{code: C.CKR_DOMAIN_PARAMS_INVALID}
	ErrCurveNotSupported             error = &Error{code: C.CKR_CURVE_NOT_SUPPORTED}
	ErrBufferTooSmall                error = &Error{code: C.CKR_BUFFER_TOO_SMALL}
	ErrSavedStateInvalid             error = &Error{code: C.CKR_SAVED_STATE_INVALID}
	ErrInformationSensitive          error = &Error{code: C.CKR_INFORMATION_SENSITIVE}
	ErrStateUnsaveable               error = &Error{code: C.CKR_STATE_UNSAVEABLE}
	ErrCryptokiNotInitialized        error = &Error{code: C.CKR_CRYPTOKI_NOT_INITIALIZED}
	ErrCryptokiAlreadyInitialized    error = &Error{code: C.CKR_CRYPTOKI_ALREADY_INITIALIZED}
	ErrMutexBad                      error = &Error{code: C.CKR_MUTEX_BAD}
	ErrMutexNotLocked                error = &Error{code: C.CKR_MUTEX_NOT_LOCKED}
	ErrNewPinMode                    error = &Error{code: C.CKR_NEW_PIN_MODE}
	ErrNextOTP                       error = &Error{code: C.CKR_NEXT_OTP}
	ErrExceededMaxIterations         error = &Error{code: C.CKR_EXCEEDED_MAX_ITERATIONS}
	ErrFipsSelfTestFailed            error = &Error{code: C.CKR_FIPS_SELF_TEST_FAILED}
	ErrLibraryLoadFailed             error = &Error{code: C.CKR_LIBRARY_LOAD_FAILED}
	ErrPinTooWeak                    error = &Error{code: C.CKR_PIN_TOO_WEAK}
	ErrPublicKeyInvalid              error = &Error{code: C.CKR_PUBLIC_KEY_INVALID}
	ErrFunctionRejected              error = &Error{code: C.CKR_FUNCTION_REJECTED}
	ErrTokenResourceExceeded         error = &Error{code: C.CKR_TOKEN_RESOURCE_EXCEEDED}
	ErrOperationCancelFailed         error = &Error{code: C.CKR_OPERATION_CANCEL_FAILED}
	ErrKeyExhausted                  error = &Error{code: C.CKR_KEY_EXHAUSTED}
	ErrVendorDefined                 error = &Error{code: C.CKR_VENDOR_DEFINED}
)

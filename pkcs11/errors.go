package pkcs11

import "fmt"

// Error is returned for cryptokit specific API codes.
type Error struct {
	fnName string
	code   rValue
}

func (e *Error) Error() string {
	code, ok := ckRVString[e.code]
	if !ok {
		code = fmt.Sprintf("0x%x", e.code)
	}
	return fmt.Sprintf("pkcs11: %s(): %s", e.fnName, code)
}

var ckRVString = map[rValue]string{
	rvCancel:                        "CKR_CANCEL",
	rvHostMemory:                    "CKR_HOST_MEMORY",
	rvSlotIdInvalid:                 "CKR_SLOT_ID_INVALID",
	rvGeneralError:                  "CKR_GENERAL_ERROR",
	rvFunctionFailed:                "CKR_FUNCTION_FAILED",
	rvArgumentsBad:                  "CKR_ARGUMENTS_BAD",
	rvNoEvent:                       "CKR_NO_EVENT",
	rvNeedToCreateThreads:           "CKR_NEED_TO_CREATE_THREADS",
	rvCantLock:                      "CKR_CANT_LOCK",
	rvAttributeReadOnly:             "CKR_ATTRIBUTE_READ_ONLY",
	rvAttributeSensitive:            "CKR_ATTRIBUTE_SENSITIVE",
	rvAttributeTypeInvalid:          "CKR_ATTRIBUTE_TYPE_INVALID",
	rvAttributeValueInvalid:         "CKR_ATTRIBUTE_VALUE_INVALID",
	rvActionProhibited:              "CKR_ACTION_PROHIBITED",
	rvDataInvalid:                   "CKR_DATA_INVALID",
	rvDataLenRange:                  "CKR_DATA_LEN_RANGE",
	rvDeviceError:                   "CKR_DEVICE_ERROR",
	rvDeviceMemory:                  "CKR_DEVICE_MEMORY",
	rvDeviceRemoved:                 "CKR_DEVICE_REMOVED",
	rvEncryptedDataInvalid:          "CKR_ENCRYPTED_DATA_INVALID",
	rvEncryptedDataLenRange:         "CKR_ENCRYPTED_DATA_LEN_RANGE",
	rvFunctionCanceled:              "CKR_FUNCTION_CANCELED",
	rvFunctionNotParallel:           "CKR_FUNCTION_NOT_PARALLEL",
	rvFunctionNotSupported:          "CKR_FUNCTION_NOT_SUPPORTED",
	rvKeyHandleInvalid:              "CKR_KEY_HANDLE_INVALID",
	rvKeySizeRange:                  "CKR_KEY_SIZE_RANGE",
	rvKeyTypeInconsistent:           "CKR_KEY_TYPE_INCONSISTENT",
	rvKeyNotNeeded:                  "CKR_KEY_NOT_NEEDED",
	rvKeyChanged:                    "CKR_KEY_CHANGED",
	rvKeyNeeded:                     "CKR_KEY_NEEDED",
	rvKeyIndigestible:               "CKR_KEY_INDIGESTIBLE",
	rvKeyFunctionNotPermitted:       "CKR_KEY_FUNCTION_NOT_PERMITTED",
	rvKeyNotWrappable:               "CKR_KEY_NOT_WRAPPABLE",
	rvKeyUnextractable:              "CKR_KEY_UNEXTRACTABLE",
	rvMechanismInvalid:              "CKR_MECHANISM_INVALID",
	rvMechanismParamInvalid:         "CKR_MECHANISM_PARAM_INVALID",
	rvObjectHandleInvalid:           "CKR_OBJECT_HANDLE_INVALID",
	rvOperationActive:               "CKR_OPERATION_ACTIVE",
	rvOperationNotInitialized:       "CKR_OPERATION_NOT_INITIALIZED",
	rvPinIncorrect:                  "CKR_PIN_INCORRECT",
	rvPinInvalid:                    "CKR_PIN_INVALID",
	rvPinLenRange:                   "CKR_PIN_LEN_RANGE",
	rvPinExpired:                    "CKR_PIN_EXPIRED",
	rvPinLocked:                     "CKR_PIN_LOCKED",
	rvSessionClosed:                 "CKR_SESSION_CLOSED",
	rvSessionCount:                  "CKR_SESSION_COUNT",
	rvSessionHandleInvalid:          "CKR_SESSION_HANDLE_INVALID",
	rvSessionParallelNotSupported:   "CKR_SESSION_PARALLEL_NOT_SUPPORTED",
	rvSessionReadOnly:               "CKR_SESSION_READ_ONLY",
	rvSessionExists:                 "CKR_SESSION_EXISTS",
	rvSessionReadOnlyExists:         "CKR_SESSION_READ_ONLY_EXISTS",
	rvSessionReadWriteSoExists:      "CKR_SESSION_READ_WRITE_SO_EXISTS",
	rvSignatureInvalid:              "CKR_SIGNATURE_INVALID",
	rvSignatureLenRange:             "CKR_SIGNATURE_LEN_RANGE",
	rvTemplateIncomplete:            "CKR_TEMPLATE_INCOMPLETE",
	rvTemplateInconsistent:          "CKR_TEMPLATE_INCONSISTENT",
	rvTokenNotPresent:               "CKR_TOKEN_NOT_PRESENT",
	rvTokenNotRecognized:            "CKR_TOKEN_NOT_RECOGNIZED",
	rvTokenWriteProtected:           "CKR_TOKEN_WRITE_PROTECTED",
	rvUnwrappingKeyHandleInvalid:    "CKR_UNWRAPPING_KEY_HANDLE_INVALID",
	rvUnwrappingKeySizeRange:        "CKR_UNWRAPPING_KEY_SIZE_RANGE",
	rvUnwrappingKeyTypeInconsistent: "CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT",
	rvUserAlreadyLoggedIn:           "CKR_USER_ALREADY_LOGGED_IN",
	rvUserNotLoggedIn:               "CKR_USER_NOT_LOGGED_IN",
	rvUserPinNotInitialized:         "CKR_USER_PIN_NOT_INITIALIZED",
	rvUserTypeInvalid:               "CKR_USER_TYPE_INVALID",
	rvUserAnotherAlreadyLoggedIn:    "CKR_USER_ANOTHER_ALREADY_LOGGED_IN",
	rvUserTooManyTypes:              "CKR_USER_TOO_MANY_TYPES",
	rvWrappedKeyInvalid:             "CKR_WRAPPED_KEY_INVALID",
	rvWrappedKeyLenRange:            "CKR_WRAPPED_KEY_LEN_RANGE",
	rvWrappingKeyHandleInvalid:      "CKR_WRAPPING_KEY_HANDLE_INVALID",
	rvWrappingKeySizeRange:          "CKR_WRAPPING_KEY_SIZE_RANGE",
	rvWrappingKeyTypeInconsistent:   "CKR_WRAPPING_KEY_TYPE_INCONSISTENT",
	rvRandomSeedNotSupported:        "CKR_RANDOM_SEED_NOT_SUPPORTED",
	rvRandomNoRng:                   "CKR_RANDOM_NO_RNG",
	rvDomainParamsInvalid:           "CKR_DOMAIN_PARAMS_INVALID",
	rvCurveNotSupported:             "CKR_CURVE_NOT_SUPPORTED",
	rvBufferTooSmall:                "CKR_BUFFER_TOO_SMALL",
	rvSavedStateInvalid:             "CKR_SAVED_STATE_INVALID",
	rvInformationSensitive:          "CKR_INFORMATION_SENSITIVE",
	rvStateUnsaveable:               "CKR_STATE_UNSAVEABLE",
	rvCryptokiNotInitialized:        "CKR_CRYPTOKI_NOT_INITIALIZED",
	rvCryptokiAlreadyInitialized:    "CKR_CRYPTOKI_ALREADY_INITIALIZED",
	rvMutexBad:                      "CKR_MUTEX_BAD",
	rvMutexNotLocked:                "CKR_MUTEX_NOT_LOCKED",
	rvFunctionRejected:              "CKR_FUNCTION_REJECTED",
	rvVendorDefined:                 "CKR_VENDOR_DEFINED",
}

func (e *Error) Is(target error) bool {
	if t, ok := target.(*Error); ok {
		return e.code == t.code
	}
	return false
}

var (
	ErrCancel                        error = &Error{code: rvCancel}
	ErrHostMemory                    error = &Error{code: rvHostMemory}
	ErrSlotIdInvalid                 error = &Error{code: rvSlotIdInvalid}
	ErrGeneralError                  error = &Error{code: rvGeneralError}
	ErrFunctionFailed                error = &Error{code: rvFunctionFailed}
	ErrArgumentsBad                  error = &Error{code: rvArgumentsBad}
	ErrNoEvent                       error = &Error{code: rvNoEvent}
	ErrNeedToCreateThreads           error = &Error{code: rvNeedToCreateThreads}
	ErrCantLock                      error = &Error{code: rvCantLock}
	ErrAttributeReadOnly             error = &Error{code: rvAttributeReadOnly}
	ErrAttributeSensitive            error = &Error{code: rvAttributeSensitive}
	ErrAttributeTypeInvalid          error = &Error{code: rvAttributeTypeInvalid}
	ErrAttributeValueInvalid         error = &Error{code: rvAttributeValueInvalid}
	ErrActionProhibited              error = &Error{code: rvActionProhibited}
	ErrDataInvalid                   error = &Error{code: rvDataInvalid}
	ErrDataLenRange                  error = &Error{code: rvDataLenRange}
	ErrDeviceError                   error = &Error{code: rvDeviceError}
	ErrDeviceMemory                  error = &Error{code: rvDeviceMemory}
	ErrDeviceRemoved                 error = &Error{code: rvDeviceRemoved}
	ErrEncryptedDataInvalid          error = &Error{code: rvEncryptedDataInvalid}
	ErrEncryptedDataLenRange         error = &Error{code: rvEncryptedDataLenRange}
	ErrFunctionCanceled              error = &Error{code: rvFunctionCanceled}
	ErrFunctionNotParallel           error = &Error{code: rvFunctionNotParallel}
	ErrFunctionNotSupported          error = &Error{code: rvFunctionNotSupported}
	ErrKeyHandleInvalid              error = &Error{code: rvKeyHandleInvalid}
	ErrKeySizeRange                  error = &Error{code: rvKeySizeRange}
	ErrKeyTypeInconsistent           error = &Error{code: rvKeyTypeInconsistent}
	ErrKeyNotNeeded                  error = &Error{code: rvKeyNotNeeded}
	ErrKeyChanged                    error = &Error{code: rvKeyChanged}
	ErrKeyNeeded                     error = &Error{code: rvKeyNeeded}
	ErrKeyIndigestible               error = &Error{code: rvKeyIndigestible}
	ErrKeyFunctionNotPermitted       error = &Error{code: rvKeyFunctionNotPermitted}
	ErrKeyNotWrappable               error = &Error{code: rvKeyNotWrappable}
	ErrKeyUnextractable              error = &Error{code: rvKeyUnextractable}
	ErrMechanismInvalid              error = &Error{code: rvMechanismInvalid}
	ErrMechanismParamInvalid         error = &Error{code: rvMechanismParamInvalid}
	ErrObjectHandleInvalid           error = &Error{code: rvObjectHandleInvalid}
	ErrOperationActive               error = &Error{code: rvOperationActive}
	ErrOperationNotInitialized       error = &Error{code: rvOperationNotInitialized}
	ErrPinIncorrect                  error = &Error{code: rvPinIncorrect}
	ErrPinInvalid                    error = &Error{code: rvPinInvalid}
	ErrPinLenRange                   error = &Error{code: rvPinLenRange}
	ErrPinExpired                    error = &Error{code: rvPinExpired}
	ErrPinLocked                     error = &Error{code: rvPinLocked}
	ErrSessionClosed                 error = &Error{code: rvSessionClosed}
	ErrSessionCount                  error = &Error{code: rvSessionCount}
	ErrSessionHandleInvalid          error = &Error{code: rvSessionHandleInvalid}
	ErrSessionParallelNotSupported   error = &Error{code: rvSessionParallelNotSupported}
	ErrSessionReadOnly               error = &Error{code: rvSessionReadOnly}
	ErrSessionExists                 error = &Error{code: rvSessionExists}
	ErrSessionReadOnlyExists         error = &Error{code: rvSessionReadOnlyExists}
	ErrSessionReadWriteSoExists      error = &Error{code: rvSessionReadWriteSoExists}
	ErrSignatureInvalid              error = &Error{code: rvSignatureInvalid}
	ErrSignatureLenRange             error = &Error{code: rvSignatureLenRange}
	ErrTemplateIncomplete            error = &Error{code: rvTemplateIncomplete}
	ErrTemplateInconsistent          error = &Error{code: rvTemplateInconsistent}
	ErrTokenNotPresent               error = &Error{code: rvTokenNotPresent}
	ErrTokenNotRecognized            error = &Error{code: rvTokenNotRecognized}
	ErrTokenWriteProtected           error = &Error{code: rvTokenWriteProtected}
	ErrUnwrappingKeyHandleInvalid    error = &Error{code: rvUnwrappingKeyHandleInvalid}
	ErrUnwrappingKeySizeRange        error = &Error{code: rvUnwrappingKeySizeRange}
	ErrUnwrappingKeyTypeInconsistent error = &Error{code: rvUnwrappingKeyTypeInconsistent}
	ErrUserAlreadyLoggedIn           error = &Error{code: rvUserAlreadyLoggedIn}
	ErrUserNotLoggedIn               error = &Error{code: rvUserNotLoggedIn}
	ErrUserPinNotInitialized         error = &Error{code: rvUserPinNotInitialized}
	ErrUserTypeInvalid               error = &Error{code: rvUserTypeInvalid}
	ErrUserAnotherAlreadyLoggedIn    error = &Error{code: rvUserAnotherAlreadyLoggedIn}
	ErrUserTooManyTypes              error = &Error{code: rvUserTooManyTypes}
	ErrWrappedKeyInvalid             error = &Error{code: rvWrappedKeyInvalid}
	ErrWrappedKeyLenRange            error = &Error{code: rvWrappedKeyLenRange}
	ErrWrappingKeyHandleInvalid      error = &Error{code: rvWrappingKeyHandleInvalid}
	ErrWrappingKeySizeRange          error = &Error{code: rvWrappingKeySizeRange}
	ErrWrappingKeyTypeInconsistent   error = &Error{code: rvWrappingKeyTypeInconsistent}
	ErrRandomSeedNotSupported        error = &Error{code: rvRandomSeedNotSupported}
	ErrRandomNoRng                   error = &Error{code: rvRandomNoRng}
	ErrDomainParamsInvalid           error = &Error{code: rvDomainParamsInvalid}
	ErrCurveNotSupported             error = &Error{code: rvCurveNotSupported}
	ErrBufferTooSmall                error = &Error{code: rvBufferTooSmall}
	ErrSavedStateInvalid             error = &Error{code: rvSavedStateInvalid}
	ErrInformationSensitive          error = &Error{code: rvInformationSensitive}
	ErrStateUnsaveable               error = &Error{code: rvStateUnsaveable}
	ErrCryptokiNotInitialized        error = &Error{code: rvCryptokiNotInitialized}
	ErrCryptokiAlreadyInitialized    error = &Error{code: rvCryptokiAlreadyInitialized}
	ErrMutexBad                      error = &Error{code: rvMutexBad}
	ErrMutexNotLocked                error = &Error{code: rvMutexNotLocked}
	ErrFunctionRejected              error = &Error{code: rvFunctionRejected}
	ErrVendorDefined                 error = &Error{code: rvVendorDefined}
)

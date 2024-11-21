package pkcs11

/*
#include "platform.h"
*/
import "C"
import (
	"encoding/hex"
	"fmt"
	"math/big"
	"strconv"
	"unsafe"
)

type Uint C.CK_ULONG

func (u Uint) String() string { return fmt.Sprintf("%#016x", C.CK_ULONG(u)) }

type Bool C.CK_BBOOL

func (b Bool) ToBool() bool   { return b != 0 }
func (b Bool) String() string { return fmt.Sprintf("%t", b.ToBool()) }

type String []byte

func (s String) String() string { return string(s) }

type Bytes []byte

func (b Bytes) String() string { return hex.EncodeToString(b) }

type AttributeType C.CK_ATTRIBUTE_TYPE

type BigInt []byte

func (b BigInt) String() string { return new(big.Int).SetBytes(b).String() }

const (
	AttributeClass                   AttributeType = C.CKA_CLASS
	AttributeToken                   AttributeType = C.CKA_TOKEN
	AttributePrivate                 AttributeType = C.CKA_PRIVATE
	AttributeLabel                   AttributeType = C.CKA_LABEL
	AttributeUniqueID                AttributeType = C.CKA_UNIQUE_ID
	AttributeApplication             AttributeType = C.CKA_APPLICATION
	AttributeValue                   AttributeType = C.CKA_VALUE
	AttributeObjectID                AttributeType = C.CKA_OBJECT_ID
	AttributeCertificateType         AttributeType = C.CKA_CERTIFICATE_TYPE
	AttributeIssuer                  AttributeType = C.CKA_ISSUER
	AttributeSerialNumber            AttributeType = C.CKA_SERIAL_NUMBER
	AttributeACIssuer                AttributeType = C.CKA_AC_ISSUER
	AttributeOwner                   AttributeType = C.CKA_OWNER
	AttributeAttrTypes               AttributeType = C.CKA_ATTR_TYPES
	AttributeTrusted                 AttributeType = C.CKA_TRUSTED
	AttributeCertificateCategory     AttributeType = C.CKA_CERTIFICATE_CATEGORY
	AttributeJavaMIDPSecurityDomain  AttributeType = C.CKA_JAVA_MIDP_SECURITY_DOMAIN
	AttributeURL                     AttributeType = C.CKA_URL
	AttributeHashOfSubjectPublicKey  AttributeType = C.CKA_HASH_OF_SUBJECT_PUBLIC_KEY
	AttributeHashOfIssuerPublicKey   AttributeType = C.CKA_HASH_OF_ISSUER_PUBLIC_KEY
	AttributeNameHashAlgorithm       AttributeType = C.CKA_NAME_HASH_ALGORITHM
	AttributeCheckValue              AttributeType = C.CKA_CHECK_VALUE
	AttributeKeyType                 AttributeType = C.CKA_KEY_TYPE
	AttributeSubject                 AttributeType = C.CKA_SUBJECT
	AttributeID                      AttributeType = C.CKA_ID
	AttributeSensitive               AttributeType = C.CKA_SENSITIVE
	AttributeEncrypt                 AttributeType = C.CKA_ENCRYPT
	AttributeDecrypt                 AttributeType = C.CKA_DECRYPT
	AttributeWrap                    AttributeType = C.CKA_WRAP
	AttributeUnwrap                  AttributeType = C.CKA_UNWRAP
	AttributeSign                    AttributeType = C.CKA_SIGN
	AttributeSignRecover             AttributeType = C.CKA_SIGN_RECOVER
	AttributeVerify                  AttributeType = C.CKA_VERIFY
	AttributeVerifyRecover           AttributeType = C.CKA_VERIFY_RECOVER
	AttributeDerive                  AttributeType = C.CKA_DERIVE
	AttributeStartDate               AttributeType = C.CKA_START_DATE
	AttributeEndDate                 AttributeType = C.CKA_END_DATE
	AttributeModulus                 AttributeType = C.CKA_MODULUS
	AttributeModulusBits             AttributeType = C.CKA_MODULUS_BITS
	AttributePublicExponent          AttributeType = C.CKA_PUBLIC_EXPONENT
	AttributePrivateExponent         AttributeType = C.CKA_PRIVATE_EXPONENT
	AttributePrime_1                 AttributeType = C.CKA_PRIME_1
	AttributePrime_2                 AttributeType = C.CKA_PRIME_2
	AttributeExponent_1              AttributeType = C.CKA_EXPONENT_1
	AttributeExponent_2              AttributeType = C.CKA_EXPONENT_2
	AttributeCoefficient             AttributeType = C.CKA_COEFFICIENT
	AttributePublicKeyInfo           AttributeType = C.CKA_PUBLIC_KEY_INFO
	AttributePrime                   AttributeType = C.CKA_PRIME
	AttributeSubprime                AttributeType = C.CKA_SUBPRIME
	AttributeBase                    AttributeType = C.CKA_BASE
	AttributePrimeBits               AttributeType = C.CKA_PRIME_BITS
	AttributeSubPrimeBits            AttributeType = C.CKA_SUB_PRIME_BITS
	AttributeValueBits               AttributeType = C.CKA_VALUE_BITS
	AttributeValueLen                AttributeType = C.CKA_VALUE_LEN
	AttributeExtractable             AttributeType = C.CKA_EXTRACTABLE
	AttributeLocal                   AttributeType = C.CKA_LOCAL
	AttributeNeverExtractable        AttributeType = C.CKA_NEVER_EXTRACTABLE
	AttributeAlwaysSensitive         AttributeType = C.CKA_ALWAYS_SENSITIVE
	AttributeKeyGenMechanism         AttributeType = C.CKA_KEY_GEN_MECHANISM
	AttributeModifiable              AttributeType = C.CKA_MODIFIABLE
	AttributeCopyable                AttributeType = C.CKA_COPYABLE
	AttributeDestroyable             AttributeType = C.CKA_DESTROYABLE
	AttributeECParams                AttributeType = C.CKA_EC_PARAMS
	AttributeECPoint                 AttributeType = C.CKA_EC_POINT
	AttributeAlwaysAuthenticate      AttributeType = C.CKA_ALWAYS_AUTHENTICATE
	AttributeWrapWithTrusted         AttributeType = C.CKA_WRAP_WITH_TRUSTED
	AttributeWrapTemplate            AttributeType = C.CKA_WRAP_TEMPLATE
	AttributeUnwrapTemplate          AttributeType = C.CKA_UNWRAP_TEMPLATE
	AttributeDeriveTemplate          AttributeType = C.CKA_DERIVE_TEMPLATE
	AttributeOTPFormat               AttributeType = C.CKA_OTP_FORMAT
	AttributeOTPLength               AttributeType = C.CKA_OTP_LENGTH
	AttributeOTPTimeInterval         AttributeType = C.CKA_OTP_TIME_INTERVAL
	AttributeOTPUserFriendlyMode     AttributeType = C.CKA_OTP_USER_FRIENDLY_MODE
	AttributeOTPChallengeRequirement AttributeType = C.CKA_OTP_CHALLENGE_REQUIREMENT
	AttributeOTPTimeRequirement      AttributeType = C.CKA_OTP_TIME_REQUIREMENT
	AttributeOTPCounterRequirement   AttributeType = C.CKA_OTP_COUNTER_REQUIREMENT
	AttributeOTPPinRequirement       AttributeType = C.CKA_OTP_PIN_REQUIREMENT
	AttributeOTPCounter              AttributeType = C.CKA_OTP_COUNTER
	AttributeOTPTime                 AttributeType = C.CKA_OTP_TIME
	AttributeOTPUserIdentifier       AttributeType = C.CKA_OTP_USER_IDENTIFIER
	AttributeOTPServiceIdentifier    AttributeType = C.CKA_OTP_SERVICE_IDENTIFIER
	AttributeOTPServiceLogo          AttributeType = C.CKA_OTP_SERVICE_LOGO
	AttributeOTPServiceLogoType      AttributeType = C.CKA_OTP_SERVICE_LOGO_TYPE
	AttributeGOSTR3410Params         AttributeType = C.CKA_GOSTR3410_PARAMS
	AttributeGOSTR3411Params         AttributeType = C.CKA_GOSTR3411_PARAMS
	AttributeGOST28147Params         AttributeType = C.CKA_GOST28147_PARAMS
	AttributeHWFeatureType           AttributeType = C.CKA_HW_FEATURE_TYPE
	AttributeResetOnInit             AttributeType = C.CKA_RESET_ON_INIT
	AttributeHasReset                AttributeType = C.CKA_HAS_RESET
	AttributePixelX                  AttributeType = C.CKA_PIXEL_X
	AttributePixelY                  AttributeType = C.CKA_PIXEL_Y
	AttributeResolution              AttributeType = C.CKA_RESOLUTION
	AttributeCharRows                AttributeType = C.CKA_CHAR_ROWS
	AttributeCharColumns             AttributeType = C.CKA_CHAR_COLUMNS
	AttributeColor                   AttributeType = C.CKA_COLOR
	AttributeBitsPerPixel            AttributeType = C.CKA_BITS_PER_PIXEL
	AttributeCharSets                AttributeType = C.CKA_CHAR_SETS
	AttributeEncodingMethods         AttributeType = C.CKA_ENCODING_METHODS
	AttributeMimeTypes               AttributeType = C.CKA_MIME_TYPES
	AttributeMechanismType           AttributeType = C.CKA_MECHANISM_TYPE
	AttributeRequiredCMSAttributes   AttributeType = C.CKA_REQUIRED_CMS_ATTRIBUTES
	AttributeDefaultCMSAttributes    AttributeType = C.CKA_DEFAULT_CMS_ATTRIBUTES
	AttributeSupportedCMSAttributes  AttributeType = C.CKA_SUPPORTED_CMS_ATTRIBUTES
	AttributeAllowedMechanisms       AttributeType = C.CKA_ALLOWED_MECHANISMS
	AttributeProfileID               AttributeType = C.CKA_PROFILE_ID
	AttributeX2RatchetBag            AttributeType = C.CKA_X2RATCHET_BAG
	AttributeX2RatchetBagSize        AttributeType = C.CKA_X2RATCHET_BAGSIZE
	AttributeX2RatchetBobs1stMsg     AttributeType = C.CKA_X2RATCHET_BOBS1STMSG
	AttributeX2RatchetCKR            AttributeType = C.CKA_X2RATCHET_CKR
	AttributeX2RatchetCKS            AttributeType = C.CKA_X2RATCHET_CKS
	AttributeX2RatchetDHP            AttributeType = C.CKA_X2RATCHET_DHP
	AttributeX2RatchetDHR            AttributeType = C.CKA_X2RATCHET_DHR
	AttributeX2RatchetDHS            AttributeType = C.CKA_X2RATCHET_DHS
	AttributeX2RatchetHKR            AttributeType = C.CKA_X2RATCHET_HKR
	AttributeX2RatchetHKS            AttributeType = C.CKA_X2RATCHET_HKS
	AttributeX2RatchetIsAlice        AttributeType = C.CKA_X2RATCHET_ISALICE
	AttributeX2RatchetNHKR           AttributeType = C.CKA_X2RATCHET_NHKR
	AttributeX2RatchetNHKS           AttributeType = C.CKA_X2RATCHET_NHKS
	AttributeX2RatchetNR             AttributeType = C.CKA_X2RATCHET_NR
	AttributeX2RatchetNS             AttributeType = C.CKA_X2RATCHET_NS
	AttributeX2RatchetPNS            AttributeType = C.CKA_X2RATCHET_PNS
	AttributeX2RatchetRK             AttributeType = C.CKA_X2RATCHET_RK
	AttributeHSSLevels               AttributeType = C.CKA_HSS_LEVELS
	AttributeHSSLMSType              AttributeType = C.CKA_HSS_LMS_TYPE
	AttributeHSSLMOTSType            AttributeType = C.CKA_HSS_LMOTS_TYPE
	AttributeHSSLMSTypes             AttributeType = C.CKA_HSS_LMS_TYPES
	AttributeHSSLMOTSTypes           AttributeType = C.CKA_HSS_LMOTS_TYPES
	AttributeHSSKeysRemaining        AttributeType = C.CKA_HSS_KEYS_REMAINING
	AttributeVendorDefined           AttributeType = C.CKA_VENDOR_DEFINED
)

var attrStr = map[AttributeType]string{
	AttributeClass:                   "CKA_CLASS",
	AttributeToken:                   "CKA_TOKEN",
	AttributePrivate:                 "CKA_PRIVATE",
	AttributeLabel:                   "CKA_LABEL",
	AttributeUniqueID:                "CKA_UNIQUE_ID",
	AttributeApplication:             "CKA_APPLICATION",
	AttributeValue:                   "CKA_VALUE",
	AttributeObjectID:                "CKA_OBJECT_ID",
	AttributeCertificateType:         "CKA_CERTIFICATE_TYPE",
	AttributeIssuer:                  "CKA_ISSUER",
	AttributeSerialNumber:            "CKA_SERIAL_NUMBER",
	AttributeACIssuer:                "CKA_AC_ISSUER",
	AttributeOwner:                   "CKA_OWNER",
	AttributeAttrTypes:               "CKA_ATTR_TYPES",
	AttributeTrusted:                 "CKA_TRUSTED",
	AttributeCertificateCategory:     "CKA_CERTIFICATE_CATEGORY",
	AttributeJavaMIDPSecurityDomain:  "CKA_JAVA_MIDP_SECURITY_DOMAIN",
	AttributeURL:                     "CKA_URL",
	AttributeHashOfSubjectPublicKey:  "CKA_HASH_OF_SUBJECT_PUBLIC_KEY",
	AttributeHashOfIssuerPublicKey:   "CKA_HASH_OF_ISSUER_PUBLIC_KEY",
	AttributeNameHashAlgorithm:       "CKA_NAME_HASH_ALGORITHM",
	AttributeCheckValue:              "CKA_CHECK_VALUE",
	AttributeKeyType:                 "CKA_KEY_TYPE",
	AttributeSubject:                 "CKA_SUBJECT",
	AttributeID:                      "CKA_ID",
	AttributeSensitive:               "CKA_SENSITIVE",
	AttributeEncrypt:                 "CKA_ENCRYPT",
	AttributeDecrypt:                 "CKA_DECRYPT",
	AttributeWrap:                    "CKA_WRAP",
	AttributeUnwrap:                  "CKA_UNWRAP",
	AttributeSign:                    "CKA_SIGN",
	AttributeSignRecover:             "CKA_SIGN_RECOVER",
	AttributeVerify:                  "CKA_VERIFY",
	AttributeVerifyRecover:           "CKA_VERIFY_RECOVER",
	AttributeDerive:                  "CKA_DERIVE",
	AttributeStartDate:               "CKA_START_DATE",
	AttributeEndDate:                 "CKA_END_DATE",
	AttributeModulus:                 "CKA_MODULUS",
	AttributeModulusBits:             "CKA_MODULUS_BITS",
	AttributePublicExponent:          "CKA_PUBLIC_EXPONENT",
	AttributePrivateExponent:         "CKA_PRIVATE_EXPONENT",
	AttributePrime_1:                 "CKA_PRIME_1",
	AttributePrime_2:                 "CKA_PRIME_2",
	AttributeExponent_1:              "CKA_EXPONENT_1",
	AttributeExponent_2:              "CKA_EXPONENT_2",
	AttributeCoefficient:             "CKA_COEFFICIENT",
	AttributePublicKeyInfo:           "CKA_PUBLIC_KEY_INFO",
	AttributePrime:                   "CKA_PRIME",
	AttributeSubprime:                "CKA_SUBPRIME",
	AttributeBase:                    "CKA_BASE",
	AttributePrimeBits:               "CKA_PRIME_BITS",
	AttributeSubPrimeBits:            "CKA_SUB_PRIME_BITS",
	AttributeValueBits:               "CKA_VALUE_BITS",
	AttributeValueLen:                "CKA_VALUE_LEN",
	AttributeExtractable:             "CKA_EXTRACTABLE",
	AttributeLocal:                   "CKA_LOCAL",
	AttributeNeverExtractable:        "CKA_NEVER_EXTRACTABLE",
	AttributeAlwaysSensitive:         "CKA_ALWAYS_SENSITIVE",
	AttributeKeyGenMechanism:         "CKA_KEY_GEN_MECHANISM",
	AttributeModifiable:              "CKA_MODIFIABLE",
	AttributeCopyable:                "CKA_COPYABLE",
	AttributeDestroyable:             "CKA_DESTROYABLE",
	AttributeECParams:                "CKA_EC_PARAMS",
	AttributeECPoint:                 "CKA_EC_POINT",
	AttributeAlwaysAuthenticate:      "CKA_ALWAYS_AUTHENTICATE",
	AttributeWrapWithTrusted:         "CKA_WRAP_WITH_TRUSTED",
	AttributeWrapTemplate:            "CKA_WRAP_TEMPLATE",
	AttributeUnwrapTemplate:          "CKA_UNWRAP_TEMPLATE",
	AttributeDeriveTemplate:          "CKA_DERIVE_TEMPLATE",
	AttributeOTPFormat:               "CKA_OTP_FORMAT",
	AttributeOTPLength:               "CKA_OTP_LENGTH",
	AttributeOTPTimeInterval:         "CKA_OTP_TIME_INTERVAL",
	AttributeOTPUserFriendlyMode:     "CKA_OTP_USER_FRIENDLY_MODE",
	AttributeOTPChallengeRequirement: "CKA_OTP_CHALLENGE_REQUIREMENT",
	AttributeOTPTimeRequirement:      "CKA_OTP_TIME_REQUIREMENT",
	AttributeOTPCounterRequirement:   "CKA_OTP_COUNTER_REQUIREMENT",
	AttributeOTPPinRequirement:       "CKA_OTP_PIN_REQUIREMENT",
	AttributeOTPCounter:              "CKA_OTP_COUNTER",
	AttributeOTPTime:                 "CKA_OTP_TIME",
	AttributeOTPUserIdentifier:       "CKA_OTP_USER_IDENTIFIER",
	AttributeOTPServiceIdentifier:    "CKA_OTP_SERVICE_IDENTIFIER",
	AttributeOTPServiceLogo:          "CKA_OTP_SERVICE_LOGO",
	AttributeOTPServiceLogoType:      "CKA_OTP_SERVICE_LOGO_TYPE",
	AttributeGOSTR3410Params:         "CKA_GOSTR3410_PARAMS",
	AttributeGOSTR3411Params:         "CKA_GOSTR3411_PARAMS",
	AttributeGOST28147Params:         "CKA_GOST28147_PARAMS",
	AttributeHWFeatureType:           "CKA_HW_FEATURE_TYPE",
	AttributeResetOnInit:             "CKA_RESET_ON_INIT",
	AttributeHasReset:                "CKA_HAS_RESET",
	AttributePixelX:                  "CKA_PIXEL_X",
	AttributePixelY:                  "CKA_PIXEL_Y",
	AttributeResolution:              "CKA_RESOLUTION",
	AttributeCharRows:                "CKA_CHAR_ROWS",
	AttributeCharColumns:             "CKA_CHAR_COLUMNS",
	AttributeColor:                   "CKA_COLOR",
	AttributeBitsPerPixel:            "CKA_BITS_PER_PIXEL",
	AttributeCharSets:                "CKA_CHAR_SETS",
	AttributeEncodingMethods:         "CKA_ENCODING_METHODS",
	AttributeMimeTypes:               "CKA_MIME_TYPES",
	AttributeMechanismType:           "CKA_MECHANISM_TYPE",
	AttributeRequiredCMSAttributes:   "CKA_REQUIRED_CMS_ATTRIBUTES",
	AttributeDefaultCMSAttributes:    "CKA_DEFAULT_CMS_ATTRIBUTES",
	AttributeSupportedCMSAttributes:  "CKA_SUPPORTED_CMS_ATTRIBUTES",
	AttributeAllowedMechanisms:       "CKA_ALLOWED_MECHANISMS",
	AttributeProfileID:               "CKA_PROFILE_ID",
	AttributeX2RatchetBag:            "CKA_X2RATCHET_BAG",
	AttributeX2RatchetBagSize:        "CKA_X2RATCHET_BAGSIZE",
	AttributeX2RatchetBobs1stMsg:     "CKA_X2RATCHET_BOBS1STMSG",
	AttributeX2RatchetCKR:            "CKA_X2RATCHET_CKR",
	AttributeX2RatchetCKS:            "CKA_X2RATCHET_CKS",
	AttributeX2RatchetDHP:            "CKA_X2RATCHET_DHP",
	AttributeX2RatchetDHR:            "CKA_X2RATCHET_DHR",
	AttributeX2RatchetDHS:            "CKA_X2RATCHET_DHS",
	AttributeX2RatchetHKR:            "CKA_X2RATCHET_HKR",
	AttributeX2RatchetHKS:            "CKA_X2RATCHET_HKS",
	AttributeX2RatchetIsAlice:        "CKA_X2RATCHET_ISALICE",
	AttributeX2RatchetNHKR:           "CKA_X2RATCHET_NHKR",
	AttributeX2RatchetNHKS:           "CKA_X2RATCHET_NHKS",
	AttributeX2RatchetNR:             "CKA_X2RATCHET_NR",
	AttributeX2RatchetNS:             "CKA_X2RATCHET_NS",
	AttributeX2RatchetPNS:            "CKA_X2RATCHET_PNS",
	AttributeX2RatchetRK:             "CKA_X2RATCHET_RK",
	AttributeHSSLevels:               "CKA_HSS_LEVELS",
	AttributeHSSLMSType:              "CKA_HSS_LMS_TYPE",
	AttributeHSSLMOTSType:            "CKA_HSS_LMOTS_TYPE",
	AttributeHSSLMSTypes:             "CKA_HSS_LMS_TYPES",
	AttributeHSSLMOTSTypes:           "CKA_HSS_LMOTS_TYPES",
	AttributeHSSKeysRemaining:        "CKA_HSS_KEYS_REMAINING",
	AttributeVendorDefined:           "CKA_VENDOR_DEFINED",
}

func (a AttributeType) String() string {
	if s, ok := attrStr[a]; ok {
		return s
	}
	return fmt.Sprintf("Attribute(0x%08x)", uint(a))
}

type Value interface {
	String() string
	IsNil() bool
	Type() AttributeType

	allocate(size int)
	len() int
	ptr() unsafe.Pointer
}

const (
	attrString = iota
	attrUint
	attrBool
	attrBigInt
	attrDate
)

var attrDataType = map[AttributeType]int{
	AttributeClass:                   attrUint,
	AttributeToken:                   attrBool,
	AttributePrivate:                 attrBool,
	AttributeLabel:                   attrString,
	AttributeUniqueID:                attrString,
	AttributeApplication:             attrString,
	AttributeCertificateType:         attrUint,
	AttributeTrusted:                 attrBool,
	AttributeCertificateCategory:     attrUint,
	AttributeJavaMIDPSecurityDomain:  attrUint,
	AttributeURL:                     attrString,
	AttributeNameHashAlgorithm:       attrUint,
	AttributeKeyType:                 attrUint,
	AttributeSensitive:               attrBool,
	AttributeEncrypt:                 attrBool,
	AttributeDecrypt:                 attrBool,
	AttributeWrap:                    attrBool,
	AttributeUnwrap:                  attrBool,
	AttributeSign:                    attrBool,
	AttributeSignRecover:             attrBool,
	AttributeVerify:                  attrBool,
	AttributeVerifyRecover:           attrBool,
	AttributeDerive:                  attrBool,
	AttributeStartDate:               attrDate,
	AttributeEndDate:                 attrDate,
	AttributeModulus:                 attrBigInt,
	AttributeModulusBits:             attrUint,
	AttributePublicExponent:          attrBigInt,
	AttributePrivateExponent:         attrBigInt,
	AttributePrime_1:                 attrBigInt,
	AttributePrime_2:                 attrBigInt,
	AttributeExponent_1:              attrBigInt,
	AttributeExponent_2:              attrBigInt,
	AttributeCoefficient:             attrBigInt,
	AttributePrime:                   attrBigInt,
	AttributeSubprime:                attrBigInt,
	AttributeBase:                    attrBigInt,
	AttributePrimeBits:               attrUint,
	AttributeSubPrimeBits:            attrUint,
	AttributeValueBits:               attrUint,
	AttributeValueLen:                attrUint,
	AttributeExtractable:             attrBool,
	AttributeLocal:                   attrBool,
	AttributeNeverExtractable:        attrBool,
	AttributeAlwaysSensitive:         attrBool,
	AttributeModifiable:              attrBool,
	AttributeCopyable:                attrBool,
	AttributeDestroyable:             attrBool,
	AttributeAlwaysAuthenticate:      attrBool,
	AttributeWrapWithTrusted:         attrBool,
	AttributeWrapTemplate:            attrUint,
	AttributeUnwrapTemplate:          attrUint,
	AttributeDeriveTemplate:          attrUint,
	AttributeOTPFormat:               attrUint,
	AttributeOTPLength:               attrUint,
	AttributeOTPTimeInterval:         attrUint,
	AttributeOTPUserFriendlyMode:     attrBool,
	AttributeOTPChallengeRequirement: attrUint,
	AttributeOTPTimeRequirement:      attrUint,
	AttributeOTPCounterRequirement:   attrUint,
	AttributeOTPPinRequirement:       attrUint,
	AttributeOTPTime:                 attrString,
	AttributeOTPUserIdentifier:       attrString,
	AttributeOTPServiceIdentifier:    attrString,
	AttributeOTPServiceLogoType:      attrString,
	AttributeHWFeatureType:           attrUint,
	AttributeResetOnInit:             attrBool,
	AttributeHasReset:                attrBool,
	AttributePixelX:                  attrUint,
	AttributePixelY:                  attrUint,
	AttributeResolution:              attrUint,
	AttributeCharRows:                attrUint,
	AttributeCharColumns:             attrUint,
	AttributeColor:                   attrBool,
	AttributeBitsPerPixel:            attrUint,
	AttributeCharSets:                attrString,
	AttributeEncodingMethods:         attrString,
	AttributeMimeTypes:               attrString,
	AttributeMechanismType:           attrUint,
	AttributeProfileID:               attrUint,
	AttributeX2RatchetBagSize:        attrUint,
	AttributeX2RatchetBobs1stMsg:     attrBool,
	AttributeX2RatchetIsAlice:        attrBool,
	AttributeHSSLevels:               attrUint,
	AttributeHSSLMSType:              attrUint,
	AttributeHSSLMOTSType:            attrUint,
	AttributeHSSKeysRemaining:        attrUint,
}

func NewValue(t AttributeType) Value {
	switch t {
	case AttributeClass:
		return NewScalar[Class](t)
	case AttributeKeyType:
		return NewScalar[KeyType](t)
	case AttributeCertificateType:
		return NewScalar[CertificateType](t)
	case AttributeMechanismType, AttributeNameHashAlgorithm, AttributeKeyGenMechanism:
		return NewScalar[MechanismType](t)
	case AttributeAllowedMechanisms:
		return NewArray[[]MechanismType](t, nil)
	case AttributeWrapTemplate, AttributeUnwrapTemplate, AttributeDeriveTemplate:
		return NewArray[[]Attribute](t, nil)
	default:
		if dt, ok := attrDataType[t]; ok {
			switch dt {
			case attrUint:
				return NewScalar[Uint](t)
			case attrBool:
				return NewScalar[Bool](t)
			case attrDate:
				return NewScalar[Date](t)
			case attrBigInt:
				return NewArray[BigInt](t, nil)
			case attrString:
				return NewArray[String](t, nil)
			}
		}
		return NewArray[Bytes](t, nil)
	}
}

type Scalar[T any] struct {
	Value T

	typ   AttributeType
	valid bool
}

func NewScalarV[T any](typ AttributeType, val T) *Scalar[T] {
	return &Scalar[T]{val, typ, true}
}

func NewScalar[T any](typ AttributeType) *Scalar[T] {
	return &Scalar[T]{typ: typ}
}

func (t *Scalar[T]) String() string {
	if !t.valid {
		return "<undefined>"
	}
	return fmt.Sprintf("%v", &t.Value)
}

func (t *Scalar[T]) IsNil() bool         { return !t.valid }
func (t *Scalar[T]) Type() AttributeType { return t.typ }
func (t *Scalar[T]) allocate(size int)   { t.valid = true }
func (t *Scalar[T]) len() int            { return int(unsafe.Sizeof(t.Value)) }
func (t *Scalar[T]) ptr() unsafe.Pointer { return unsafe.Pointer(&t.Value) }

var _ Value = (*Scalar[C.ulong])(nil)

type Array[T ~[]E, E any] struct {
	Value T
	typ   AttributeType
}

func NewArray[T ~[]E, E any](typ AttributeType, val T) *Array[T, E] {
	return &Array[T, E]{val, typ}
}

func (t *Array[T, E]) String() string {
	if t.Value == nil {
		return "<undefined>"
	}
	return fmt.Sprintf("%v", t.Value)
}
func (t *Array[T, E]) IsNil() bool         { return t.Value == nil }
func (t *Array[T, E]) Type() AttributeType { return t.typ }
func (t *Array[T, E]) allocate(size int) {
	t.Value = make(T, size/int(unsafe.Sizeof(t.Value[0])))
}
func (t *Array[T, E]) len() int {
	return len(t.Value) * int(unsafe.Sizeof(t.Value[0]))
}
func (t *Array[T, E]) ptr() unsafe.Pointer {
	if len(t.Value) != 0 {
		return unsafe.Pointer(&t.Value[0])
	}
	return nil
}

var _ Value = (*Array[[]C.ulong, C.ulong])(nil)

type BytesAttribute[T ~[]byte] struct {
	Value T
	typ   AttributeType
}

// Class is the primary object type. Such as a certificate, public key, or private key.
type Class C.CK_OBJECT_CLASS

// Set of classes supported by this package.
const (
	ClassData             Class = C.CKO_DATA
	ClassCertificate      Class = C.CKO_CERTIFICATE
	ClassPublicKey        Class = C.CKO_PUBLIC_KEY
	ClassPrivateKey       Class = C.CKO_PRIVATE_KEY
	ClassSecretKey        Class = C.CKO_SECRET_KEY
	ClassHWFeature        Class = C.CKO_HW_FEATURE
	ClassDomainParameters Class = C.CKO_DOMAIN_PARAMETERS
	ClassMechanism        Class = C.CKO_MECHANISM
	ClassOTPKey           Class = C.CKO_OTP_KEY
	ClassProfile          Class = C.CKO_PROFILE
	ClassVendorDefined    Class = C.CKO_VENDOR_DEFINED
)

var classString = map[Class]string{
	ClassData:             "CKO_DATA",
	ClassCertificate:      "CKO_CERTIFICATE",
	ClassPublicKey:        "CKO_PUBLIC_KEY",
	ClassPrivateKey:       "CKO_PRIVATE_KEY",
	ClassSecretKey:        "CKO_SECRET_KEY",
	ClassHWFeature:        "CKO_HW_FEATURE",
	ClassDomainParameters: "CKO_DOMAIN_PARAMETERS",
	ClassMechanism:        "CKO_MECHANISM",
	ClassOTPKey:           "CKO_OTP_KEY",
	ClassProfile:          "CKO_PROFILE",
	ClassVendorDefined:    "CKO_VENDOR_DEFINED",
}

// String returns a human readable version of the object class.
func (c Class) String() string {
	if s, ok := classString[c]; ok {
		return s
	}
	return fmt.Sprintf("Class(0x%08x)", uint(c))
}

type KeyType C.CK_KEY_TYPE

const (
	KeyRSA            KeyType = C.CKK_RSA
	KeyDSA            KeyType = C.CKK_DSA
	KeyDH             KeyType = C.CKK_DH
	KeyEC             KeyType = C.CKK_EC
	KeyX9_42DH        KeyType = C.CKK_X9_42_DH
	KeyKEA            KeyType = C.CKK_KEA
	KeyGenericSecret  KeyType = C.CKK_GENERIC_SECRET
	KeyRC2            KeyType = C.CKK_RC2
	KeyRC4            KeyType = C.CKK_RC4
	KeyDES            KeyType = C.CKK_DES
	KeyDES2           KeyType = C.CKK_DES2
	KeyDES3           KeyType = C.CKK_DES3
	KeyCAST           KeyType = C.CKK_CAST
	KeyCAST3          KeyType = C.CKK_CAST3
	KeyCAST128        KeyType = C.CKK_CAST128
	KeyRC5            KeyType = C.CKK_RC5
	KeyIDEA           KeyType = C.CKK_IDEA
	KeySkipjack       KeyType = C.CKK_SKIPJACK
	KeyBATON          KeyType = C.CKK_BATON
	KeyJuniper        KeyType = C.CKK_JUNIPER
	KeyCDMF           KeyType = C.CKK_CDMF
	KeyAES            KeyType = C.CKK_AES
	KeyBlowfish       KeyType = C.CKK_BLOWFISH
	KeyTwofish        KeyType = C.CKK_TWOFISH
	KeySecurID        KeyType = C.CKK_SECURID
	KeyHOTP           KeyType = C.CKK_HOTP
	KeyACTI           KeyType = C.CKK_ACTI
	KeyCamellia       KeyType = C.CKK_CAMELLIA
	KeyARIA           KeyType = C.CKK_ARIA
	KeyMD5HMAC        KeyType = C.CKK_MD5_HMAC
	KeySHA1HMAC       KeyType = C.CKK_SHA_1_HMAC
	KeyRIPEMD128HMAC  KeyType = C.CKK_RIPEMD128_HMAC
	KeyRIPEMD160HMAC  KeyType = C.CKK_RIPEMD160_HMAC
	KeySHA256HMAC     KeyType = C.CKK_SHA256_HMAC
	KeySHA384HMAC     KeyType = C.CKK_SHA384_HMAC
	KeySHA512HMAC     KeyType = C.CKK_SHA512_HMAC
	KeySHA224HMAC     KeyType = C.CKK_SHA224_HMAC
	KeySeed           KeyType = C.CKK_SEED
	KeyGOSTR3410      KeyType = C.CKK_GOSTR3410
	KeyGOSTR3411      KeyType = C.CKK_GOSTR3411
	KeyGOST28147      KeyType = C.CKK_GOST28147
	KeyChaCha20       KeyType = C.CKK_CHACHA20
	KeyPoly1305       KeyType = C.CKK_POLY1305
	KeyAESXTS         KeyType = C.CKK_AES_XTS
	KeySHA3_224HMAC   KeyType = C.CKK_SHA3_224_HMAC
	KeySHA3_256HMAC   KeyType = C.CKK_SHA3_256_HMAC
	KeySHA3_384HMAC   KeyType = C.CKK_SHA3_384_HMAC
	KeySHA3_512HMAC   KeyType = C.CKK_SHA3_512_HMAC
	KeyBLAKE2b160HMAC KeyType = C.CKK_BLAKE2B_160_HMAC
	KeyBLAKE2b256HMAC KeyType = C.CKK_BLAKE2B_256_HMAC
	KeyBLAKE2b384HMAC KeyType = C.CKK_BLAKE2B_384_HMAC
	KeyBLAKE2b512HMAC KeyType = C.CKK_BLAKE2B_512_HMAC
	KeySalsa20        KeyType = C.CKK_SALSA20
	KeyX2Ratchet      KeyType = C.CKK_X2RATCHET
	KeyECEdwards      KeyType = C.CKK_EC_EDWARDS
	KeyECMontgomery   KeyType = C.CKK_EC_MONTGOMERY
	KeyHKDF           KeyType = C.CKK_HKDF
	KeySHA512_224HMAC KeyType = C.CKK_SHA512_224_HMAC
	KeySHA512_256HMAC KeyType = C.CKK_SHA512_256_HMAC
	KeySHA512THMAC    KeyType = C.CKK_SHA512_T_HMAC
	KeyHSS            KeyType = C.CKK_HSS
	KeyVendorDefined  KeyType = C.CKK_VENDOR_DEFINED
)

var ktStr = map[KeyType]string{
	KeyRSA:            "CKK_RSA",
	KeyDSA:            "CKK_DSA",
	KeyDH:             "CKK_DH",
	KeyEC:             "CKK_EC",
	KeyX9_42DH:        "CKK_X9_42_DH",
	KeyKEA:            "CKK_KEA",
	KeyGenericSecret:  "CKK_GENERIC_SECRET",
	KeyRC2:            "CKK_RC2",
	KeyRC4:            "CKK_RC4",
	KeyDES:            "CKK_DES",
	KeyDES2:           "CKK_DES2",
	KeyDES3:           "CKK_DES3",
	KeyCAST:           "CKK_CAST",
	KeyCAST3:          "CKK_CAST3",
	KeyCAST128:        "CKK_CAST128",
	KeyRC5:            "CKK_RC5",
	KeyIDEA:           "CKK_IDEA",
	KeySkipjack:       "CKK_SKIPJACK",
	KeyBATON:          "CKK_BATON",
	KeyJuniper:        "CKK_JUNIPER",
	KeyCDMF:           "CKK_CDMF",
	KeyAES:            "CKK_AES",
	KeyBlowfish:       "CKK_BLOWFISH",
	KeyTwofish:        "CKK_TWOFISH",
	KeySecurID:        "CKK_SECURID",
	KeyHOTP:           "CKK_HOTP",
	KeyACTI:           "CKK_ACTI",
	KeyCamellia:       "CKK_CAMELLIA",
	KeyARIA:           "CKK_ARIA",
	KeyMD5HMAC:        "CKK_MD5_HMAC",
	KeySHA1HMAC:       "CKK_SHA_1_HMAC",
	KeyRIPEMD128HMAC:  "CKK_RIPEMD128_HMAC",
	KeyRIPEMD160HMAC:  "CKK_RIPEMD160_HMAC",
	KeySHA256HMAC:     "CKK_SHA256_HMAC",
	KeySHA384HMAC:     "CKK_SHA384_HMAC",
	KeySHA512HMAC:     "CKK_SHA512_HMAC",
	KeySHA224HMAC:     "CKK_SHA224_HMAC",
	KeySeed:           "CKK_SEED",
	KeyGOSTR3410:      "CKK_GOSTR3410",
	KeyGOSTR3411:      "CKK_GOSTR3411",
	KeyGOST28147:      "CKK_GOST28147",
	KeyChaCha20:       "CKK_CHACHA20",
	KeyPoly1305:       "CKK_POLY1305",
	KeyAESXTS:         "CKK_AES_XTS",
	KeySHA3_224HMAC:   "CKK_SHA3_224_HMAC",
	KeySHA3_256HMAC:   "CKK_SHA3_256_HMAC",
	KeySHA3_384HMAC:   "CKK_SHA3_384_HMAC",
	KeySHA3_512HMAC:   "CKK_SHA3_512_HMAC",
	KeyBLAKE2b160HMAC: "CKK_BLAKE2B_160_HMAC",
	KeyBLAKE2b256HMAC: "CKK_BLAKE2B_256_HMAC",
	KeyBLAKE2b384HMAC: "CKK_BLAKE2B_384_HMAC",
	KeyBLAKE2b512HMAC: "CKK_BLAKE2B_512_HMAC",
	KeySalsa20:        "CKK_SALSA20",
	KeyX2Ratchet:      "CKK_X2RATCHET",
	KeyECEdwards:      "CKK_EC_EDWARDS",
	KeyECMontgomery:   "CKK_EC_MONTGOMERY",
	KeyHKDF:           "CKK_HKDF",
	KeySHA512_224HMAC: "CKK_SHA512_224_HMAC",
	KeySHA512_256HMAC: "CKK_SHA512_256_HMAC",
	KeySHA512THMAC:    "CKK_SHA512_T_HMAC",
	KeyHSS:            "CKK_HSS",
	KeyVendorDefined:  "CKK_VENDOR_DEFINED",
}

func (k KeyType) String() string {
	if s, ok := ktStr[k]; ok {
		return s
	}
	return fmt.Sprintf("KeyType(0x%08x)", uint(k))
}

// CertificateType determines the kind of certificate a certificate object holds.
// This can be X.509, WTLS, GPG, etc.
//
// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#_Toc416959709
type CertificateType C.CK_CERTIFICATE_TYPE

// Certificate types supported by this package.
const (
	CertificateX509          CertificateType = C.CKC_X_509
	CertificateX509AttrCert  CertificateType = C.CKC_X_509_ATTR_CERT
	CertificateWTLS          CertificateType = C.CKC_WTLS
	CertificateVendorDefined CertificateType = C.CKC_VENDOR_DEFINED
)

func (t CertificateType) String() string {
	switch t {
	case CertificateX509:
		return "CKC_X_509"
	case CertificateX509AttrCert:
		return "CKC_X_509_ATTR_CERT"
	case CertificateWTLS:
		return "CKC_WTLS"
	case CertificateVendorDefined:
		return "CKC_VENDOR_DEFINED"
	default:
		return fmt.Sprintf("CertificateType(0x%08x)", uint(t))
	}
}

type Date C.CK_DATE

func NewDate(y, m, d int) Date {
	var out Date
	yr := fmt.Sprintf("%04d", y%10000)
	mn := fmt.Sprintf("%02d", m%100)
	dd := fmt.Sprintf("%02d", d%100)
	copy(out.year[:], []C.uchar(yr))
	copy(out.month[:], []C.uchar(mn))
	copy(out.day[:], []C.uchar(dd))
	return out
}

func (d *Date) Value() (year, month, day int, err error) {
	y, err := strconv.ParseInt(string(d.year[:]), 10, 32)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("pkcs11: %w", err)
	}
	m, err := strconv.ParseInt(string(d.month[:]), 10, 32)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("pkcs11: %w", err)
	}
	dd, err := strconv.ParseInt(string(d.day[:]), 10, 32)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("pkcs11: %w", err)
	}
	return int(y), int(m), int(dd), nil
}

func (d *Date) String() string {
	y, m, dd, err := d.Value()
	if err != nil {
		return "<undefined>"
	}
	return fmt.Sprintf("%04d.%02d.%02d", y, m, dd)
}

type MechanismType C.CK_MECHANISM_TYPE

const (
	MechanismRSAPKCSKeyPairGen            MechanismType = C.CKM_RSA_PKCS_KEY_PAIR_GEN
	MechanismRSAPKCS                      MechanismType = C.CKM_RSA_PKCS
	MechanismRSA9796                      MechanismType = C.CKM_RSA_9796
	MechanismRSAX509                      MechanismType = C.CKM_RSA_X_509
	MechanismMD2RSAPKCS                   MechanismType = C.CKM_MD2_RSA_PKCS
	MechanismMD5RSAPKCS                   MechanismType = C.CKM_MD5_RSA_PKCS
	MechanismSHA1RSAPKCS                  MechanismType = C.CKM_SHA1_RSA_PKCS
	MechanismRIPEMD128RSAPKCS             MechanismType = C.CKM_RIPEMD128_RSA_PKCS
	MechanismRIPEMD160RSAPKCS             MechanismType = C.CKM_RIPEMD160_RSA_PKCS
	MechanismRSAPKCSOAEP                  MechanismType = C.CKM_RSA_PKCS_OAEP
	MechanismRSAX9_31KeyPairGen           MechanismType = C.CKM_RSA_X9_31_KEY_PAIR_GEN
	MechanismRSAX9_31                     MechanismType = C.CKM_RSA_X9_31
	MechanismSHA1RSAX9_31                 MechanismType = C.CKM_SHA1_RSA_X9_31
	MechanismRSAPKCSPSS                   MechanismType = C.CKM_RSA_PKCS_PSS
	MechanismSHA1RSAPKCSPSS               MechanismType = C.CKM_SHA1_RSA_PKCS_PSS
	MechanismDSAKeyPairGen                MechanismType = C.CKM_DSA_KEY_PAIR_GEN
	MechanismDSA                          MechanismType = C.CKM_DSA
	MechanismDSASHA1                      MechanismType = C.CKM_DSA_SHA1
	MechanismDSASHA224                    MechanismType = C.CKM_DSA_SHA224
	MechanismDSASHA256                    MechanismType = C.CKM_DSA_SHA256
	MechanismDSASHA384                    MechanismType = C.CKM_DSA_SHA384
	MechanismDSASHA512                    MechanismType = C.CKM_DSA_SHA512
	MechanismDSASHA3_224                  MechanismType = C.CKM_DSA_SHA3_224
	MechanismDSASHA3_256                  MechanismType = C.CKM_DSA_SHA3_256
	MechanismDSASHA3_384                  MechanismType = C.CKM_DSA_SHA3_384
	MechanismDSASHA3_512                  MechanismType = C.CKM_DSA_SHA3_512
	MechanismDHPKCSKeyPairGen             MechanismType = C.CKM_DH_PKCS_KEY_PAIR_GEN
	MechanismDHPKCSDerive                 MechanismType = C.CKM_DH_PKCS_DERIVE
	MechanismX9_42DHKeyPairGen            MechanismType = C.CKM_X9_42_DH_KEY_PAIR_GEN
	MechanismX9_42DHDerive                MechanismType = C.CKM_X9_42_DH_DERIVE
	MechanismX9_42DHHybridDerive          MechanismType = C.CKM_X9_42_DH_HYBRID_DERIVE
	MechanismX9_42MQVDerive               MechanismType = C.CKM_X9_42_MQV_DERIVE
	MechanismSHA256RSAPKCS                MechanismType = C.CKM_SHA256_RSA_PKCS
	MechanismSHA384RSAPKCS                MechanismType = C.CKM_SHA384_RSA_PKCS
	MechanismSHA512RSAPKCS                MechanismType = C.CKM_SHA512_RSA_PKCS
	MechanismSHA256RSAPKCSPSS             MechanismType = C.CKM_SHA256_RSA_PKCS_PSS
	MechanismSHA384RSAPKCSPSS             MechanismType = C.CKM_SHA384_RSA_PKCS_PSS
	MechanismSHA512RSAPKCSPSS             MechanismType = C.CKM_SHA512_RSA_PKCS_PSS
	MechanismSHA224RSAPKCS                MechanismType = C.CKM_SHA224_RSA_PKCS
	MechanismSHA224RSAPKCSPSS             MechanismType = C.CKM_SHA224_RSA_PKCS_PSS
	MechanismSHA512224                    MechanismType = C.CKM_SHA512_224
	MechanismSHA512224HMAC                MechanismType = C.CKM_SHA512_224_HMAC
	MechanismSHA512224HMACGeneral         MechanismType = C.CKM_SHA512_224_HMAC_GENERAL
	MechanismSHA512224KeyDerivation       MechanismType = C.CKM_SHA512_224_KEY_DERIVATION
	MechanismSHA512256                    MechanismType = C.CKM_SHA512_256
	MechanismSHA512256HMAC                MechanismType = C.CKM_SHA512_256_HMAC
	MechanismSHA512256HMACGeneral         MechanismType = C.CKM_SHA512_256_HMAC_GENERAL
	MechanismSHA512256KeyDerivation       MechanismType = C.CKM_SHA512_256_KEY_DERIVATION
	MechanismSHA512T                      MechanismType = C.CKM_SHA512_T
	MechanismSHA512THMAC                  MechanismType = C.CKM_SHA512_T_HMAC
	MechanismSHA512THMACGeneral           MechanismType = C.CKM_SHA512_T_HMAC_GENERAL
	MechanismSHA512TKeyDerivation         MechanismType = C.CKM_SHA512_T_KEY_DERIVATION
	MechanismSHA3_256RSAPKCS              MechanismType = C.CKM_SHA3_256_RSA_PKCS
	MechanismSHA3_384RSAPKCS              MechanismType = C.CKM_SHA3_384_RSA_PKCS
	MechanismSHA3_512RSAPKCS              MechanismType = C.CKM_SHA3_512_RSA_PKCS
	MechanismSHA3_256RSAPKCSPSS           MechanismType = C.CKM_SHA3_256_RSA_PKCS_PSS
	MechanismSHA3_384RSAPKCSPSS           MechanismType = C.CKM_SHA3_384_RSA_PKCS_PSS
	MechanismSHA3_512RSAPKCSPSS           MechanismType = C.CKM_SHA3_512_RSA_PKCS_PSS
	MechanismSHA3_224RSAPKCS              MechanismType = C.CKM_SHA3_224_RSA_PKCS
	MechanismSHA3_224RSAPKCSPSS           MechanismType = C.CKM_SHA3_224_RSA_PKCS_PSS
	MechanismRC2KeyGen                    MechanismType = C.CKM_RC2_KEY_GEN
	MechanismRC2ECB                       MechanismType = C.CKM_RC2_ECB
	MechanismRC2CBC                       MechanismType = C.CKM_RC2_CBC
	MechanismRC2MAC                       MechanismType = C.CKM_RC2_MAC
	MechanismRC2MACGeneral                MechanismType = C.CKM_RC2_MAC_GENERAL
	MechanismRC2CBCPad                    MechanismType = C.CKM_RC2_CBC_PAD
	MechanismRC4KeyGen                    MechanismType = C.CKM_RC4_KEY_GEN
	MechanismRC4                          MechanismType = C.CKM_RC4
	MechanismDESKeyGen                    MechanismType = C.CKM_DES_KEY_GEN
	MechanismDESECB                       MechanismType = C.CKM_DES_ECB
	MechanismDESCBC                       MechanismType = C.CKM_DES_CBC
	MechanismDESMAC                       MechanismType = C.CKM_DES_MAC
	MechanismDESMACGeneral                MechanismType = C.CKM_DES_MAC_GENERAL
	MechanismDESCBCPad                    MechanismType = C.CKM_DES_CBC_PAD
	MechanismDES2KeyGen                   MechanismType = C.CKM_DES2_KEY_GEN
	MechanismDES3KeyGen                   MechanismType = C.CKM_DES3_KEY_GEN
	MechanismDES3ECB                      MechanismType = C.CKM_DES3_ECB
	MechanismDES3CBC                      MechanismType = C.CKM_DES3_CBC
	MechanismDES3MAC                      MechanismType = C.CKM_DES3_MAC
	MechanismDES3MACGeneral               MechanismType = C.CKM_DES3_MAC_GENERAL
	MechanismDES3CBCPad                   MechanismType = C.CKM_DES3_CBC_PAD
	MechanismDES3CMACGeneral              MechanismType = C.CKM_DES3_CMAC_GENERAL
	MechanismDES3CMAC                     MechanismType = C.CKM_DES3_CMAC
	MechanismCDMFKeyGen                   MechanismType = C.CKM_CDMF_KEY_GEN
	MechanismCDMFECB                      MechanismType = C.CKM_CDMF_ECB
	MechanismCDMFCBC                      MechanismType = C.CKM_CDMF_CBC
	MechanismCDMFMAC                      MechanismType = C.CKM_CDMF_MAC
	MechanismCDMFMACGeneral               MechanismType = C.CKM_CDMF_MAC_GENERAL
	MechanismCDMFCBCPad                   MechanismType = C.CKM_CDMF_CBC_PAD
	MechanismDESOFB64                     MechanismType = C.CKM_DES_OFB64
	MechanismDESOFB8                      MechanismType = C.CKM_DES_OFB8
	MechanismDESCFB64                     MechanismType = C.CKM_DES_CFB64
	MechanismDESCFB8                      MechanismType = C.CKM_DES_CFB8
	MechanismMD2                          MechanismType = C.CKM_MD2
	MechanismMD2HMAC                      MechanismType = C.CKM_MD2_HMAC
	MechanismMD2HMACGeneral               MechanismType = C.CKM_MD2_HMAC_GENERAL
	MechanismMD5                          MechanismType = C.CKM_MD5
	MechanismMD5HMAC                      MechanismType = C.CKM_MD5_HMAC
	MechanismMD5HMACGeneral               MechanismType = C.CKM_MD5_HMAC_GENERAL
	MechanismSHA1                         MechanismType = C.CKM_SHA_1
	MechanismSHA1HMAC                     MechanismType = C.CKM_SHA_1_HMAC
	MechanismSHA1HMACGeneral              MechanismType = C.CKM_SHA_1_HMAC_GENERAL
	MechanismRIPEMD128                    MechanismType = C.CKM_RIPEMD128
	MechanismRIPEMD128HMAC                MechanismType = C.CKM_RIPEMD128_HMAC
	MechanismRIPEMD128HMACGeneral         MechanismType = C.CKM_RIPEMD128_HMAC_GENERAL
	MechanismRIPEMD160                    MechanismType = C.CKM_RIPEMD160
	MechanismRIPEMD160HMAC                MechanismType = C.CKM_RIPEMD160_HMAC
	MechanismRIPEMD160HMACGeneral         MechanismType = C.CKM_RIPEMD160_HMAC_GENERAL
	MechanismSHA256                       MechanismType = C.CKM_SHA256
	MechanismSHA256HMAC                   MechanismType = C.CKM_SHA256_HMAC
	MechanismSHA256HMACGeneral            MechanismType = C.CKM_SHA256_HMAC_GENERAL
	MechanismSHA224                       MechanismType = C.CKM_SHA224
	MechanismSHA224HMAC                   MechanismType = C.CKM_SHA224_HMAC
	MechanismSHA224HMACGeneral            MechanismType = C.CKM_SHA224_HMAC_GENERAL
	MechanismSHA384                       MechanismType = C.CKM_SHA384
	MechanismSHA384HMAC                   MechanismType = C.CKM_SHA384_HMAC
	MechanismSHA384HMACGeneral            MechanismType = C.CKM_SHA384_HMAC_GENERAL
	MechanismSHA512                       MechanismType = C.CKM_SHA512
	MechanismSHA512HMAC                   MechanismType = C.CKM_SHA512_HMAC
	MechanismSHA512HMACGeneral            MechanismType = C.CKM_SHA512_HMAC_GENERAL
	MechanismSecurIDKeyGen                MechanismType = C.CKM_SECURID_KEY_GEN
	MechanismSecurID                      MechanismType = C.CKM_SECURID
	MechanismHOTPKeyGen                   MechanismType = C.CKM_HOTP_KEY_GEN
	MechanismHOTP                         MechanismType = C.CKM_HOTP
	MechanismACTI                         MechanismType = C.CKM_ACTI
	MechanismACTIKeyGen                   MechanismType = C.CKM_ACTI_KEY_GEN
	MechanismSHA3_256                     MechanismType = C.CKM_SHA3_256
	MechanismSHA3_256HMAC                 MechanismType = C.CKM_SHA3_256_HMAC
	MechanismSHA3_256HMACGeneral          MechanismType = C.CKM_SHA3_256_HMAC_GENERAL
	MechanismSHA3_256KeyGen               MechanismType = C.CKM_SHA3_256_KEY_GEN
	MechanismSHA3_224                     MechanismType = C.CKM_SHA3_224
	MechanismSHA3_224HMAC                 MechanismType = C.CKM_SHA3_224_HMAC
	MechanismSHA3_224HMACGeneral          MechanismType = C.CKM_SHA3_224_HMAC_GENERAL
	MechanismSHA3_224KeyGen               MechanismType = C.CKM_SHA3_224_KEY_GEN
	MechanismSHA3_384                     MechanismType = C.CKM_SHA3_384
	MechanismSHA3_384HMAC                 MechanismType = C.CKM_SHA3_384_HMAC
	MechanismSHA3_384HMACGeneral          MechanismType = C.CKM_SHA3_384_HMAC_GENERAL
	MechanismSHA3_384KeyGen               MechanismType = C.CKM_SHA3_384_KEY_GEN
	MechanismSHA3_512                     MechanismType = C.CKM_SHA3_512
	MechanismSHA3_512HMAC                 MechanismType = C.CKM_SHA3_512_HMAC
	MechanismSHA3_512HMACGeneral          MechanismType = C.CKM_SHA3_512_HMAC_GENERAL
	MechanismSHA3_512KeyGen               MechanismType = C.CKM_SHA3_512_KEY_GEN
	MechanismCASTKeyGen                   MechanismType = C.CKM_CAST_KEY_GEN
	MechanismCASTECB                      MechanismType = C.CKM_CAST_ECB
	MechanismCASTCBC                      MechanismType = C.CKM_CAST_CBC
	MechanismCASTMAC                      MechanismType = C.CKM_CAST_MAC
	MechanismCASTMACGeneral               MechanismType = C.CKM_CAST_MAC_GENERAL
	MechanismCASTCBCPad                   MechanismType = C.CKM_CAST_CBC_PAD
	MechanismCAST3KeyGen                  MechanismType = C.CKM_CAST3_KEY_GEN
	MechanismCAST3ECB                     MechanismType = C.CKM_CAST3_ECB
	MechanismCAST3CBC                     MechanismType = C.CKM_CAST3_CBC
	MechanismCAST3MAC                     MechanismType = C.CKM_CAST3_MAC
	MechanismCAST3MACGeneral              MechanismType = C.CKM_CAST3_MAC_GENERAL
	MechanismCAST3CBCPad                  MechanismType = C.CKM_CAST3_CBC_PAD
	MechanismCAST128KeyGen                MechanismType = C.CKM_CAST128_KEY_GEN
	MechanismCAST128ECB                   MechanismType = C.CKM_CAST128_ECB
	MechanismCAST128CBC                   MechanismType = C.CKM_CAST128_CBC
	MechanismCAST128MAC                   MechanismType = C.CKM_CAST128_MAC
	MechanismCAST128MACGeneral            MechanismType = C.CKM_CAST128_MAC_GENERAL
	MechanismCAST128CBCPad                MechanismType = C.CKM_CAST128_CBC_PAD
	MechanismRC5KeyGen                    MechanismType = C.CKM_RC5_KEY_GEN
	MechanismRC5ECB                       MechanismType = C.CKM_RC5_ECB
	MechanismRC5CBC                       MechanismType = C.CKM_RC5_CBC
	MechanismRC5MAC                       MechanismType = C.CKM_RC5_MAC
	MechanismRC5MACGeneral                MechanismType = C.CKM_RC5_MAC_GENERAL
	MechanismRC5CBCPad                    MechanismType = C.CKM_RC5_CBC_PAD
	MechanismIDEAKeyGen                   MechanismType = C.CKM_IDEA_KEY_GEN
	MechanismIDEAECB                      MechanismType = C.CKM_IDEA_ECB
	MechanismIDEACBC                      MechanismType = C.CKM_IDEA_CBC
	MechanismIDEAMAC                      MechanismType = C.CKM_IDEA_MAC
	MechanismIDEAMACGeneral               MechanismType = C.CKM_IDEA_MAC_GENERAL
	MechanismIDEACBCPad                   MechanismType = C.CKM_IDEA_CBC_PAD
	MechanismGenericSecretKeyGen          MechanismType = C.CKM_GENERIC_SECRET_KEY_GEN
	MechanismConcatenateBaseAndKey        MechanismType = C.CKM_CONCATENATE_BASE_AND_KEY
	MechanismConcatenateBaseAndData       MechanismType = C.CKM_CONCATENATE_BASE_AND_DATA
	MechanismConcatenateDataAndBase       MechanismType = C.CKM_CONCATENATE_DATA_AND_BASE
	MechanismXorBaseAndData               MechanismType = C.CKM_XOR_BASE_AND_DATA
	MechanismExtractKeyFromKey            MechanismType = C.CKM_EXTRACT_KEY_FROM_KEY
	MechanismSSL3PreMasterKeyGen          MechanismType = C.CKM_SSL3_PRE_MASTER_KEY_GEN
	MechanismSSL3MasterKeyDerive          MechanismType = C.CKM_SSL3_MASTER_KEY_DERIVE
	MechanismSSL3KeyAndMACDerive          MechanismType = C.CKM_SSL3_KEY_AND_MAC_DERIVE
	MechanismSSL3MasterKeyDeriveDH        MechanismType = C.CKM_SSL3_MASTER_KEY_DERIVE_DH
	MechanismTLSPreMasterKeyGen           MechanismType = C.CKM_TLS_PRE_MASTER_KEY_GEN
	MechanismTLSMasterKeyDerive           MechanismType = C.CKM_TLS_MASTER_KEY_DERIVE
	MechanismTLSKeyAndMACDerive           MechanismType = C.CKM_TLS_KEY_AND_MAC_DERIVE
	MechanismTLSMasterKeyDeriveDH         MechanismType = C.CKM_TLS_MASTER_KEY_DERIVE_DH
	MechanismTLSPRF                       MechanismType = C.CKM_TLS_PRF
	MechanismSSL3MD5MAC                   MechanismType = C.CKM_SSL3_MD5_MAC
	MechanismSSL3SHA1MAC                  MechanismType = C.CKM_SSL3_SHA1_MAC
	MechanismMD5KeyDerivation             MechanismType = C.CKM_MD5_KEY_DERIVATION
	MechanismMD2KeyDerivation             MechanismType = C.CKM_MD2_KEY_DERIVATION
	MechanismSHA1KeyDerivation            MechanismType = C.CKM_SHA1_KEY_DERIVATION
	MechanismSHA256KeyDerivation          MechanismType = C.CKM_SHA256_KEY_DERIVATION
	MechanismSHA384KeyDerivation          MechanismType = C.CKM_SHA384_KEY_DERIVATION
	MechanismSHA512KeyDerivation          MechanismType = C.CKM_SHA512_KEY_DERIVATION
	MechanismSHA224KeyDerivation          MechanismType = C.CKM_SHA224_KEY_DERIVATION
	MechanismSHA3_256KeyDerivation        MechanismType = C.CKM_SHA3_256_KEY_DERIVATION
	MechanismSHA3_224KeyDerivation        MechanismType = C.CKM_SHA3_224_KEY_DERIVATION
	MechanismSHA3_384KeyDerivation        MechanismType = C.CKM_SHA3_384_KEY_DERIVATION
	MechanismSHA3_512KeyDerivation        MechanismType = C.CKM_SHA3_512_KEY_DERIVATION
	MechanismSHAKE128KeyDerivation        MechanismType = C.CKM_SHAKE_128_KEY_DERIVATION
	MechanismSHAKE256KeyDerivation        MechanismType = C.CKM_SHAKE_256_KEY_DERIVATION
	MechanismPBEMD2DESCBC                 MechanismType = C.CKM_PBE_MD2_DES_CBC
	MechanismPBEMD5DESCBC                 MechanismType = C.CKM_PBE_MD5_DES_CBC
	MechanismPBEMD5CASTCBC                MechanismType = C.CKM_PBE_MD5_CAST_CBC
	MechanismPBEMD5CAST3CBC               MechanismType = C.CKM_PBE_MD5_CAST3_CBC
	MechanismPBEMD5CAST128CBC             MechanismType = C.CKM_PBE_MD5_CAST128_CBC
	MechanismPBESHA1CAST128CBC            MechanismType = C.CKM_PBE_SHA1_CAST128_CBC
	MechanismPBESHA1RC4_128               MechanismType = C.CKM_PBE_SHA1_RC4_128
	MechanismPBESHA1RC4_40                MechanismType = C.CKM_PBE_SHA1_RC4_40
	MechanismPBESHA1DES3EDECBC            MechanismType = C.CKM_PBE_SHA1_DES3_EDE_CBC
	MechanismPBESHA1DES2EDECBC            MechanismType = C.CKM_PBE_SHA1_DES2_EDE_CBC
	MechanismPBESHA1RC2_128CBC            MechanismType = C.CKM_PBE_SHA1_RC2_128_CBC
	MechanismPBESHA1RC2_40CBC             MechanismType = C.CKM_PBE_SHA1_RC2_40_CBC
	MechanismPKCS5PBKD2                   MechanismType = C.CKM_PKCS5_PBKD2
	MechanismPBASHA1WithSHA1HMAC          MechanismType = C.CKM_PBA_SHA1_WITH_SHA1_HMAC
	MechanismWTLSPreMasterKeyGen          MechanismType = C.CKM_WTLS_PRE_MASTER_KEY_GEN
	MechanismWTLSMasterKeyDerive          MechanismType = C.CKM_WTLS_MASTER_KEY_DERIVE
	MechanismWTLSMasterKeyDeriveDHECC     MechanismType = C.CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC
	MechanismWTLSPRF                      MechanismType = C.CKM_WTLS_PRF
	MechanismWTLSServerKeyAndMACDerive    MechanismType = C.CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE
	MechanismWTLSClientKeyAndMACDerive    MechanismType = C.CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE
	MechanismTLS10MACServer               MechanismType = C.CKM_TLS10_MAC_SERVER
	MechanismTLS10MACClient               MechanismType = C.CKM_TLS10_MAC_CLIENT
	MechanismTLS12MAC                     MechanismType = C.CKM_TLS12_MAC
	MechanismTLS12KDF                     MechanismType = C.CKM_TLS12_KDF
	MechanismTLS12MasterKeyDerive         MechanismType = C.CKM_TLS12_MASTER_KEY_DERIVE
	MechanismTLS12KeyAndMACDerive         MechanismType = C.CKM_TLS12_KEY_AND_MAC_DERIVE
	MechanismTLS12MasterKeyDeriveDH       MechanismType = C.CKM_TLS12_MASTER_KEY_DERIVE_DH
	MechanismTLS12KeySafeDerive           MechanismType = C.CKM_TLS12_KEY_SAFE_DERIVE
	MechanismTLSMAC                       MechanismType = C.CKM_TLS_MAC
	MechanismTLSKDF                       MechanismType = C.CKM_TLS_KDF
	MechanismKeyWrapLYNKS                 MechanismType = C.CKM_KEY_WRAP_LYNKS
	MechanismKeyWrapSetOAEP               MechanismType = C.CKM_KEY_WRAP_SET_OAEP
	MechanismCMSSIG                       MechanismType = C.CKM_CMS_SIG
	MechanismKIPDerive                    MechanismType = C.CKM_KIP_DERIVE
	MechanismKIPWrap                      MechanismType = C.CKM_KIP_WRAP
	MechanismKIPMAC                       MechanismType = C.CKM_KIP_MAC
	MechanismCamelliaKeyGen               MechanismType = C.CKM_CAMELLIA_KEY_GEN
	MechanismCamelliaECB                  MechanismType = C.CKM_CAMELLIA_ECB
	MechanismCamelliaCBC                  MechanismType = C.CKM_CAMELLIA_CBC
	MechanismCamelliaMAC                  MechanismType = C.CKM_CAMELLIA_MAC
	MechanismCamelliaMACGeneral           MechanismType = C.CKM_CAMELLIA_MAC_GENERAL
	MechanismCamelliaCBCPad               MechanismType = C.CKM_CAMELLIA_CBC_PAD
	MechanismCamelliaECBEncryptData       MechanismType = C.CKM_CAMELLIA_ECB_ENCRYPT_DATA
	MechanismCamelliaCBCEncryptData       MechanismType = C.CKM_CAMELLIA_CBC_ENCRYPT_DATA
	MechanismCamelliaCTR                  MechanismType = C.CKM_CAMELLIA_CTR
	MechanismARIAKeyGen                   MechanismType = C.CKM_ARIA_KEY_GEN
	MechanismARIAECB                      MechanismType = C.CKM_ARIA_ECB
	MechanismARIACBC                      MechanismType = C.CKM_ARIA_CBC
	MechanismARIAMAC                      MechanismType = C.CKM_ARIA_MAC
	MechanismARIAMACGeneral               MechanismType = C.CKM_ARIA_MAC_GENERAL
	MechanismARIACBCPad                   MechanismType = C.CKM_ARIA_CBC_PAD
	MechanismARIAECBEncryptData           MechanismType = C.CKM_ARIA_ECB_ENCRYPT_DATA
	MechanismARIACBCEncryptData           MechanismType = C.CKM_ARIA_CBC_ENCRYPT_DATA
	MechanismSeedKeyGen                   MechanismType = C.CKM_SEED_KEY_GEN
	MechanismSeedECB                      MechanismType = C.CKM_SEED_ECB
	MechanismSeedCBC                      MechanismType = C.CKM_SEED_CBC
	MechanismSeedMAC                      MechanismType = C.CKM_SEED_MAC
	MechanismSeedMACGeneral               MechanismType = C.CKM_SEED_MAC_GENERAL
	MechanismSeedCBCPad                   MechanismType = C.CKM_SEED_CBC_PAD
	MechanismSeedECBEncryptData           MechanismType = C.CKM_SEED_ECB_ENCRYPT_DATA
	MechanismSeedCBCEncryptData           MechanismType = C.CKM_SEED_CBC_ENCRYPT_DATA
	MechanismSkipjackKeyGen               MechanismType = C.CKM_SKIPJACK_KEY_GEN
	MechanismSkipjackECB64                MechanismType = C.CKM_SKIPJACK_ECB64
	MechanismSkipjackCBC64                MechanismType = C.CKM_SKIPJACK_CBC64
	MechanismSkipjackOFB64                MechanismType = C.CKM_SKIPJACK_OFB64
	MechanismSkipjackCFB64                MechanismType = C.CKM_SKIPJACK_CFB64
	MechanismSkipjackCFB32                MechanismType = C.CKM_SKIPJACK_CFB32
	MechanismSkipjackCFB16                MechanismType = C.CKM_SKIPJACK_CFB16
	MechanismSkipjackCFB8                 MechanismType = C.CKM_SKIPJACK_CFB8
	MechanismSkipjackWrap                 MechanismType = C.CKM_SKIPJACK_WRAP
	MechanismSkipjackPrivateWrap          MechanismType = C.CKM_SKIPJACK_PRIVATE_WRAP
	MechanismSkipjackRelayx               MechanismType = C.CKM_SKIPJACK_RELAYX
	MechanismKEAKeyPairGen                MechanismType = C.CKM_KEA_KEY_PAIR_GEN
	MechanismKEAKeyDerive                 MechanismType = C.CKM_KEA_KEY_DERIVE
	MechanismKEADerive                    MechanismType = C.CKM_KEA_DERIVE
	MechanismFortezzaTimestamp            MechanismType = C.CKM_FORTEZZA_TIMESTAMP
	MechanismBATONKeyGen                  MechanismType = C.CKM_BATON_KEY_GEN
	MechanismBATONECB128                  MechanismType = C.CKM_BATON_ECB128
	MechanismBATONECB96                   MechanismType = C.CKM_BATON_ECB96
	MechanismBATONCBC128                  MechanismType = C.CKM_BATON_CBC128
	MechanismBATONCounter                 MechanismType = C.CKM_BATON_COUNTER
	MechanismBATONShuffle                 MechanismType = C.CKM_BATON_SHUFFLE
	MechanismBATONWrap                    MechanismType = C.CKM_BATON_WRAP
	MechanismECKeyPairGen                 MechanismType = C.CKM_EC_KEY_PAIR_GEN
	MechanismECDSA                        MechanismType = C.CKM_ECDSA
	MechanismECDSASHA1                    MechanismType = C.CKM_ECDSA_SHA1
	MechanismECDSASHA224                  MechanismType = C.CKM_ECDSA_SHA224
	MechanismECDSASHA256                  MechanismType = C.CKM_ECDSA_SHA256
	MechanismECDSASHA384                  MechanismType = C.CKM_ECDSA_SHA384
	MechanismECDSASHA512                  MechanismType = C.CKM_ECDSA_SHA512
	MechanismECKeyPairGenWExtraBits       MechanismType = C.CKM_EC_KEY_PAIR_GEN_W_EXTRA_BITS
	MechanismECDH1Derive                  MechanismType = C.CKM_ECDH1_DERIVE
	MechanismECDH1CofactorDerive          MechanismType = C.CKM_ECDH1_COFACTOR_DERIVE
	MechanismECMQVDerive                  MechanismType = C.CKM_ECMQV_DERIVE
	MechanismECDHAESKeyWrap               MechanismType = C.CKM_ECDH_AES_KEY_WRAP
	MechanismRSAAESKeyWrap                MechanismType = C.CKM_RSA_AES_KEY_WRAP
	MechanismJuniperKeyGen                MechanismType = C.CKM_JUNIPER_KEY_GEN
	MechanismJuniperECB128                MechanismType = C.CKM_JUNIPER_ECB128
	MechanismJuniperCBC128                MechanismType = C.CKM_JUNIPER_CBC128
	MechanismJuniperCounter               MechanismType = C.CKM_JUNIPER_COUNTER
	MechanismJuniperShuffle               MechanismType = C.CKM_JUNIPER_SHUFFLE
	MechanismJuniperWrap                  MechanismType = C.CKM_JUNIPER_WRAP
	MechanismFasthash                     MechanismType = C.CKM_FASTHASH
	MechanismAESXTS                       MechanismType = C.CKM_AES_XTS
	MechanismAESXTSKeyGen                 MechanismType = C.CKM_AES_XTS_KEY_GEN
	MechanismAESKeyGen                    MechanismType = C.CKM_AES_KEY_GEN
	MechanismAESECB                       MechanismType = C.CKM_AES_ECB
	MechanismAESCBC                       MechanismType = C.CKM_AES_CBC
	MechanismAESMAC                       MechanismType = C.CKM_AES_MAC
	MechanismAESMACGeneral                MechanismType = C.CKM_AES_MAC_GENERAL
	MechanismAESCBCPad                    MechanismType = C.CKM_AES_CBC_PAD
	MechanismAESCTR                       MechanismType = C.CKM_AES_CTR
	MechanismAESGCM                       MechanismType = C.CKM_AES_GCM
	MechanismAESCCM                       MechanismType = C.CKM_AES_CCM
	MechanismAESCTS                       MechanismType = C.CKM_AES_CTS
	MechanismAESCMAC                      MechanismType = C.CKM_AES_CMAC
	MechanismAESCMACGeneral               MechanismType = C.CKM_AES_CMAC_GENERAL
	MechanismAESXCBCMAC                   MechanismType = C.CKM_AES_XCBC_MAC
	MechanismAESXCBCMAC96                 MechanismType = C.CKM_AES_XCBC_MAC_96
	MechanismAESGMAC                      MechanismType = C.CKM_AES_GMAC
	MechanismBlowfishKeyGen               MechanismType = C.CKM_BLOWFISH_KEY_GEN
	MechanismBlowfishCBC                  MechanismType = C.CKM_BLOWFISH_CBC
	MechanismTwofishKeyGen                MechanismType = C.CKM_TWOFISH_KEY_GEN
	MechanismTwofishCBC                   MechanismType = C.CKM_TWOFISH_CBC
	MechanismBlowfishCBCPad               MechanismType = C.CKM_BLOWFISH_CBC_PAD
	MechanismTwofishCBCPad                MechanismType = C.CKM_TWOFISH_CBC_PAD
	MechanismDESECBEncryptData            MechanismType = C.CKM_DES_ECB_ENCRYPT_DATA
	MechanismDESCBCEncryptData            MechanismType = C.CKM_DES_CBC_ENCRYPT_DATA
	MechanismDES3ECBEncryptData           MechanismType = C.CKM_DES3_ECB_ENCRYPT_DATA
	MechanismDES3CBCEncryptData           MechanismType = C.CKM_DES3_CBC_ENCRYPT_DATA
	MechanismAESECBEncryptData            MechanismType = C.CKM_AES_ECB_ENCRYPT_DATA
	MechanismAESCBCEncryptData            MechanismType = C.CKM_AES_CBC_ENCRYPT_DATA
	MechanismGOSTR3410KeyPairGen          MechanismType = C.CKM_GOSTR3410_KEY_PAIR_GEN
	MechanismGOSTR3410                    MechanismType = C.CKM_GOSTR3410
	MechanismGOSTR3410WithGOSTR3411       MechanismType = C.CKM_GOSTR3410_WITH_GOSTR3411
	MechanismGOSTR3410KeyWrap             MechanismType = C.CKM_GOSTR3410_KEY_WRAP
	MechanismGOSTR3410Derive              MechanismType = C.CKM_GOSTR3410_DERIVE
	MechanismGOSTR3411                    MechanismType = C.CKM_GOSTR3411
	MechanismGOSTR3411HMAC                MechanismType = C.CKM_GOSTR3411_HMAC
	MechanismGOST28147KeyGen              MechanismType = C.CKM_GOST28147_KEY_GEN
	MechanismGOST28147ECB                 MechanismType = C.CKM_GOST28147_ECB
	MechanismGOST28147                    MechanismType = C.CKM_GOST28147
	MechanismGOST28147MAC                 MechanismType = C.CKM_GOST28147_MAC
	MechanismGOST28147KeyWrap             MechanismType = C.CKM_GOST28147_KEY_WRAP
	MechanismChaCha20KeyGen               MechanismType = C.CKM_CHACHA20_KEY_GEN
	MechanismChaCha20                     MechanismType = C.CKM_CHACHA20
	MechanismPoly1305KeyGen               MechanismType = C.CKM_POLY1305_KEY_GEN
	MechanismPoly1305                     MechanismType = C.CKM_POLY1305
	MechanismDSAParameterGen              MechanismType = C.CKM_DSA_PARAMETER_GEN
	MechanismDHPKCSParameterGen           MechanismType = C.CKM_DH_PKCS_PARAMETER_GEN
	MechanismX9_42DHParameterGen          MechanismType = C.CKM_X9_42_DH_PARAMETER_GEN
	MechanismDSAProbabilisticParameterGen MechanismType = C.CKM_DSA_PROBABILISTIC_PARAMETER_GEN
	MechanismDSAShaweTaylorParameterGen   MechanismType = C.CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN
	MechanismDSAFIPSGGen                  MechanismType = C.CKM_DSA_FIPS_G_GEN
	MechanismAESOFB                       MechanismType = C.CKM_AES_OFB
	MechanismAESCFB64                     MechanismType = C.CKM_AES_CFB64
	MechanismAESCFB8                      MechanismType = C.CKM_AES_CFB8
	MechanismAESCFB128                    MechanismType = C.CKM_AES_CFB128
	MechanismAESCFB1                      MechanismType = C.CKM_AES_CFB1
	MechanismAESKeyWrap                   MechanismType = C.CKM_AES_KEY_WRAP
	MechanismAESKeyWrapPad                MechanismType = C.CKM_AES_KEY_WRAP_PAD
	MechanismAESKeyWrapKWP                MechanismType = C.CKM_AES_KEY_WRAP_KWP
	MechanismAESKeyWrapPKCS7              MechanismType = C.CKM_AES_KEY_WRAP_PKCS7
	MechanismRSAPKCSTPM1_1                MechanismType = C.CKM_RSA_PKCS_TPM_1_1
	MechanismRSAPKCSOAEPTPM1_1            MechanismType = C.CKM_RSA_PKCS_OAEP_TPM_1_1
	MechanismSHA1KeyGen                   MechanismType = C.CKM_SHA_1_KEY_GEN
	MechanismSHA224KeyGen                 MechanismType = C.CKM_SHA224_KEY_GEN
	MechanismSHA256KeyGen                 MechanismType = C.CKM_SHA256_KEY_GEN
	MechanismSHA384KeyGen                 MechanismType = C.CKM_SHA384_KEY_GEN
	MechanismSHA512KeyGen                 MechanismType = C.CKM_SHA512_KEY_GEN
	MechanismSHA512_224KeyGen             MechanismType = C.CKM_SHA512_224_KEY_GEN
	MechanismSHA512_256KeyGen             MechanismType = C.CKM_SHA512_256_KEY_GEN
	MechanismSHA512TKeyGen                MechanismType = C.CKM_SHA512_T_KEY_GEN
	MechanismNull                         MechanismType = C.CKM_NULL
	MechanismBLAKE2b160                   MechanismType = C.CKM_BLAKE2B_160
	MechanismBLAKE2b160HMAC               MechanismType = C.CKM_BLAKE2B_160_HMAC
	MechanismBLAKE2b160HMACGeneral        MechanismType = C.CKM_BLAKE2B_160_HMAC_GENERAL
	MechanismBLAKE2b160KeyDerive          MechanismType = C.CKM_BLAKE2B_160_KEY_DERIVE
	MechanismBLAKE2b160KeyGen             MechanismType = C.CKM_BLAKE2B_160_KEY_GEN
	MechanismBLAKE2b256                   MechanismType = C.CKM_BLAKE2B_256
	MechanismBLAKE2b256HMAC               MechanismType = C.CKM_BLAKE2B_256_HMAC
	MechanismBLAKE2b256HMACGeneral        MechanismType = C.CKM_BLAKE2B_256_HMAC_GENERAL
	MechanismBLAKE2b256KeyDerive          MechanismType = C.CKM_BLAKE2B_256_KEY_DERIVE
	MechanismBLAKE2b256KeyGen             MechanismType = C.CKM_BLAKE2B_256_KEY_GEN
	MechanismBLAKE2b384                   MechanismType = C.CKM_BLAKE2B_384
	MechanismBLAKE2b384HMAC               MechanismType = C.CKM_BLAKE2B_384_HMAC
	MechanismBLAKE2b384HMACGeneral        MechanismType = C.CKM_BLAKE2B_384_HMAC_GENERAL
	MechanismBLAKE2b384KeyDerive          MechanismType = C.CKM_BLAKE2B_384_KEY_DERIVE
	MechanismBLAKE2b384KeyGen             MechanismType = C.CKM_BLAKE2B_384_KEY_GEN
	MechanismBLAKE2b512                   MechanismType = C.CKM_BLAKE2B_512
	MechanismBLAKE2b512HMAC               MechanismType = C.CKM_BLAKE2B_512_HMAC
	MechanismBLAKE2b512HMACGeneral        MechanismType = C.CKM_BLAKE2B_512_HMAC_GENERAL
	MechanismBLAKE2b512KeyDerive          MechanismType = C.CKM_BLAKE2B_512_KEY_DERIVE
	MechanismBLAKE2b512KeyGen             MechanismType = C.CKM_BLAKE2B_512_KEY_GEN
	MechanismSalsa20                      MechanismType = C.CKM_SALSA20
	MechanismChacha20Poly1305             MechanismType = C.CKM_CHACHA20_POLY1305
	MechanismSalsa20Poly1305              MechanismType = C.CKM_SALSA20_POLY1305
	MechanismX3DHInitialize               MechanismType = C.CKM_X3DH_INITIALIZE
	MechanismX3DHRespond                  MechanismType = C.CKM_X3DH_RESPOND
	MechanismX2RatchetInitialize          MechanismType = C.CKM_X2RATCHET_INITIALIZE
	MechanismX2RatchetRespond             MechanismType = C.CKM_X2RATCHET_RESPOND
	MechanismX2RatchetEncrypt             MechanismType = C.CKM_X2RATCHET_ENCRYPT
	MechanismX2RatchetDecrypt             MechanismType = C.CKM_X2RATCHET_DECRYPT
	MechanismXEDDSA                       MechanismType = C.CKM_XEDDSA
	MechanismHKDFDerive                   MechanismType = C.CKM_HKDF_DERIVE
	MechanismHKDFData                     MechanismType = C.CKM_HKDF_DATA
	MechanismHKDFKeyGen                   MechanismType = C.CKM_HKDF_KEY_GEN
	MechanismSalsa20KeyGen                MechanismType = C.CKM_SALSA20_KEY_GEN
	MechanismECDSASHA3_224                MechanismType = C.CKM_ECDSA_SHA3_224
	MechanismECDSASHA3_256                MechanismType = C.CKM_ECDSA_SHA3_256
	MechanismECDSASHA3_384                MechanismType = C.CKM_ECDSA_SHA3_384
	MechanismECDSASHA3_512                MechanismType = C.CKM_ECDSA_SHA3_512
	MechanismECEdwardsKeyPairGen          MechanismType = C.CKM_EC_EDWARDS_KEY_PAIR_GEN
	MechanismECMontgomeryKeyPairGen       MechanismType = C.CKM_EC_MONTGOMERY_KEY_PAIR_GEN
	MechanismEDDSA                        MechanismType = C.CKM_EDDSA
	MechanismSP800_108CounterKDF          MechanismType = C.CKM_SP800_108_COUNTER_KDF
	MechanismSP800_108FeedbackKDF         MechanismType = C.CKM_SP800_108_FEEDBACK_KDF
	MechanismSP800_108DoublePipelineKDF   MechanismType = C.CKM_SP800_108_DOUBLE_PIPELINE_KDF
	MechanismIKE2PRFPlusDerive            MechanismType = C.CKM_IKE2_PRF_PLUS_DERIVE
	MechanismIKEPRFDerive                 MechanismType = C.CKM_IKE_PRF_DERIVE
	MechanismIKE1PRFDerive                MechanismType = C.CKM_IKE1_PRF_DERIVE
	MechanismIKE1ExtendedDerive           MechanismType = C.CKM_IKE1_EXTENDED_DERIVE
	MechanismHSSKeyPairGen                MechanismType = C.CKM_HSS_KEY_PAIR_GEN
	MechanismHSS                          MechanismType = C.CKM_HSS
	MechanismVendorDefined                MechanismType = C.CKM_VENDOR_DEFINED
)

var mechStr = map[MechanismType]string{
	MechanismRSAPKCSKeyPairGen:            "CKM_RSA_PKCS_KEY_PAIR_GEN",
	MechanismRSAPKCS:                      "CKM_RSA_PKCS",
	MechanismRSA9796:                      "CKM_RSA_9796",
	MechanismRSAX509:                      "CKM_RSA_X_509",
	MechanismMD2RSAPKCS:                   "CKM_MD2_RSA_PKCS",
	MechanismMD5RSAPKCS:                   "CKM_MD5_RSA_PKCS",
	MechanismSHA1RSAPKCS:                  "CKM_SHA1_RSA_PKCS",
	MechanismRIPEMD128RSAPKCS:             "CKM_RIPEMD128_RSA_PKCS",
	MechanismRIPEMD160RSAPKCS:             "CKM_RIPEMD160_RSA_PKCS",
	MechanismRSAPKCSOAEP:                  "CKM_RSA_PKCS_OAEP",
	MechanismRSAX9_31KeyPairGen:           "CKM_RSA_X9_31_KEY_PAIR_GEN",
	MechanismRSAX9_31:                     "CKM_RSA_X9_31",
	MechanismSHA1RSAX9_31:                 "CKM_SHA1_RSA_X9_31",
	MechanismRSAPKCSPSS:                   "CKM_RSA_PKCS_PSS",
	MechanismSHA1RSAPKCSPSS:               "CKM_SHA1_RSA_PKCS_PSS",
	MechanismDSAKeyPairGen:                "CKM_DSA_KEY_PAIR_GEN",
	MechanismDSA:                          "CKM_DSA",
	MechanismDSASHA1:                      "CKM_DSA_SHA1",
	MechanismDSASHA224:                    "CKM_DSA_SHA224",
	MechanismDSASHA256:                    "CKM_DSA_SHA256",
	MechanismDSASHA384:                    "CKM_DSA_SHA384",
	MechanismDSASHA512:                    "CKM_DSA_SHA512",
	MechanismDSASHA3_224:                  "CKM_DSA_SHA3_224",
	MechanismDSASHA3_256:                  "CKM_DSA_SHA3_256",
	MechanismDSASHA3_384:                  "CKM_DSA_SHA3_384",
	MechanismDSASHA3_512:                  "CKM_DSA_SHA3_512",
	MechanismDHPKCSKeyPairGen:             "CKM_DH_PKCS_KEY_PAIR_GEN",
	MechanismDHPKCSDerive:                 "CKM_DH_PKCS_DERIVE",
	MechanismX9_42DHKeyPairGen:            "CKM_X9_42_DH_KEY_PAIR_GEN",
	MechanismX9_42DHDerive:                "CKM_X9_42_DH_DERIVE",
	MechanismX9_42DHHybridDerive:          "CKM_X9_42_DH_HYBRID_DERIVE",
	MechanismX9_42MQVDerive:               "CKM_X9_42_MQV_DERIVE",
	MechanismSHA256RSAPKCS:                "CKM_SHA256_RSA_PKCS",
	MechanismSHA384RSAPKCS:                "CKM_SHA384_RSA_PKCS",
	MechanismSHA512RSAPKCS:                "CKM_SHA512_RSA_PKCS",
	MechanismSHA256RSAPKCSPSS:             "CKM_SHA256_RSA_PKCS_PSS",
	MechanismSHA384RSAPKCSPSS:             "CKM_SHA384_RSA_PKCS_PSS",
	MechanismSHA512RSAPKCSPSS:             "CKM_SHA512_RSA_PKCS_PSS",
	MechanismSHA224RSAPKCS:                "CKM_SHA224_RSA_PKCS",
	MechanismSHA224RSAPKCSPSS:             "CKM_SHA224_RSA_PKCS_PSS",
	MechanismSHA512224:                    "CKM_SHA512_224",
	MechanismSHA512224HMAC:                "CKM_SHA512_224_HMAC",
	MechanismSHA512224HMACGeneral:         "CKM_SHA512_224_HMAC_GENERAL",
	MechanismSHA512224KeyDerivation:       "CKM_SHA512_224_KEY_DERIVATION",
	MechanismSHA512256:                    "CKM_SHA512_256",
	MechanismSHA512256HMAC:                "CKM_SHA512_256_HMAC",
	MechanismSHA512256HMACGeneral:         "CKM_SHA512_256_HMAC_GENERAL",
	MechanismSHA512256KeyDerivation:       "CKM_SHA512_256_KEY_DERIVATION",
	MechanismSHA512T:                      "CKM_SHA512_T",
	MechanismSHA512THMAC:                  "CKM_SHA512_T_HMAC",
	MechanismSHA512THMACGeneral:           "CKM_SHA512_T_HMAC_GENERAL",
	MechanismSHA512TKeyDerivation:         "CKM_SHA512_T_KEY_DERIVATION",
	MechanismSHA3_256RSAPKCS:              "CKM_SHA3_256_RSA_PKCS",
	MechanismSHA3_384RSAPKCS:              "CKM_SHA3_384_RSA_PKCS",
	MechanismSHA3_512RSAPKCS:              "CKM_SHA3_512_RSA_PKCS",
	MechanismSHA3_256RSAPKCSPSS:           "CKM_SHA3_256_RSA_PKCS_PSS",
	MechanismSHA3_384RSAPKCSPSS:           "CKM_SHA3_384_RSA_PKCS_PSS",
	MechanismSHA3_512RSAPKCSPSS:           "CKM_SHA3_512_RSA_PKCS_PSS",
	MechanismSHA3_224RSAPKCS:              "CKM_SHA3_224_RSA_PKCS",
	MechanismSHA3_224RSAPKCSPSS:           "CKM_SHA3_224_RSA_PKCS_PSS",
	MechanismRC2KeyGen:                    "CKM_RC2_KEY_GEN",
	MechanismRC2ECB:                       "CKM_RC2_ECB",
	MechanismRC2CBC:                       "CKM_RC2_CBC",
	MechanismRC2MAC:                       "CKM_RC2_MAC",
	MechanismRC2MACGeneral:                "CKM_RC2_MAC_GENERAL",
	MechanismRC2CBCPad:                    "CKM_RC2_CBC_PAD",
	MechanismRC4KeyGen:                    "CKM_RC4_KEY_GEN",
	MechanismRC4:                          "CKM_RC4",
	MechanismDESKeyGen:                    "CKM_DES_KEY_GEN",
	MechanismDESECB:                       "CKM_DES_ECB",
	MechanismDESCBC:                       "CKM_DES_CBC",
	MechanismDESMAC:                       "CKM_DES_MAC",
	MechanismDESMACGeneral:                "CKM_DES_MAC_GENERAL",
	MechanismDESCBCPad:                    "CKM_DES_CBC_PAD",
	MechanismDES2KeyGen:                   "CKM_DES2_KEY_GEN",
	MechanismDES3KeyGen:                   "CKM_DES3_KEY_GEN",
	MechanismDES3ECB:                      "CKM_DES3_ECB",
	MechanismDES3CBC:                      "CKM_DES3_CBC",
	MechanismDES3MAC:                      "CKM_DES3_MAC",
	MechanismDES3MACGeneral:               "CKM_DES3_MAC_GENERAL",
	MechanismDES3CBCPad:                   "CKM_DES3_CBC_PAD",
	MechanismDES3CMACGeneral:              "CKM_DES3_CMAC_GENERAL",
	MechanismDES3CMAC:                     "CKM_DES3_CMAC",
	MechanismCDMFKeyGen:                   "CKM_CDMF_KEY_GEN",
	MechanismCDMFECB:                      "CKM_CDMF_ECB",
	MechanismCDMFCBC:                      "CKM_CDMF_CBC",
	MechanismCDMFMAC:                      "CKM_CDMF_MAC",
	MechanismCDMFMACGeneral:               "CKM_CDMF_MAC_GENERAL",
	MechanismCDMFCBCPad:                   "CKM_CDMF_CBC_PAD",
	MechanismDESOFB64:                     "CKM_DES_OFB64",
	MechanismDESOFB8:                      "CKM_DES_OFB8",
	MechanismDESCFB64:                     "CKM_DES_CFB64",
	MechanismDESCFB8:                      "CKM_DES_CFB8",
	MechanismMD2:                          "CKM_MD2",
	MechanismMD2HMAC:                      "CKM_MD2_HMAC",
	MechanismMD2HMACGeneral:               "CKM_MD2_HMAC_GENERAL",
	MechanismMD5:                          "CKM_MD5",
	MechanismMD5HMAC:                      "CKM_MD5_HMAC",
	MechanismMD5HMACGeneral:               "CKM_MD5_HMAC_GENERAL",
	MechanismSHA1:                         "CKM_SHA_1",
	MechanismSHA1HMAC:                     "CKM_SHA_1_HMAC",
	MechanismSHA1HMACGeneral:              "CKM_SHA_1_HMAC_GENERAL",
	MechanismRIPEMD128:                    "CKM_RIPEMD128",
	MechanismRIPEMD128HMAC:                "CKM_RIPEMD128_HMAC",
	MechanismRIPEMD128HMACGeneral:         "CKM_RIPEMD128_HMAC_GENERAL",
	MechanismRIPEMD160:                    "CKM_RIPEMD160",
	MechanismRIPEMD160HMAC:                "CKM_RIPEMD160_HMAC",
	MechanismRIPEMD160HMACGeneral:         "CKM_RIPEMD160_HMAC_GENERAL",
	MechanismSHA256:                       "CKM_SHA256",
	MechanismSHA256HMAC:                   "CKM_SHA256_HMAC",
	MechanismSHA256HMACGeneral:            "CKM_SHA256_HMAC_GENERAL",
	MechanismSHA224:                       "CKM_SHA224",
	MechanismSHA224HMAC:                   "CKM_SHA224_HMAC",
	MechanismSHA224HMACGeneral:            "CKM_SHA224_HMAC_GENERAL",
	MechanismSHA384:                       "CKM_SHA384",
	MechanismSHA384HMAC:                   "CKM_SHA384_HMAC",
	MechanismSHA384HMACGeneral:            "CKM_SHA384_HMAC_GENERAL",
	MechanismSHA512:                       "CKM_SHA512",
	MechanismSHA512HMAC:                   "CKM_SHA512_HMAC",
	MechanismSHA512HMACGeneral:            "CKM_SHA512_HMAC_GENERAL",
	MechanismSecurIDKeyGen:                "CKM_SECURID_KEY_GEN",
	MechanismSecurID:                      "CKM_SECURID",
	MechanismHOTPKeyGen:                   "CKM_HOTP_KEY_GEN",
	MechanismHOTP:                         "CKM_HOTP",
	MechanismACTI:                         "CKM_ACTI",
	MechanismACTIKeyGen:                   "CKM_ACTI_KEY_GEN",
	MechanismSHA3_256:                     "CKM_SHA3_256",
	MechanismSHA3_256HMAC:                 "CKM_SHA3_256_HMAC",
	MechanismSHA3_256HMACGeneral:          "CKM_SHA3_256_HMAC_GENERAL",
	MechanismSHA3_256KeyGen:               "CKM_SHA3_256_KEY_GEN",
	MechanismSHA3_224:                     "CKM_SHA3_224",
	MechanismSHA3_224HMAC:                 "CKM_SHA3_224_HMAC",
	MechanismSHA3_224HMACGeneral:          "CKM_SHA3_224_HMAC_GENERAL",
	MechanismSHA3_224KeyGen:               "CKM_SHA3_224_KEY_GEN",
	MechanismSHA3_384:                     "CKM_SHA3_384",
	MechanismSHA3_384HMAC:                 "CKM_SHA3_384_HMAC",
	MechanismSHA3_384HMACGeneral:          "CKM_SHA3_384_HMAC_GENERAL",
	MechanismSHA3_384KeyGen:               "CKM_SHA3_384_KEY_GEN",
	MechanismSHA3_512:                     "CKM_SHA3_512",
	MechanismSHA3_512HMAC:                 "CKM_SHA3_512_HMAC",
	MechanismSHA3_512HMACGeneral:          "CKM_SHA3_512_HMAC_GENERAL",
	MechanismSHA3_512KeyGen:               "CKM_SHA3_512_KEY_GEN",
	MechanismCASTKeyGen:                   "CKM_CAST_KEY_GEN",
	MechanismCASTECB:                      "CKM_CAST_ECB",
	MechanismCASTCBC:                      "CKM_CAST_CBC",
	MechanismCASTMAC:                      "CKM_CAST_MAC",
	MechanismCASTMACGeneral:               "CKM_CAST_MAC_GENERAL",
	MechanismCASTCBCPad:                   "CKM_CAST_CBC_PAD",
	MechanismCAST3KeyGen:                  "CKM_CAST3_KEY_GEN",
	MechanismCAST3ECB:                     "CKM_CAST3_ECB",
	MechanismCAST3CBC:                     "CKM_CAST3_CBC",
	MechanismCAST3MAC:                     "CKM_CAST3_MAC",
	MechanismCAST3MACGeneral:              "CKM_CAST3_MAC_GENERAL",
	MechanismCAST3CBCPad:                  "CKM_CAST3_CBC_PAD",
	MechanismCAST128KeyGen:                "CKM_CAST128_KEY_GEN",
	MechanismCAST128ECB:                   "CKM_CAST128_ECB",
	MechanismCAST128CBC:                   "CKM_CAST128_CBC",
	MechanismCAST128MAC:                   "CKM_CAST128_MAC",
	MechanismCAST128MACGeneral:            "CKM_CAST128_MAC_GENERAL",
	MechanismCAST128CBCPad:                "CKM_CAST128_CBC_PAD",
	MechanismRC5KeyGen:                    "CKM_RC5_KEY_GEN",
	MechanismRC5ECB:                       "CKM_RC5_ECB",
	MechanismRC5CBC:                       "CKM_RC5_CBC",
	MechanismRC5MAC:                       "CKM_RC5_MAC",
	MechanismRC5MACGeneral:                "CKM_RC5_MAC_GENERAL",
	MechanismRC5CBCPad:                    "CKM_RC5_CBC_PAD",
	MechanismIDEAKeyGen:                   "CKM_IDEA_KEY_GEN",
	MechanismIDEAECB:                      "CKM_IDEA_ECB",
	MechanismIDEACBC:                      "CKM_IDEA_CBC",
	MechanismIDEAMAC:                      "CKM_IDEA_MAC",
	MechanismIDEAMACGeneral:               "CKM_IDEA_MAC_GENERAL",
	MechanismIDEACBCPad:                   "CKM_IDEA_CBC_PAD",
	MechanismGenericSecretKeyGen:          "CKM_GENERIC_SECRET_KEY_GEN",
	MechanismConcatenateBaseAndKey:        "CKM_CONCATENATE_BASE_AND_KEY",
	MechanismConcatenateBaseAndData:       "CKM_CONCATENATE_BASE_AND_DATA",
	MechanismConcatenateDataAndBase:       "CKM_CONCATENATE_DATA_AND_BASE",
	MechanismXorBaseAndData:               "CKM_XOR_BASE_AND_DATA",
	MechanismExtractKeyFromKey:            "CKM_EXTRACT_KEY_FROM_KEY",
	MechanismSSL3PreMasterKeyGen:          "CKM_SSL3_PRE_MASTER_KEY_GEN",
	MechanismSSL3MasterKeyDerive:          "CKM_SSL3_MASTER_KEY_DERIVE",
	MechanismSSL3KeyAndMACDerive:          "CKM_SSL3_KEY_AND_MAC_DERIVE",
	MechanismSSL3MasterKeyDeriveDH:        "CKM_SSL3_MASTER_KEY_DERIVE_DH",
	MechanismTLSPreMasterKeyGen:           "CKM_TLS_PRE_MASTER_KEY_GEN",
	MechanismTLSMasterKeyDerive:           "CKM_TLS_MASTER_KEY_DERIVE",
	MechanismTLSKeyAndMACDerive:           "CKM_TLS_KEY_AND_MAC_DERIVE",
	MechanismTLSMasterKeyDeriveDH:         "CKM_TLS_MASTER_KEY_DERIVE_DH",
	MechanismTLSPRF:                       "CKM_TLS_PRF",
	MechanismSSL3MD5MAC:                   "CKM_SSL3_MD5_MAC",
	MechanismSSL3SHA1MAC:                  "CKM_SSL3_SHA1_MAC",
	MechanismMD5KeyDerivation:             "CKM_MD5_KEY_DERIVATION",
	MechanismMD2KeyDerivation:             "CKM_MD2_KEY_DERIVATION",
	MechanismSHA1KeyDerivation:            "CKM_SHA1_KEY_DERIVATION",
	MechanismSHA256KeyDerivation:          "CKM_SHA256_KEY_DERIVATION",
	MechanismSHA384KeyDerivation:          "CKM_SHA384_KEY_DERIVATION",
	MechanismSHA512KeyDerivation:          "CKM_SHA512_KEY_DERIVATION",
	MechanismSHA224KeyDerivation:          "CKM_SHA224_KEY_DERIVATION",
	MechanismSHA3_256KeyDerivation:        "CKM_SHA3_256_KEY_DERIVATION",
	MechanismSHA3_224KeyDerivation:        "CKM_SHA3_224_KEY_DERIVATION",
	MechanismSHA3_384KeyDerivation:        "CKM_SHA3_384_KEY_DERIVATION",
	MechanismSHA3_512KeyDerivation:        "CKM_SHA3_512_KEY_DERIVATION",
	MechanismSHAKE128KeyDerivation:        "CKM_SHAKE_128_KEY_DERIVATION",
	MechanismSHAKE256KeyDerivation:        "CKM_SHAKE_256_KEY_DERIVATION",
	MechanismPBEMD2DESCBC:                 "CKM_PBE_MD2_DES_CBC",
	MechanismPBEMD5DESCBC:                 "CKM_PBE_MD5_DES_CBC",
	MechanismPBEMD5CASTCBC:                "CKM_PBE_MD5_CAST_CBC",
	MechanismPBEMD5CAST3CBC:               "CKM_PBE_MD5_CAST3_CBC",
	MechanismPBEMD5CAST128CBC:             "CKM_PBE_MD5_CAST128_CBC",
	MechanismPBESHA1CAST128CBC:            "CKM_PBE_SHA1_CAST128_CBC",
	MechanismPBESHA1RC4_128:               "CKM_PBE_SHA1_RC4_128",
	MechanismPBESHA1RC4_40:                "CKM_PBE_SHA1_RC4_40",
	MechanismPBESHA1DES3EDECBC:            "CKM_PBE_SHA1_DES3_EDE_CBC",
	MechanismPBESHA1DES2EDECBC:            "CKM_PBE_SHA1_DES2_EDE_CBC",
	MechanismPBESHA1RC2_128CBC:            "CKM_PBE_SHA1_RC2_128_CBC",
	MechanismPBESHA1RC2_40CBC:             "CKM_PBE_SHA1_RC2_40_CBC",
	MechanismPKCS5PBKD2:                   "CKM_PKCS5_PBKD2",
	MechanismPBASHA1WithSHA1HMAC:          "CKM_PBA_SHA1_WITH_SHA1_HMAC",
	MechanismWTLSPreMasterKeyGen:          "CKM_WTLS_PRE_MASTER_KEY_GEN",
	MechanismWTLSMasterKeyDerive:          "CKM_WTLS_MASTER_KEY_DERIVE",
	MechanismWTLSMasterKeyDeriveDHECC:     "CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC",
	MechanismWTLSPRF:                      "CKM_WTLS_PRF",
	MechanismWTLSServerKeyAndMACDerive:    "CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE",
	MechanismWTLSClientKeyAndMACDerive:    "CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE",
	MechanismTLS10MACServer:               "CKM_TLS10_MAC_SERVER",
	MechanismTLS10MACClient:               "CKM_TLS10_MAC_CLIENT",
	MechanismTLS12MAC:                     "CKM_TLS12_MAC",
	MechanismTLS12KDF:                     "CKM_TLS12_KDF",
	MechanismTLS12MasterKeyDerive:         "CKM_TLS12_MASTER_KEY_DERIVE",
	MechanismTLS12KeyAndMACDerive:         "CKM_TLS12_KEY_AND_MAC_DERIVE",
	MechanismTLS12MasterKeyDeriveDH:       "CKM_TLS12_MASTER_KEY_DERIVE_DH",
	MechanismTLS12KeySafeDerive:           "CKM_TLS12_KEY_SAFE_DERIVE",
	MechanismTLSMAC:                       "CKM_TLS_MAC",
	MechanismTLSKDF:                       "CKM_TLS_KDF",
	MechanismKeyWrapLYNKS:                 "CKM_KEY_WRAP_LYNKS",
	MechanismKeyWrapSetOAEP:               "CKM_KEY_WRAP_SET_OAEP",
	MechanismCMSSIG:                       "CKM_CMS_SIG",
	MechanismKIPDerive:                    "CKM_KIP_DERIVE",
	MechanismKIPWrap:                      "CKM_KIP_WRAP",
	MechanismKIPMAC:                       "CKM_KIP_MAC",
	MechanismCamelliaKeyGen:               "CKM_CAMELLIA_KEY_GEN",
	MechanismCamelliaECB:                  "CKM_CAMELLIA_ECB",
	MechanismCamelliaCBC:                  "CKM_CAMELLIA_CBC",
	MechanismCamelliaMAC:                  "CKM_CAMELLIA_MAC",
	MechanismCamelliaMACGeneral:           "CKM_CAMELLIA_MAC_GENERAL",
	MechanismCamelliaCBCPad:               "CKM_CAMELLIA_CBC_PAD",
	MechanismCamelliaECBEncryptData:       "CKM_CAMELLIA_ECB_ENCRYPT_DATA",
	MechanismCamelliaCBCEncryptData:       "CKM_CAMELLIA_CBC_ENCRYPT_DATA",
	MechanismCamelliaCTR:                  "CKM_CAMELLIA_CTR",
	MechanismARIAKeyGen:                   "CKM_ARIA_KEY_GEN",
	MechanismARIAECB:                      "CKM_ARIA_ECB",
	MechanismARIACBC:                      "CKM_ARIA_CBC",
	MechanismARIAMAC:                      "CKM_ARIA_MAC",
	MechanismARIAMACGeneral:               "CKM_ARIA_MAC_GENERAL",
	MechanismARIACBCPad:                   "CKM_ARIA_CBC_PAD",
	MechanismARIAECBEncryptData:           "CKM_ARIA_ECB_ENCRYPT_DATA",
	MechanismARIACBCEncryptData:           "CKM_ARIA_CBC_ENCRYPT_DATA",
	MechanismSeedKeyGen:                   "CKM_SEED_KEY_GEN",
	MechanismSeedECB:                      "CKM_SEED_ECB",
	MechanismSeedCBC:                      "CKM_SEED_CBC",
	MechanismSeedMAC:                      "CKM_SEED_MAC",
	MechanismSeedMACGeneral:               "CKM_SEED_MAC_GENERAL",
	MechanismSeedCBCPad:                   "CKM_SEED_CBC_PAD",
	MechanismSeedECBEncryptData:           "CKM_SEED_ECB_ENCRYPT_DATA",
	MechanismSeedCBCEncryptData:           "CKM_SEED_CBC_ENCRYPT_DATA",
	MechanismSkipjackKeyGen:               "CKM_SKIPJACK_KEY_GEN",
	MechanismSkipjackECB64:                "CKM_SKIPJACK_ECB64",
	MechanismSkipjackCBC64:                "CKM_SKIPJACK_CBC64",
	MechanismSkipjackOFB64:                "CKM_SKIPJACK_OFB64",
	MechanismSkipjackCFB64:                "CKM_SKIPJACK_CFB64",
	MechanismSkipjackCFB32:                "CKM_SKIPJACK_CFB32",
	MechanismSkipjackCFB16:                "CKM_SKIPJACK_CFB16",
	MechanismSkipjackCFB8:                 "CKM_SKIPJACK_CFB8",
	MechanismSkipjackWrap:                 "CKM_SKIPJACK_WRAP",
	MechanismSkipjackPrivateWrap:          "CKM_SKIPJACK_PRIVATE_WRAP",
	MechanismSkipjackRelayx:               "CKM_SKIPJACK_RELAYX",
	MechanismKEAKeyPairGen:                "CKM_KEA_KEY_PAIR_GEN",
	MechanismKEAKeyDerive:                 "CKM_KEA_KEY_DERIVE",
	MechanismKEADerive:                    "CKM_KEA_DERIVE",
	MechanismFortezzaTimestamp:            "CKM_FORTEZZA_TIMESTAMP",
	MechanismBATONKeyGen:                  "CKM_BATON_KEY_GEN",
	MechanismBATONECB128:                  "CKM_BATON_ECB128",
	MechanismBATONECB96:                   "CKM_BATON_ECB96",
	MechanismBATONCBC128:                  "CKM_BATON_CBC128",
	MechanismBATONCounter:                 "CKM_BATON_COUNTER",
	MechanismBATONShuffle:                 "CKM_BATON_SHUFFLE",
	MechanismBATONWrap:                    "CKM_BATON_WRAP",
	MechanismECKeyPairGen:                 "CKM_EC_KEY_PAIR_GEN",
	MechanismECDSA:                        "CKM_ECDSA",
	MechanismECDSASHA1:                    "CKM_ECDSA_SHA1",
	MechanismECDSASHA224:                  "CKM_ECDSA_SHA224",
	MechanismECDSASHA256:                  "CKM_ECDSA_SHA256",
	MechanismECDSASHA384:                  "CKM_ECDSA_SHA384",
	MechanismECDSASHA512:                  "CKM_ECDSA_SHA512",
	MechanismECKeyPairGenWExtraBits:       "CKM_EC_KEY_PAIR_GEN_W_EXTRA_BITS",
	MechanismECDH1Derive:                  "CKM_ECDH1_DERIVE",
	MechanismECDH1CofactorDerive:          "CKM_ECDH1_COFACTOR_DERIVE",
	MechanismECMQVDerive:                  "CKM_ECMQV_DERIVE",
	MechanismECDHAESKeyWrap:               "CKM_ECDH_AES_KEY_WRAP",
	MechanismRSAAESKeyWrap:                "CKM_RSA_AES_KEY_WRAP",
	MechanismJuniperKeyGen:                "CKM_JUNIPER_KEY_GEN",
	MechanismJuniperECB128:                "CKM_JUNIPER_ECB128",
	MechanismJuniperCBC128:                "CKM_JUNIPER_CBC128",
	MechanismJuniperCounter:               "CKM_JUNIPER_COUNTER",
	MechanismJuniperShuffle:               "CKM_JUNIPER_SHUFFLE",
	MechanismJuniperWrap:                  "CKM_JUNIPER_WRAP",
	MechanismFasthash:                     "CKM_FASTHASH",
	MechanismAESXTS:                       "CKM_AES_XTS",
	MechanismAESXTSKeyGen:                 "CKM_AES_XTS_KEY_GEN",
	MechanismAESKeyGen:                    "CKM_AES_KEY_GEN",
	MechanismAESECB:                       "CKM_AES_ECB",
	MechanismAESCBC:                       "CKM_AES_CBC",
	MechanismAESMAC:                       "CKM_AES_MAC",
	MechanismAESMACGeneral:                "CKM_AES_MAC_GENERAL",
	MechanismAESCBCPad:                    "CKM_AES_CBC_PAD",
	MechanismAESCTR:                       "CKM_AES_CTR",
	MechanismAESGCM:                       "CKM_AES_GCM",
	MechanismAESCCM:                       "CKM_AES_CCM",
	MechanismAESCTS:                       "CKM_AES_CTS",
	MechanismAESCMAC:                      "CKM_AES_CMAC",
	MechanismAESCMACGeneral:               "CKM_AES_CMAC_GENERAL",
	MechanismAESXCBCMAC:                   "CKM_AES_XCBC_MAC",
	MechanismAESXCBCMAC96:                 "CKM_AES_XCBC_MAC_96",
	MechanismAESGMAC:                      "CKM_AES_GMAC",
	MechanismBlowfishKeyGen:               "CKM_BLOWFISH_KEY_GEN",
	MechanismBlowfishCBC:                  "CKM_BLOWFISH_CBC",
	MechanismTwofishKeyGen:                "CKM_TWOFISH_KEY_GEN",
	MechanismTwofishCBC:                   "CKM_TWOFISH_CBC",
	MechanismBlowfishCBCPad:               "CKM_BLOWFISH_CBC_PAD",
	MechanismTwofishCBCPad:                "CKM_TWOFISH_CBC_PAD",
	MechanismDESECBEncryptData:            "CKM_DES_ECB_ENCRYPT_DATA",
	MechanismDESCBCEncryptData:            "CKM_DES_CBC_ENCRYPT_DATA",
	MechanismDES3ECBEncryptData:           "CKM_DES3_ECB_ENCRYPT_DATA",
	MechanismDES3CBCEncryptData:           "CKM_DES3_CBC_ENCRYPT_DATA",
	MechanismAESECBEncryptData:            "CKM_AES_ECB_ENCRYPT_DATA",
	MechanismAESCBCEncryptData:            "CKM_AES_CBC_ENCRYPT_DATA",
	MechanismGOSTR3410KeyPairGen:          "CKM_GOSTR3410_KEY_PAIR_GEN",
	MechanismGOSTR3410:                    "CKM_GOSTR3410",
	MechanismGOSTR3410WithGOSTR3411:       "CKM_GOSTR3410_WITH_GOSTR3411",
	MechanismGOSTR3410KeyWrap:             "CKM_GOSTR3410_KEY_WRAP",
	MechanismGOSTR3410Derive:              "CKM_GOSTR3410_DERIVE",
	MechanismGOSTR3411:                    "CKM_GOSTR3411",
	MechanismGOSTR3411HMAC:                "CKM_GOSTR3411_HMAC",
	MechanismGOST28147KeyGen:              "CKM_GOST28147_KEY_GEN",
	MechanismGOST28147ECB:                 "CKM_GOST28147_ECB",
	MechanismGOST28147:                    "CKM_GOST28147",
	MechanismGOST28147MAC:                 "CKM_GOST28147_MAC",
	MechanismGOST28147KeyWrap:             "CKM_GOST28147_KEY_WRAP",
	MechanismChaCha20KeyGen:               "CKM_CHACHA20_KEY_GEN",
	MechanismChaCha20:                     "CKM_CHACHA20",
	MechanismPoly1305KeyGen:               "CKM_POLY1305_KEY_GEN",
	MechanismPoly1305:                     "CKM_POLY1305",
	MechanismDSAParameterGen:              "CKM_DSA_PARAMETER_GEN",
	MechanismDHPKCSParameterGen:           "CKM_DH_PKCS_PARAMETER_GEN",
	MechanismX9_42DHParameterGen:          "CKM_X9_42_DH_PARAMETER_GEN",
	MechanismDSAProbabilisticParameterGen: "CKM_DSA_PROBABILISTIC_PARAMETER_GEN",
	MechanismDSAShaweTaylorParameterGen:   "CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN",
	MechanismDSAFIPSGGen:                  "CKM_DSA_FIPS_G_GEN",
	MechanismAESOFB:                       "CKM_AES_OFB",
	MechanismAESCFB64:                     "CKM_AES_CFB64",
	MechanismAESCFB8:                      "CKM_AES_CFB8",
	MechanismAESCFB128:                    "CKM_AES_CFB128",
	MechanismAESCFB1:                      "CKM_AES_CFB1",
	MechanismAESKeyWrap:                   "CKM_AES_KEY_WRAP",
	MechanismAESKeyWrapPad:                "CKM_AES_KEY_WRAP_PAD",
	MechanismAESKeyWrapKWP:                "CKM_AES_KEY_WRAP_KWP",
	MechanismAESKeyWrapPKCS7:              "CKM_AES_KEY_WRAP_PKCS7",
	MechanismRSAPKCSTPM1_1:                "CKM_RSA_PKCS_TPM_1_1",
	MechanismRSAPKCSOAEPTPM1_1:            "CKM_RSA_PKCS_OAEP_TPM_1_1",
	MechanismSHA1KeyGen:                   "CKM_SHA_1_KEY_GEN",
	MechanismSHA224KeyGen:                 "CKM_SHA224_KEY_GEN",
	MechanismSHA256KeyGen:                 "CKM_SHA256_KEY_GEN",
	MechanismSHA384KeyGen:                 "CKM_SHA384_KEY_GEN",
	MechanismSHA512KeyGen:                 "CKM_SHA512_KEY_GEN",
	MechanismSHA512_224KeyGen:             "CKM_SHA512_224_KEY_GEN",
	MechanismSHA512_256KeyGen:             "CKM_SHA512_256_KEY_GEN",
	MechanismSHA512TKeyGen:                "CKM_SHA512_T_KEY_GEN",
	MechanismNull:                         "CKM_NULL",
	MechanismBLAKE2b160:                   "CKM_BLAKE2B_160",
	MechanismBLAKE2b160HMAC:               "CKM_BLAKE2B_160_HMAC",
	MechanismBLAKE2b160HMACGeneral:        "CKM_BLAKE2B_160_HMAC_GENERAL",
	MechanismBLAKE2b160KeyDerive:          "CKM_BLAKE2B_160_KEY_DERIVE",
	MechanismBLAKE2b160KeyGen:             "CKM_BLAKE2B_160_KEY_GEN",
	MechanismBLAKE2b256:                   "CKM_BLAKE2B_256",
	MechanismBLAKE2b256HMAC:               "CKM_BLAKE2B_256_HMAC",
	MechanismBLAKE2b256HMACGeneral:        "CKM_BLAKE2B_256_HMAC_GENERAL",
	MechanismBLAKE2b256KeyDerive:          "CKM_BLAKE2B_256_KEY_DERIVE",
	MechanismBLAKE2b256KeyGen:             "CKM_BLAKE2B_256_KEY_GEN",
	MechanismBLAKE2b384:                   "CKM_BLAKE2B_384",
	MechanismBLAKE2b384HMAC:               "CKM_BLAKE2B_384_HMAC",
	MechanismBLAKE2b384HMACGeneral:        "CKM_BLAKE2B_384_HMAC_GENERAL",
	MechanismBLAKE2b384KeyDerive:          "CKM_BLAKE2B_384_KEY_DERIVE",
	MechanismBLAKE2b384KeyGen:             "CKM_BLAKE2B_384_KEY_GEN",
	MechanismBLAKE2b512:                   "CKM_BLAKE2B_512",
	MechanismBLAKE2b512HMAC:               "CKM_BLAKE2B_512_HMAC",
	MechanismBLAKE2b512HMACGeneral:        "CKM_BLAKE2B_512_HMAC_GENERAL",
	MechanismBLAKE2b512KeyDerive:          "CKM_BLAKE2B_512_KEY_DERIVE",
	MechanismBLAKE2b512KeyGen:             "CKM_BLAKE2B_512_KEY_GEN",
	MechanismSalsa20:                      "CKM_SALSA20",
	MechanismChacha20Poly1305:             "CKM_CHACHA20_POLY1305",
	MechanismSalsa20Poly1305:              "CKM_SALSA20_POLY1305",
	MechanismX3DHInitialize:               "CKM_X3DH_INITIALIZE",
	MechanismX3DHRespond:                  "CKM_X3DH_RESPOND",
	MechanismX2RatchetInitialize:          "CKM_X2RATCHET_INITIALIZE",
	MechanismX2RatchetRespond:             "CKM_X2RATCHET_RESPOND",
	MechanismX2RatchetEncrypt:             "CKM_X2RATCHET_ENCRYPT",
	MechanismX2RatchetDecrypt:             "CKM_X2RATCHET_DECRYPT",
	MechanismXEDDSA:                       "CKM_XEDDSA",
	MechanismHKDFDerive:                   "CKM_HKDF_DERIVE",
	MechanismHKDFData:                     "CKM_HKDF_DATA",
	MechanismHKDFKeyGen:                   "CKM_HKDF_KEY_GEN",
	MechanismSalsa20KeyGen:                "CKM_SALSA20_KEY_GEN",
	MechanismECDSASHA3_224:                "CKM_ECDSA_SHA3_224",
	MechanismECDSASHA3_256:                "CKM_ECDSA_SHA3_256",
	MechanismECDSASHA3_384:                "CKM_ECDSA_SHA3_384",
	MechanismECDSASHA3_512:                "CKM_ECDSA_SHA3_512",
	MechanismECEdwardsKeyPairGen:          "CKM_EC_EDWARDS_KEY_PAIR_GEN",
	MechanismECMontgomeryKeyPairGen:       "CKM_EC_MONTGOMERY_KEY_PAIR_GEN",
	MechanismEDDSA:                        "CKM_EDDSA",
	MechanismSP800_108CounterKDF:          "CKM_SP800_108_COUNTER_KDF",
	MechanismSP800_108FeedbackKDF:         "CKM_SP800_108_FEEDBACK_KDF",
	MechanismSP800_108DoublePipelineKDF:   "CKM_SP800_108_DOUBLE_PIPELINE_KDF",
	MechanismIKE2PRFPlusDerive:            "CKM_IKE2_PRF_PLUS_DERIVE",
	MechanismIKEPRFDerive:                 "CKM_IKE_PRF_DERIVE",
	MechanismIKE1PRFDerive:                "CKM_IKE1_PRF_DERIVE",
	MechanismIKE1ExtendedDerive:           "CKM_IKE1_EXTENDED_DERIVE",
	MechanismHSSKeyPairGen:                "CKM_HSS_KEY_PAIR_GEN",
	MechanismHSS:                          "CKM_HSS",
	MechanismVendorDefined:                "CKM_VENDOR_DEFINED",
}

func (m MechanismType) String() string {
	if s, ok := mechStr[m]; ok {
		return s
	}
	return fmt.Sprintf("MechanismType(0x%08x)", uint(m))
}

type Attribute C.CK_ATTRIBUTE

func (a *Attribute) Value() Value {
	t := AttributeType(a._type)
	switch t {
	case AttributeClass:
		return &Scalar[Class]{Value: *(*Class)(unsafe.Pointer(a.pValue)), typ: t, valid: true}

	case AttributeKeyType:
		return &Scalar[KeyType]{Value: *(*KeyType)(unsafe.Pointer(a.pValue)), typ: t, valid: true}

	case AttributeCertificateType:
		return &Scalar[CertificateType]{Value: *(*CertificateType)(unsafe.Pointer(a.pValue)), typ: t, valid: true}

	case AttributeMechanismType, AttributeNameHashAlgorithm, AttributeKeyGenMechanism:
		return &Scalar[MechanismType]{Value: *(*MechanismType)(unsafe.Pointer(a.pValue)), typ: t, valid: true}

	case AttributeAllowedMechanisms:
		ptr := (*MechanismType)(unsafe.Pointer(a.pValue))
		return &Array[[]MechanismType, MechanismType]{Value: unsafe.Slice(ptr, int(a.ulValueLen)/int(unsafe.Sizeof(*ptr))), typ: t}

	case AttributeWrapTemplate, AttributeUnwrapTemplate, AttributeDeriveTemplate:
		ptr := (*Attribute)(unsafe.Pointer(a.pValue))
		return &Array[[]Attribute, Attribute]{Value: unsafe.Slice(ptr, int(a.ulValueLen)/int(unsafe.Sizeof(*ptr))), typ: t}

	default:
		if dt, ok := attrDataType[t]; ok {
			switch dt {
			case attrUint:
				return &Scalar[Uint]{Value: *(*Uint)(unsafe.Pointer(a.pValue)), typ: t, valid: true}
			case attrBool:
				return &Scalar[Bool]{Value: *(*Bool)(unsafe.Pointer(a.pValue)), typ: t, valid: true}
			case attrDate:
				return &Scalar[Date]{Value: *(*Date)(unsafe.Pointer(a.pValue)), typ: t, valid: true}
			case attrBigInt:
				ptr := (*byte)(unsafe.Pointer(a.pValue))
				return &Array[BigInt, byte]{Value: unsafe.Slice(ptr, int(a.ulValueLen)), typ: t}
			case attrString:
				ptr := (*byte)(unsafe.Pointer(a.pValue))
				return &Array[String, byte]{Value: unsafe.Slice(ptr, int(a.ulValueLen)), typ: t}
			}
		}
		ptr := (*byte)(unsafe.Pointer(a.pValue))
		return &Array[Bytes, byte]{Value: unsafe.Slice(ptr, int(a.ulValueLen)), typ: t}
	}
}

func (a *Attribute) String() string { return a.Value().String() }

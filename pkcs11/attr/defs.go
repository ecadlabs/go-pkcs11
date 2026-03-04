package attr

/*
#include "../platform.h"
*/
import "C"
import "fmt"

type Type C.CK_ATTRIBUTE_TYPE

const (
	TypeClass                   Type = C.CKA_CLASS
	TypeToken                   Type = C.CKA_TOKEN
	TypePrivate                 Type = C.CKA_PRIVATE
	TypeLabel                   Type = C.CKA_LABEL
	TypeUniqueID                Type = C.CKA_UNIQUE_ID
	TypeApplication             Type = C.CKA_APPLICATION
	TypeValue                   Type = C.CKA_VALUE
	TypeObjectID                Type = C.CKA_OBJECT_ID
	TypeCertificateType         Type = C.CKA_CERTIFICATE_TYPE
	TypeIssuer                  Type = C.CKA_ISSUER
	TypeSerialNumber            Type = C.CKA_SERIAL_NUMBER
	TypeACIssuer                Type = C.CKA_AC_ISSUER
	TypeOwner                   Type = C.CKA_OWNER
	TypeAttrTypes               Type = C.CKA_ATTR_TYPES
	TypeTrusted                 Type = C.CKA_TRUSTED
	TypeCertificateCategory     Type = C.CKA_CERTIFICATE_CATEGORY
	TypeJavaMIDPSecurityDomain  Type = C.CKA_JAVA_MIDP_SECURITY_DOMAIN
	TypeURL                     Type = C.CKA_URL
	TypeHashOfSubjectPublicKey  Type = C.CKA_HASH_OF_SUBJECT_PUBLIC_KEY
	TypeHashOfIssuerPublicKey   Type = C.CKA_HASH_OF_ISSUER_PUBLIC_KEY
	TypeNameHashAlgorithm       Type = C.CKA_NAME_HASH_ALGORITHM
	TypeCheckValue              Type = C.CKA_CHECK_VALUE
	TypeKeyType                 Type = C.CKA_KEY_TYPE
	TypeSubject                 Type = C.CKA_SUBJECT
	TypeID                      Type = C.CKA_ID
	TypeSensitive               Type = C.CKA_SENSITIVE
	TypeEncrypt                 Type = C.CKA_ENCRYPT
	TypeDecrypt                 Type = C.CKA_DECRYPT
	TypeWrap                    Type = C.CKA_WRAP
	TypeUnwrap                  Type = C.CKA_UNWRAP
	TypeSign                    Type = C.CKA_SIGN
	TypeSignRecover             Type = C.CKA_SIGN_RECOVER
	TypeVerify                  Type = C.CKA_VERIFY
	TypeVerifyRecover           Type = C.CKA_VERIFY_RECOVER
	TypeDerive                  Type = C.CKA_DERIVE
	TypeStartDate               Type = C.CKA_START_DATE
	TypeEndDate                 Type = C.CKA_END_DATE
	TypeModulus                 Type = C.CKA_MODULUS
	TypeModulusBits             Type = C.CKA_MODULUS_BITS
	TypePublicExponent          Type = C.CKA_PUBLIC_EXPONENT
	TypePrivateExponent         Type = C.CKA_PRIVATE_EXPONENT
	TypePrime_1                 Type = C.CKA_PRIME_1
	TypePrime_2                 Type = C.CKA_PRIME_2
	TypeExponent_1              Type = C.CKA_EXPONENT_1
	TypeExponent_2              Type = C.CKA_EXPONENT_2
	TypeCoefficient             Type = C.CKA_COEFFICIENT
	TypePublicKeyInfo           Type = C.CKA_PUBLIC_KEY_INFO
	TypePrime                   Type = C.CKA_PRIME
	TypeSubprime                Type = C.CKA_SUBPRIME
	TypeBase                    Type = C.CKA_BASE
	TypePrimeBits               Type = C.CKA_PRIME_BITS
	TypeSubPrimeBits            Type = C.CKA_SUB_PRIME_BITS
	TypeValueBits               Type = C.CKA_VALUE_BITS
	TypeValueLen                Type = C.CKA_VALUE_LEN
	TypeExtractable             Type = C.CKA_EXTRACTABLE
	TypeLocal                   Type = C.CKA_LOCAL
	TypeNeverExtractable        Type = C.CKA_NEVER_EXTRACTABLE
	TypeAlwaysSensitive         Type = C.CKA_ALWAYS_SENSITIVE
	TypeKeyGenMechanism         Type = C.CKA_KEY_GEN_MECHANISM
	TypeModifiable              Type = C.CKA_MODIFIABLE
	TypeCopyable                Type = C.CKA_COPYABLE
	TypeDestroyable             Type = C.CKA_DESTROYABLE
	TypeECParams                Type = C.CKA_EC_PARAMS
	TypeECPoint                 Type = C.CKA_EC_POINT
	TypeAlwaysAuthenticate      Type = C.CKA_ALWAYS_AUTHENTICATE
	TypeWrapWithTrusted         Type = C.CKA_WRAP_WITH_TRUSTED
	TypeWrapTemplate            Type = C.CKA_WRAP_TEMPLATE
	TypeUnwrapTemplate          Type = C.CKA_UNWRAP_TEMPLATE
	TypeDeriveTemplate          Type = C.CKA_DERIVE_TEMPLATE
	TypeOTPFormat               Type = C.CKA_OTP_FORMAT
	TypeOTPLength               Type = C.CKA_OTP_LENGTH
	TypeOTPTimeInterval         Type = C.CKA_OTP_TIME_INTERVAL
	TypeOTPUserFriendlyMode     Type = C.CKA_OTP_USER_FRIENDLY_MODE
	TypeOTPChallengeRequirement Type = C.CKA_OTP_CHALLENGE_REQUIREMENT
	TypeOTPTimeRequirement      Type = C.CKA_OTP_TIME_REQUIREMENT
	TypeOTPCounterRequirement   Type = C.CKA_OTP_COUNTER_REQUIREMENT
	TypeOTPPinRequirement       Type = C.CKA_OTP_PIN_REQUIREMENT
	TypeOTPCounter              Type = C.CKA_OTP_COUNTER
	TypeOTPTime                 Type = C.CKA_OTP_TIME
	TypeOTPUserIdentifier       Type = C.CKA_OTP_USER_IDENTIFIER
	TypeOTPServiceIdentifier    Type = C.CKA_OTP_SERVICE_IDENTIFIER
	TypeOTPServiceLogo          Type = C.CKA_OTP_SERVICE_LOGO
	TypeOTPServiceLogoType      Type = C.CKA_OTP_SERVICE_LOGO_TYPE
	TypeGOSTR3410Params         Type = C.CKA_GOSTR3410_PARAMS
	TypeGOSTR3411Params         Type = C.CKA_GOSTR3411_PARAMS
	TypeGOST28147Params         Type = C.CKA_GOST28147_PARAMS
	TypeHWFeatureType           Type = C.CKA_HW_FEATURE_TYPE
	TypeResetOnInit             Type = C.CKA_RESET_ON_INIT
	TypeHasReset                Type = C.CKA_HAS_RESET
	TypePixelX                  Type = C.CKA_PIXEL_X
	TypePixelY                  Type = C.CKA_PIXEL_Y
	TypeResolution              Type = C.CKA_RESOLUTION
	TypeCharRows                Type = C.CKA_CHAR_ROWS
	TypeCharColumns             Type = C.CKA_CHAR_COLUMNS
	TypeColor                   Type = C.CKA_COLOR
	TypeBitsPerPixel            Type = C.CKA_BITS_PER_PIXEL
	TypeCharSets                Type = C.CKA_CHAR_SETS
	TypeEncodingMethods         Type = C.CKA_ENCODING_METHODS
	TypeMimeTypes               Type = C.CKA_MIME_TYPES
	TypeMechanismType           Type = C.CKA_MECHANISM_TYPE
	TypeRequiredCMSAttributes   Type = C.CKA_REQUIRED_CMS_ATTRIBUTES
	TypeDefaultCMSAttributes    Type = C.CKA_DEFAULT_CMS_ATTRIBUTES
	TypeSupportedCMSAttributes  Type = C.CKA_SUPPORTED_CMS_ATTRIBUTES
	TypeAllowedMechanisms       Type = C.CKA_ALLOWED_MECHANISMS
	TypeProfileID               Type = C.CKA_PROFILE_ID
	TypeX2RatchetBag            Type = C.CKA_X2RATCHET_BAG
	TypeX2RatchetBagSize        Type = C.CKA_X2RATCHET_BAGSIZE
	TypeX2RatchetBobs1stMsg     Type = C.CKA_X2RATCHET_BOBS1STMSG
	TypeX2RatchetCKR            Type = C.CKA_X2RATCHET_CKR
	TypeX2RatchetCKS            Type = C.CKA_X2RATCHET_CKS
	TypeX2RatchetDHP            Type = C.CKA_X2RATCHET_DHP
	TypeX2RatchetDHR            Type = C.CKA_X2RATCHET_DHR
	TypeX2RatchetDHS            Type = C.CKA_X2RATCHET_DHS
	TypeX2RatchetHKR            Type = C.CKA_X2RATCHET_HKR
	TypeX2RatchetHKS            Type = C.CKA_X2RATCHET_HKS
	TypeX2RatchetIsAlice        Type = C.CKA_X2RATCHET_ISALICE
	TypeX2RatchetNHKR           Type = C.CKA_X2RATCHET_NHKR
	TypeX2RatchetNHKS           Type = C.CKA_X2RATCHET_NHKS
	TypeX2RatchetNR             Type = C.CKA_X2RATCHET_NR
	TypeX2RatchetNS             Type = C.CKA_X2RATCHET_NS
	TypeX2RatchetPNS            Type = C.CKA_X2RATCHET_PNS
	TypeX2RatchetRK             Type = C.CKA_X2RATCHET_RK
	TypeHSSLevels               Type = C.CKA_HSS_LEVELS
	TypeHSSLMSType              Type = C.CKA_HSS_LMS_TYPE
	TypeHSSLMOTSType            Type = C.CKA_HSS_LMOTS_TYPE
	TypeHSSLMSTypes             Type = C.CKA_HSS_LMS_TYPES
	TypeHSSLMOTSTypes           Type = C.CKA_HSS_LMOTS_TYPES
	TypeHSSKeysRemaining        Type = C.CKA_HSS_KEYS_REMAINING
	TypeVendorDefined           Type = C.CKA_VENDOR_DEFINED
)

var attrStr = map[Type]string{
	TypeClass:                   "CKA_CLASS",
	TypeToken:                   "CKA_TOKEN",
	TypePrivate:                 "CKA_PRIVATE",
	TypeLabel:                   "CKA_LABEL",
	TypeUniqueID:                "CKA_UNIQUE_ID",
	TypeApplication:             "CKA_APPLICATION",
	TypeValue:                   "CKA_VALUE",
	TypeObjectID:                "CKA_OBJECT_ID",
	TypeCertificateType:         "CKA_CERTIFICATE_TYPE",
	TypeIssuer:                  "CKA_ISSUER",
	TypeSerialNumber:            "CKA_SERIAL_NUMBER",
	TypeACIssuer:                "CKA_AC_ISSUER",
	TypeOwner:                   "CKA_OWNER",
	TypeAttrTypes:               "CKA_ATTR_TYPES",
	TypeTrusted:                 "CKA_TRUSTED",
	TypeCertificateCategory:     "CKA_CERTIFICATE_CATEGORY",
	TypeJavaMIDPSecurityDomain:  "CKA_JAVA_MIDP_SECURITY_DOMAIN",
	TypeURL:                     "CKA_URL",
	TypeHashOfSubjectPublicKey:  "CKA_HASH_OF_SUBJECT_PUBLIC_KEY",
	TypeHashOfIssuerPublicKey:   "CKA_HASH_OF_ISSUER_PUBLIC_KEY",
	TypeNameHashAlgorithm:       "CKA_NAME_HASH_ALGORITHM",
	TypeCheckValue:              "CKA_CHECK_VALUE",
	TypeKeyType:                 "CKA_KEY_TYPE",
	TypeSubject:                 "CKA_SUBJECT",
	TypeID:                      "CKA_ID",
	TypeSensitive:               "CKA_SENSITIVE",
	TypeEncrypt:                 "CKA_ENCRYPT",
	TypeDecrypt:                 "CKA_DECRYPT",
	TypeWrap:                    "CKA_WRAP",
	TypeUnwrap:                  "CKA_UNWRAP",
	TypeSign:                    "CKA_SIGN",
	TypeSignRecover:             "CKA_SIGN_RECOVER",
	TypeVerify:                  "CKA_VERIFY",
	TypeVerifyRecover:           "CKA_VERIFY_RECOVER",
	TypeDerive:                  "CKA_DERIVE",
	TypeStartDate:               "CKA_START_DATE",
	TypeEndDate:                 "CKA_END_DATE",
	TypeModulus:                 "CKA_MODULUS",
	TypeModulusBits:             "CKA_MODULUS_BITS",
	TypePublicExponent:          "CKA_PUBLIC_EXPONENT",
	TypePrivateExponent:         "CKA_PRIVATE_EXPONENT",
	TypePrime_1:                 "CKA_PRIME_1",
	TypePrime_2:                 "CKA_PRIME_2",
	TypeExponent_1:              "CKA_EXPONENT_1",
	TypeExponent_2:              "CKA_EXPONENT_2",
	TypeCoefficient:             "CKA_COEFFICIENT",
	TypePublicKeyInfo:           "CKA_PUBLIC_KEY_INFO",
	TypePrime:                   "CKA_PRIME",
	TypeSubprime:                "CKA_SUBPRIME",
	TypeBase:                    "CKA_BASE",
	TypePrimeBits:               "CKA_PRIME_BITS",
	TypeSubPrimeBits:            "CKA_SUB_PRIME_BITS",
	TypeValueBits:               "CKA_VALUE_BITS",
	TypeValueLen:                "CKA_VALUE_LEN",
	TypeExtractable:             "CKA_EXTRACTABLE",
	TypeLocal:                   "CKA_LOCAL",
	TypeNeverExtractable:        "CKA_NEVER_EXTRACTABLE",
	TypeAlwaysSensitive:         "CKA_ALWAYS_SENSITIVE",
	TypeKeyGenMechanism:         "CKA_KEY_GEN_MECHANISM",
	TypeModifiable:              "CKA_MODIFIABLE",
	TypeCopyable:                "CKA_COPYABLE",
	TypeDestroyable:             "CKA_DESTROYABLE",
	TypeECParams:                "CKA_EC_PARAMS",
	TypeECPoint:                 "CKA_EC_POINT",
	TypeAlwaysAuthenticate:      "CKA_ALWAYS_AUTHENTICATE",
	TypeWrapWithTrusted:         "CKA_WRAP_WITH_TRUSTED",
	TypeWrapTemplate:            "CKA_WRAP_TEMPLATE",
	TypeUnwrapTemplate:          "CKA_UNWRAP_TEMPLATE",
	TypeDeriveTemplate:          "CKA_DERIVE_TEMPLATE",
	TypeOTPFormat:               "CKA_OTP_FORMAT",
	TypeOTPLength:               "CKA_OTP_LENGTH",
	TypeOTPTimeInterval:         "CKA_OTP_TIME_INTERVAL",
	TypeOTPUserFriendlyMode:     "CKA_OTP_USER_FRIENDLY_MODE",
	TypeOTPChallengeRequirement: "CKA_OTP_CHALLENGE_REQUIREMENT",
	TypeOTPTimeRequirement:      "CKA_OTP_TIME_REQUIREMENT",
	TypeOTPCounterRequirement:   "CKA_OTP_COUNTER_REQUIREMENT",
	TypeOTPPinRequirement:       "CKA_OTP_PIN_REQUIREMENT",
	TypeOTPCounter:              "CKA_OTP_COUNTER",
	TypeOTPTime:                 "CKA_OTP_TIME",
	TypeOTPUserIdentifier:       "CKA_OTP_USER_IDENTIFIER",
	TypeOTPServiceIdentifier:    "CKA_OTP_SERVICE_IDENTIFIER",
	TypeOTPServiceLogo:          "CKA_OTP_SERVICE_LOGO",
	TypeOTPServiceLogoType:      "CKA_OTP_SERVICE_LOGO_TYPE",
	TypeGOSTR3410Params:         "CKA_GOSTR3410_PARAMS",
	TypeGOSTR3411Params:         "CKA_GOSTR3411_PARAMS",
	TypeGOST28147Params:         "CKA_GOST28147_PARAMS",
	TypeHWFeatureType:           "CKA_HW_FEATURE_TYPE",
	TypeResetOnInit:             "CKA_RESET_ON_INIT",
	TypeHasReset:                "CKA_HAS_RESET",
	TypePixelX:                  "CKA_PIXEL_X",
	TypePixelY:                  "CKA_PIXEL_Y",
	TypeResolution:              "CKA_RESOLUTION",
	TypeCharRows:                "CKA_CHAR_ROWS",
	TypeCharColumns:             "CKA_CHAR_COLUMNS",
	TypeColor:                   "CKA_COLOR",
	TypeBitsPerPixel:            "CKA_BITS_PER_PIXEL",
	TypeCharSets:                "CKA_CHAR_SETS",
	TypeEncodingMethods:         "CKA_ENCODING_METHODS",
	TypeMimeTypes:               "CKA_MIME_TYPES",
	TypeMechanismType:           "CKA_MECHANISM_TYPE",
	TypeRequiredCMSAttributes:   "CKA_REQUIRED_CMS_ATTRIBUTES",
	TypeDefaultCMSAttributes:    "CKA_DEFAULT_CMS_ATTRIBUTES",
	TypeSupportedCMSAttributes:  "CKA_SUPPORTED_CMS_ATTRIBUTES",
	TypeAllowedMechanisms:       "CKA_ALLOWED_MECHANISMS",
	TypeProfileID:               "CKA_PROFILE_ID",
	TypeX2RatchetBag:            "CKA_X2RATCHET_BAG",
	TypeX2RatchetBagSize:        "CKA_X2RATCHET_BAGSIZE",
	TypeX2RatchetBobs1stMsg:     "CKA_X2RATCHET_BOBS1STMSG",
	TypeX2RatchetCKR:            "CKA_X2RATCHET_CKR",
	TypeX2RatchetCKS:            "CKA_X2RATCHET_CKS",
	TypeX2RatchetDHP:            "CKA_X2RATCHET_DHP",
	TypeX2RatchetDHR:            "CKA_X2RATCHET_DHR",
	TypeX2RatchetDHS:            "CKA_X2RATCHET_DHS",
	TypeX2RatchetHKR:            "CKA_X2RATCHET_HKR",
	TypeX2RatchetHKS:            "CKA_X2RATCHET_HKS",
	TypeX2RatchetIsAlice:        "CKA_X2RATCHET_ISALICE",
	TypeX2RatchetNHKR:           "CKA_X2RATCHET_NHKR",
	TypeX2RatchetNHKS:           "CKA_X2RATCHET_NHKS",
	TypeX2RatchetNR:             "CKA_X2RATCHET_NR",
	TypeX2RatchetNS:             "CKA_X2RATCHET_NS",
	TypeX2RatchetPNS:            "CKA_X2RATCHET_PNS",
	TypeX2RatchetRK:             "CKA_X2RATCHET_RK",
	TypeHSSLevels:               "CKA_HSS_LEVELS",
	TypeHSSLMSType:              "CKA_HSS_LMS_TYPE",
	TypeHSSLMOTSType:            "CKA_HSS_LMOTS_TYPE",
	TypeHSSLMSTypes:             "CKA_HSS_LMS_TYPES",
	TypeHSSLMOTSTypes:           "CKA_HSS_LMOTS_TYPES",
	TypeHSSKeysRemaining:        "CKA_HSS_KEYS_REMAINING",
	TypeVendorDefined:           "CKA_VENDOR_DEFINED",
}

func (a Type) String() string {
	if s, ok := attrStr[a]; ok {
		return s
	}
	return fmt.Sprintf("Attribute(0x%08x)", uint(a))
}

type MechType C.CK_MECHANISM_TYPE

const (
	MechanismRSAPKCSKeyPairGen            MechType = C.CKM_RSA_PKCS_KEY_PAIR_GEN
	MechanismRSAPKCS                      MechType = C.CKM_RSA_PKCS
	MechanismRSA9796                      MechType = C.CKM_RSA_9796
	MechanismRSAX509                      MechType = C.CKM_RSA_X_509
	MechanismMD2RSAPKCS                   MechType = C.CKM_MD2_RSA_PKCS
	MechanismMD5RSAPKCS                   MechType = C.CKM_MD5_RSA_PKCS
	MechanismSHA1RSAPKCS                  MechType = C.CKM_SHA1_RSA_PKCS
	MechanismRIPEMD128RSAPKCS             MechType = C.CKM_RIPEMD128_RSA_PKCS
	MechanismRIPEMD160RSAPKCS             MechType = C.CKM_RIPEMD160_RSA_PKCS
	MechanismRSAPKCSOAEP                  MechType = C.CKM_RSA_PKCS_OAEP
	MechanismRSAX9_31KeyPairGen           MechType = C.CKM_RSA_X9_31_KEY_PAIR_GEN
	MechanismRSAX9_31                     MechType = C.CKM_RSA_X9_31
	MechanismSHA1RSAX9_31                 MechType = C.CKM_SHA1_RSA_X9_31
	MechanismRSAPKCSPSS                   MechType = C.CKM_RSA_PKCS_PSS
	MechanismSHA1RSAPKCSPSS               MechType = C.CKM_SHA1_RSA_PKCS_PSS
	MechanismDSAKeyPairGen                MechType = C.CKM_DSA_KEY_PAIR_GEN
	MechanismDSA                          MechType = C.CKM_DSA
	MechanismDSASHA1                      MechType = C.CKM_DSA_SHA1
	MechanismDSASHA224                    MechType = C.CKM_DSA_SHA224
	MechanismDSASHA256                    MechType = C.CKM_DSA_SHA256
	MechanismDSASHA384                    MechType = C.CKM_DSA_SHA384
	MechanismDSASHA512                    MechType = C.CKM_DSA_SHA512
	MechanismDSASHA3_224                  MechType = C.CKM_DSA_SHA3_224
	MechanismDSASHA3_256                  MechType = C.CKM_DSA_SHA3_256
	MechanismDSASHA3_384                  MechType = C.CKM_DSA_SHA3_384
	MechanismDSASHA3_512                  MechType = C.CKM_DSA_SHA3_512
	MechanismDHPKCSKeyPairGen             MechType = C.CKM_DH_PKCS_KEY_PAIR_GEN
	MechanismDHPKCSDerive                 MechType = C.CKM_DH_PKCS_DERIVE
	MechanismX9_42DHKeyPairGen            MechType = C.CKM_X9_42_DH_KEY_PAIR_GEN
	MechanismX9_42DHDerive                MechType = C.CKM_X9_42_DH_DERIVE
	MechanismX9_42DHHybridDerive          MechType = C.CKM_X9_42_DH_HYBRID_DERIVE
	MechanismX9_42MQVDerive               MechType = C.CKM_X9_42_MQV_DERIVE
	MechanismSHA256RSAPKCS                MechType = C.CKM_SHA256_RSA_PKCS
	MechanismSHA384RSAPKCS                MechType = C.CKM_SHA384_RSA_PKCS
	MechanismSHA512RSAPKCS                MechType = C.CKM_SHA512_RSA_PKCS
	MechanismSHA256RSAPKCSPSS             MechType = C.CKM_SHA256_RSA_PKCS_PSS
	MechanismSHA384RSAPKCSPSS             MechType = C.CKM_SHA384_RSA_PKCS_PSS
	MechanismSHA512RSAPKCSPSS             MechType = C.CKM_SHA512_RSA_PKCS_PSS
	MechanismSHA224RSAPKCS                MechType = C.CKM_SHA224_RSA_PKCS
	MechanismSHA224RSAPKCSPSS             MechType = C.CKM_SHA224_RSA_PKCS_PSS
	MechanismSHA512224                    MechType = C.CKM_SHA512_224
	MechanismSHA512224HMAC                MechType = C.CKM_SHA512_224_HMAC
	MechanismSHA512224HMACGeneral         MechType = C.CKM_SHA512_224_HMAC_GENERAL
	MechanismSHA512224KeyDerivation       MechType = C.CKM_SHA512_224_KEY_DERIVATION
	MechanismSHA512256                    MechType = C.CKM_SHA512_256
	MechanismSHA512256HMAC                MechType = C.CKM_SHA512_256_HMAC
	MechanismSHA512256HMACGeneral         MechType = C.CKM_SHA512_256_HMAC_GENERAL
	MechanismSHA512256KeyDerivation       MechType = C.CKM_SHA512_256_KEY_DERIVATION
	MechanismSHA512T                      MechType = C.CKM_SHA512_T
	MechanismSHA512THMAC                  MechType = C.CKM_SHA512_T_HMAC
	MechanismSHA512THMACGeneral           MechType = C.CKM_SHA512_T_HMAC_GENERAL
	MechanismSHA512TKeyDerivation         MechType = C.CKM_SHA512_T_KEY_DERIVATION
	MechanismSHA3_256RSAPKCS              MechType = C.CKM_SHA3_256_RSA_PKCS
	MechanismSHA3_384RSAPKCS              MechType = C.CKM_SHA3_384_RSA_PKCS
	MechanismSHA3_512RSAPKCS              MechType = C.CKM_SHA3_512_RSA_PKCS
	MechanismSHA3_256RSAPKCSPSS           MechType = C.CKM_SHA3_256_RSA_PKCS_PSS
	MechanismSHA3_384RSAPKCSPSS           MechType = C.CKM_SHA3_384_RSA_PKCS_PSS
	MechanismSHA3_512RSAPKCSPSS           MechType = C.CKM_SHA3_512_RSA_PKCS_PSS
	MechanismSHA3_224RSAPKCS              MechType = C.CKM_SHA3_224_RSA_PKCS
	MechanismSHA3_224RSAPKCSPSS           MechType = C.CKM_SHA3_224_RSA_PKCS_PSS
	MechanismRC2KeyGen                    MechType = C.CKM_RC2_KEY_GEN
	MechanismRC2ECB                       MechType = C.CKM_RC2_ECB
	MechanismRC2CBC                       MechType = C.CKM_RC2_CBC
	MechanismRC2MAC                       MechType = C.CKM_RC2_MAC
	MechanismRC2MACGeneral                MechType = C.CKM_RC2_MAC_GENERAL
	MechanismRC2CBCPad                    MechType = C.CKM_RC2_CBC_PAD
	MechanismRC4KeyGen                    MechType = C.CKM_RC4_KEY_GEN
	MechanismRC4                          MechType = C.CKM_RC4
	MechanismDESKeyGen                    MechType = C.CKM_DES_KEY_GEN
	MechanismDESECB                       MechType = C.CKM_DES_ECB
	MechanismDESCBC                       MechType = C.CKM_DES_CBC
	MechanismDESMAC                       MechType = C.CKM_DES_MAC
	MechanismDESMACGeneral                MechType = C.CKM_DES_MAC_GENERAL
	MechanismDESCBCPad                    MechType = C.CKM_DES_CBC_PAD
	MechanismDES2KeyGen                   MechType = C.CKM_DES2_KEY_GEN
	MechanismDES3KeyGen                   MechType = C.CKM_DES3_KEY_GEN
	MechanismDES3ECB                      MechType = C.CKM_DES3_ECB
	MechanismDES3CBC                      MechType = C.CKM_DES3_CBC
	MechanismDES3MAC                      MechType = C.CKM_DES3_MAC
	MechanismDES3MACGeneral               MechType = C.CKM_DES3_MAC_GENERAL
	MechanismDES3CBCPad                   MechType = C.CKM_DES3_CBC_PAD
	MechanismDES3CMACGeneral              MechType = C.CKM_DES3_CMAC_GENERAL
	MechanismDES3CMAC                     MechType = C.CKM_DES3_CMAC
	MechanismCDMFKeyGen                   MechType = C.CKM_CDMF_KEY_GEN
	MechanismCDMFECB                      MechType = C.CKM_CDMF_ECB
	MechanismCDMFCBC                      MechType = C.CKM_CDMF_CBC
	MechanismCDMFMAC                      MechType = C.CKM_CDMF_MAC
	MechanismCDMFMACGeneral               MechType = C.CKM_CDMF_MAC_GENERAL
	MechanismCDMFCBCPad                   MechType = C.CKM_CDMF_CBC_PAD
	MechanismDESOFB64                     MechType = C.CKM_DES_OFB64
	MechanismDESOFB8                      MechType = C.CKM_DES_OFB8
	MechanismDESCFB64                     MechType = C.CKM_DES_CFB64
	MechanismDESCFB8                      MechType = C.CKM_DES_CFB8
	MechanismMD2                          MechType = C.CKM_MD2
	MechanismMD2HMAC                      MechType = C.CKM_MD2_HMAC
	MechanismMD2HMACGeneral               MechType = C.CKM_MD2_HMAC_GENERAL
	MechanismMD5                          MechType = C.CKM_MD5
	MechanismMD5HMAC                      MechType = C.CKM_MD5_HMAC
	MechanismMD5HMACGeneral               MechType = C.CKM_MD5_HMAC_GENERAL
	MechanismSHA1                         MechType = C.CKM_SHA_1
	MechanismSHA1HMAC                     MechType = C.CKM_SHA_1_HMAC
	MechanismSHA1HMACGeneral              MechType = C.CKM_SHA_1_HMAC_GENERAL
	MechanismRIPEMD128                    MechType = C.CKM_RIPEMD128
	MechanismRIPEMD128HMAC                MechType = C.CKM_RIPEMD128_HMAC
	MechanismRIPEMD128HMACGeneral         MechType = C.CKM_RIPEMD128_HMAC_GENERAL
	MechanismRIPEMD160                    MechType = C.CKM_RIPEMD160
	MechanismRIPEMD160HMAC                MechType = C.CKM_RIPEMD160_HMAC
	MechanismRIPEMD160HMACGeneral         MechType = C.CKM_RIPEMD160_HMAC_GENERAL
	MechanismSHA256                       MechType = C.CKM_SHA256
	MechanismSHA256HMAC                   MechType = C.CKM_SHA256_HMAC
	MechanismSHA256HMACGeneral            MechType = C.CKM_SHA256_HMAC_GENERAL
	MechanismSHA224                       MechType = C.CKM_SHA224
	MechanismSHA224HMAC                   MechType = C.CKM_SHA224_HMAC
	MechanismSHA224HMACGeneral            MechType = C.CKM_SHA224_HMAC_GENERAL
	MechanismSHA384                       MechType = C.CKM_SHA384
	MechanismSHA384HMAC                   MechType = C.CKM_SHA384_HMAC
	MechanismSHA384HMACGeneral            MechType = C.CKM_SHA384_HMAC_GENERAL
	MechanismSHA512                       MechType = C.CKM_SHA512
	MechanismSHA512HMAC                   MechType = C.CKM_SHA512_HMAC
	MechanismSHA512HMACGeneral            MechType = C.CKM_SHA512_HMAC_GENERAL
	MechanismSecurIDKeyGen                MechType = C.CKM_SECURID_KEY_GEN
	MechanismSecurID                      MechType = C.CKM_SECURID
	MechanismHOTPKeyGen                   MechType = C.CKM_HOTP_KEY_GEN
	MechanismHOTP                         MechType = C.CKM_HOTP
	MechanismACTI                         MechType = C.CKM_ACTI
	MechanismACTIKeyGen                   MechType = C.CKM_ACTI_KEY_GEN
	MechanismSHA3_256                     MechType = C.CKM_SHA3_256
	MechanismSHA3_256HMAC                 MechType = C.CKM_SHA3_256_HMAC
	MechanismSHA3_256HMACGeneral          MechType = C.CKM_SHA3_256_HMAC_GENERAL
	MechanismSHA3_256KeyGen               MechType = C.CKM_SHA3_256_KEY_GEN
	MechanismSHA3_224                     MechType = C.CKM_SHA3_224
	MechanismSHA3_224HMAC                 MechType = C.CKM_SHA3_224_HMAC
	MechanismSHA3_224HMACGeneral          MechType = C.CKM_SHA3_224_HMAC_GENERAL
	MechanismSHA3_224KeyGen               MechType = C.CKM_SHA3_224_KEY_GEN
	MechanismSHA3_384                     MechType = C.CKM_SHA3_384
	MechanismSHA3_384HMAC                 MechType = C.CKM_SHA3_384_HMAC
	MechanismSHA3_384HMACGeneral          MechType = C.CKM_SHA3_384_HMAC_GENERAL
	MechanismSHA3_384KeyGen               MechType = C.CKM_SHA3_384_KEY_GEN
	MechanismSHA3_512                     MechType = C.CKM_SHA3_512
	MechanismSHA3_512HMAC                 MechType = C.CKM_SHA3_512_HMAC
	MechanismSHA3_512HMACGeneral          MechType = C.CKM_SHA3_512_HMAC_GENERAL
	MechanismSHA3_512KeyGen               MechType = C.CKM_SHA3_512_KEY_GEN
	MechanismCASTKeyGen                   MechType = C.CKM_CAST_KEY_GEN
	MechanismCASTECB                      MechType = C.CKM_CAST_ECB
	MechanismCASTCBC                      MechType = C.CKM_CAST_CBC
	MechanismCASTMAC                      MechType = C.CKM_CAST_MAC
	MechanismCASTMACGeneral               MechType = C.CKM_CAST_MAC_GENERAL
	MechanismCASTCBCPad                   MechType = C.CKM_CAST_CBC_PAD
	MechanismCAST3KeyGen                  MechType = C.CKM_CAST3_KEY_GEN
	MechanismCAST3ECB                     MechType = C.CKM_CAST3_ECB
	MechanismCAST3CBC                     MechType = C.CKM_CAST3_CBC
	MechanismCAST3MAC                     MechType = C.CKM_CAST3_MAC
	MechanismCAST3MACGeneral              MechType = C.CKM_CAST3_MAC_GENERAL
	MechanismCAST3CBCPad                  MechType = C.CKM_CAST3_CBC_PAD
	MechanismCAST128KeyGen                MechType = C.CKM_CAST128_KEY_GEN
	MechanismCAST128ECB                   MechType = C.CKM_CAST128_ECB
	MechanismCAST128CBC                   MechType = C.CKM_CAST128_CBC
	MechanismCAST128MAC                   MechType = C.CKM_CAST128_MAC
	MechanismCAST128MACGeneral            MechType = C.CKM_CAST128_MAC_GENERAL
	MechanismCAST128CBCPad                MechType = C.CKM_CAST128_CBC_PAD
	MechanismRC5KeyGen                    MechType = C.CKM_RC5_KEY_GEN
	MechanismRC5ECB                       MechType = C.CKM_RC5_ECB
	MechanismRC5CBC                       MechType = C.CKM_RC5_CBC
	MechanismRC5MAC                       MechType = C.CKM_RC5_MAC
	MechanismRC5MACGeneral                MechType = C.CKM_RC5_MAC_GENERAL
	MechanismRC5CBCPad                    MechType = C.CKM_RC5_CBC_PAD
	MechanismIDEAKeyGen                   MechType = C.CKM_IDEA_KEY_GEN
	MechanismIDEAECB                      MechType = C.CKM_IDEA_ECB
	MechanismIDEACBC                      MechType = C.CKM_IDEA_CBC
	MechanismIDEAMAC                      MechType = C.CKM_IDEA_MAC
	MechanismIDEAMACGeneral               MechType = C.CKM_IDEA_MAC_GENERAL
	MechanismIDEACBCPad                   MechType = C.CKM_IDEA_CBC_PAD
	MechanismGenericSecretKeyGen          MechType = C.CKM_GENERIC_SECRET_KEY_GEN
	MechanismConcatenateBaseAndKey        MechType = C.CKM_CONCATENATE_BASE_AND_KEY
	MechanismConcatenateBaseAndData       MechType = C.CKM_CONCATENATE_BASE_AND_DATA
	MechanismConcatenateDataAndBase       MechType = C.CKM_CONCATENATE_DATA_AND_BASE
	MechanismXorBaseAndData               MechType = C.CKM_XOR_BASE_AND_DATA
	MechanismExtractKeyFromKey            MechType = C.CKM_EXTRACT_KEY_FROM_KEY
	MechanismSSL3PreMasterKeyGen          MechType = C.CKM_SSL3_PRE_MASTER_KEY_GEN
	MechanismSSL3MasterKeyDerive          MechType = C.CKM_SSL3_MASTER_KEY_DERIVE
	MechanismSSL3KeyAndMACDerive          MechType = C.CKM_SSL3_KEY_AND_MAC_DERIVE
	MechanismSSL3MasterKeyDeriveDH        MechType = C.CKM_SSL3_MASTER_KEY_DERIVE_DH
	MechanismTLSPreMasterKeyGen           MechType = C.CKM_TLS_PRE_MASTER_KEY_GEN
	MechanismTLSMasterKeyDerive           MechType = C.CKM_TLS_MASTER_KEY_DERIVE
	MechanismTLSKeyAndMACDerive           MechType = C.CKM_TLS_KEY_AND_MAC_DERIVE
	MechanismTLSMasterKeyDeriveDH         MechType = C.CKM_TLS_MASTER_KEY_DERIVE_DH
	MechanismTLSPRF                       MechType = C.CKM_TLS_PRF
	MechanismSSL3MD5MAC                   MechType = C.CKM_SSL3_MD5_MAC
	MechanismSSL3SHA1MAC                  MechType = C.CKM_SSL3_SHA1_MAC
	MechanismMD5KeyDerivation             MechType = C.CKM_MD5_KEY_DERIVATION
	MechanismMD2KeyDerivation             MechType = C.CKM_MD2_KEY_DERIVATION
	MechanismSHA1KeyDerivation            MechType = C.CKM_SHA1_KEY_DERIVATION
	MechanismSHA256KeyDerivation          MechType = C.CKM_SHA256_KEY_DERIVATION
	MechanismSHA384KeyDerivation          MechType = C.CKM_SHA384_KEY_DERIVATION
	MechanismSHA512KeyDerivation          MechType = C.CKM_SHA512_KEY_DERIVATION
	MechanismSHA224KeyDerivation          MechType = C.CKM_SHA224_KEY_DERIVATION
	MechanismSHA3_256KeyDerivation        MechType = C.CKM_SHA3_256_KEY_DERIVATION
	MechanismSHA3_224KeyDerivation        MechType = C.CKM_SHA3_224_KEY_DERIVATION
	MechanismSHA3_384KeyDerivation        MechType = C.CKM_SHA3_384_KEY_DERIVATION
	MechanismSHA3_512KeyDerivation        MechType = C.CKM_SHA3_512_KEY_DERIVATION
	MechanismSHAKE128KeyDerivation        MechType = C.CKM_SHAKE_128_KEY_DERIVATION
	MechanismSHAKE256KeyDerivation        MechType = C.CKM_SHAKE_256_KEY_DERIVATION
	MechanismPBEMD2DESCBC                 MechType = C.CKM_PBE_MD2_DES_CBC
	MechanismPBEMD5DESCBC                 MechType = C.CKM_PBE_MD5_DES_CBC
	MechanismPBEMD5CASTCBC                MechType = C.CKM_PBE_MD5_CAST_CBC
	MechanismPBEMD5CAST3CBC               MechType = C.CKM_PBE_MD5_CAST3_CBC
	MechanismPBEMD5CAST128CBC             MechType = C.CKM_PBE_MD5_CAST128_CBC
	MechanismPBESHA1CAST128CBC            MechType = C.CKM_PBE_SHA1_CAST128_CBC
	MechanismPBESHA1RC4_128               MechType = C.CKM_PBE_SHA1_RC4_128
	MechanismPBESHA1RC4_40                MechType = C.CKM_PBE_SHA1_RC4_40
	MechanismPBESHA1DES3EDECBC            MechType = C.CKM_PBE_SHA1_DES3_EDE_CBC
	MechanismPBESHA1DES2EDECBC            MechType = C.CKM_PBE_SHA1_DES2_EDE_CBC
	MechanismPBESHA1RC2_128CBC            MechType = C.CKM_PBE_SHA1_RC2_128_CBC
	MechanismPBESHA1RC2_40CBC             MechType = C.CKM_PBE_SHA1_RC2_40_CBC
	MechanismPKCS5PBKD2                   MechType = C.CKM_PKCS5_PBKD2
	MechanismPBASHA1WithSHA1HMAC          MechType = C.CKM_PBA_SHA1_WITH_SHA1_HMAC
	MechanismWTLSPreMasterKeyGen          MechType = C.CKM_WTLS_PRE_MASTER_KEY_GEN
	MechanismWTLSMasterKeyDerive          MechType = C.CKM_WTLS_MASTER_KEY_DERIVE
	MechanismWTLSMasterKeyDeriveDHECC     MechType = C.CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC
	MechanismWTLSPRF                      MechType = C.CKM_WTLS_PRF
	MechanismWTLSServerKeyAndMACDerive    MechType = C.CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE
	MechanismWTLSClientKeyAndMACDerive    MechType = C.CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE
	MechanismTLS10MACServer               MechType = C.CKM_TLS10_MAC_SERVER
	MechanismTLS10MACClient               MechType = C.CKM_TLS10_MAC_CLIENT
	MechanismTLS12MAC                     MechType = C.CKM_TLS12_MAC
	MechanismTLS12KDF                     MechType = C.CKM_TLS12_KDF
	MechanismTLS12MasterKeyDerive         MechType = C.CKM_TLS12_MASTER_KEY_DERIVE
	MechanismTLS12KeyAndMACDerive         MechType = C.CKM_TLS12_KEY_AND_MAC_DERIVE
	MechanismTLS12MasterKeyDeriveDH       MechType = C.CKM_TLS12_MASTER_KEY_DERIVE_DH
	MechanismTLS12KeySafeDerive           MechType = C.CKM_TLS12_KEY_SAFE_DERIVE
	MechanismTLSMAC                       MechType = C.CKM_TLS_MAC
	MechanismTLSKDF                       MechType = C.CKM_TLS_KDF
	MechanismKeyWrapLYNKS                 MechType = C.CKM_KEY_WRAP_LYNKS
	MechanismKeyWrapSetOAEP               MechType = C.CKM_KEY_WRAP_SET_OAEP
	MechanismCMSSIG                       MechType = C.CKM_CMS_SIG
	MechanismKIPDerive                    MechType = C.CKM_KIP_DERIVE
	MechanismKIPWrap                      MechType = C.CKM_KIP_WRAP
	MechanismKIPMAC                       MechType = C.CKM_KIP_MAC
	MechanismCamelliaKeyGen               MechType = C.CKM_CAMELLIA_KEY_GEN
	MechanismCamelliaECB                  MechType = C.CKM_CAMELLIA_ECB
	MechanismCamelliaCBC                  MechType = C.CKM_CAMELLIA_CBC
	MechanismCamelliaMAC                  MechType = C.CKM_CAMELLIA_MAC
	MechanismCamelliaMACGeneral           MechType = C.CKM_CAMELLIA_MAC_GENERAL
	MechanismCamelliaCBCPad               MechType = C.CKM_CAMELLIA_CBC_PAD
	MechanismCamelliaECBEncryptData       MechType = C.CKM_CAMELLIA_ECB_ENCRYPT_DATA
	MechanismCamelliaCBCEncryptData       MechType = C.CKM_CAMELLIA_CBC_ENCRYPT_DATA
	MechanismCamelliaCTR                  MechType = C.CKM_CAMELLIA_CTR
	MechanismARIAKeyGen                   MechType = C.CKM_ARIA_KEY_GEN
	MechanismARIAECB                      MechType = C.CKM_ARIA_ECB
	MechanismARIACBC                      MechType = C.CKM_ARIA_CBC
	MechanismARIAMAC                      MechType = C.CKM_ARIA_MAC
	MechanismARIAMACGeneral               MechType = C.CKM_ARIA_MAC_GENERAL
	MechanismARIACBCPad                   MechType = C.CKM_ARIA_CBC_PAD
	MechanismARIAECBEncryptData           MechType = C.CKM_ARIA_ECB_ENCRYPT_DATA
	MechanismARIACBCEncryptData           MechType = C.CKM_ARIA_CBC_ENCRYPT_DATA
	MechanismSeedKeyGen                   MechType = C.CKM_SEED_KEY_GEN
	MechanismSeedECB                      MechType = C.CKM_SEED_ECB
	MechanismSeedCBC                      MechType = C.CKM_SEED_CBC
	MechanismSeedMAC                      MechType = C.CKM_SEED_MAC
	MechanismSeedMACGeneral               MechType = C.CKM_SEED_MAC_GENERAL
	MechanismSeedCBCPad                   MechType = C.CKM_SEED_CBC_PAD
	MechanismSeedECBEncryptData           MechType = C.CKM_SEED_ECB_ENCRYPT_DATA
	MechanismSeedCBCEncryptData           MechType = C.CKM_SEED_CBC_ENCRYPT_DATA
	MechanismSkipjackKeyGen               MechType = C.CKM_SKIPJACK_KEY_GEN
	MechanismSkipjackECB64                MechType = C.CKM_SKIPJACK_ECB64
	MechanismSkipjackCBC64                MechType = C.CKM_SKIPJACK_CBC64
	MechanismSkipjackOFB64                MechType = C.CKM_SKIPJACK_OFB64
	MechanismSkipjackCFB64                MechType = C.CKM_SKIPJACK_CFB64
	MechanismSkipjackCFB32                MechType = C.CKM_SKIPJACK_CFB32
	MechanismSkipjackCFB16                MechType = C.CKM_SKIPJACK_CFB16
	MechanismSkipjackCFB8                 MechType = C.CKM_SKIPJACK_CFB8
	MechanismSkipjackWrap                 MechType = C.CKM_SKIPJACK_WRAP
	MechanismSkipjackPrivateWrap          MechType = C.CKM_SKIPJACK_PRIVATE_WRAP
	MechanismSkipjackRelayx               MechType = C.CKM_SKIPJACK_RELAYX
	MechanismKEAKeyPairGen                MechType = C.CKM_KEA_KEY_PAIR_GEN
	MechanismKEAKeyDerive                 MechType = C.CKM_KEA_KEY_DERIVE
	MechanismKEADerive                    MechType = C.CKM_KEA_DERIVE
	MechanismFortezzaTimestamp            MechType = C.CKM_FORTEZZA_TIMESTAMP
	MechanismBATONKeyGen                  MechType = C.CKM_BATON_KEY_GEN
	MechanismBATONECB128                  MechType = C.CKM_BATON_ECB128
	MechanismBATONECB96                   MechType = C.CKM_BATON_ECB96
	MechanismBATONCBC128                  MechType = C.CKM_BATON_CBC128
	MechanismBATONCounter                 MechType = C.CKM_BATON_COUNTER
	MechanismBATONShuffle                 MechType = C.CKM_BATON_SHUFFLE
	MechanismBATONWrap                    MechType = C.CKM_BATON_WRAP
	MechanismECKeyPairGen                 MechType = C.CKM_EC_KEY_PAIR_GEN
	MechanismECDSA                        MechType = C.CKM_ECDSA
	MechanismECDSASHA1                    MechType = C.CKM_ECDSA_SHA1
	MechanismECDSASHA224                  MechType = C.CKM_ECDSA_SHA224
	MechanismECDSASHA256                  MechType = C.CKM_ECDSA_SHA256
	MechanismECDSASHA384                  MechType = C.CKM_ECDSA_SHA384
	MechanismECDSASHA512                  MechType = C.CKM_ECDSA_SHA512
	MechanismECKeyPairGenWExtraBits       MechType = C.CKM_EC_KEY_PAIR_GEN_W_EXTRA_BITS
	MechanismECDH1Derive                  MechType = C.CKM_ECDH1_DERIVE
	MechanismECDH1CofactorDerive          MechType = C.CKM_ECDH1_COFACTOR_DERIVE
	MechanismECMQVDerive                  MechType = C.CKM_ECMQV_DERIVE
	MechanismECDHAESKeyWrap               MechType = C.CKM_ECDH_AES_KEY_WRAP
	MechanismRSAAESKeyWrap                MechType = C.CKM_RSA_AES_KEY_WRAP
	MechanismJuniperKeyGen                MechType = C.CKM_JUNIPER_KEY_GEN
	MechanismJuniperECB128                MechType = C.CKM_JUNIPER_ECB128
	MechanismJuniperCBC128                MechType = C.CKM_JUNIPER_CBC128
	MechanismJuniperCounter               MechType = C.CKM_JUNIPER_COUNTER
	MechanismJuniperShuffle               MechType = C.CKM_JUNIPER_SHUFFLE
	MechanismJuniperWrap                  MechType = C.CKM_JUNIPER_WRAP
	MechanismFasthash                     MechType = C.CKM_FASTHASH
	MechanismAESXTS                       MechType = C.CKM_AES_XTS
	MechanismAESXTSKeyGen                 MechType = C.CKM_AES_XTS_KEY_GEN
	MechanismAESKeyGen                    MechType = C.CKM_AES_KEY_GEN
	MechanismAESECB                       MechType = C.CKM_AES_ECB
	MechanismAESCBC                       MechType = C.CKM_AES_CBC
	MechanismAESMAC                       MechType = C.CKM_AES_MAC
	MechanismAESMACGeneral                MechType = C.CKM_AES_MAC_GENERAL
	MechanismAESCBCPad                    MechType = C.CKM_AES_CBC_PAD
	MechanismAESCTR                       MechType = C.CKM_AES_CTR
	MechanismAESGCM                       MechType = C.CKM_AES_GCM
	MechanismAESCCM                       MechType = C.CKM_AES_CCM
	MechanismAESCTS                       MechType = C.CKM_AES_CTS
	MechanismAESCMAC                      MechType = C.CKM_AES_CMAC
	MechanismAESCMACGeneral               MechType = C.CKM_AES_CMAC_GENERAL
	MechanismAESXCBCMAC                   MechType = C.CKM_AES_XCBC_MAC
	MechanismAESXCBCMAC96                 MechType = C.CKM_AES_XCBC_MAC_96
	MechanismAESGMAC                      MechType = C.CKM_AES_GMAC
	MechanismBlowfishKeyGen               MechType = C.CKM_BLOWFISH_KEY_GEN
	MechanismBlowfishCBC                  MechType = C.CKM_BLOWFISH_CBC
	MechanismTwofishKeyGen                MechType = C.CKM_TWOFISH_KEY_GEN
	MechanismTwofishCBC                   MechType = C.CKM_TWOFISH_CBC
	MechanismBlowfishCBCPad               MechType = C.CKM_BLOWFISH_CBC_PAD
	MechanismTwofishCBCPad                MechType = C.CKM_TWOFISH_CBC_PAD
	MechanismDESECBEncryptData            MechType = C.CKM_DES_ECB_ENCRYPT_DATA
	MechanismDESCBCEncryptData            MechType = C.CKM_DES_CBC_ENCRYPT_DATA
	MechanismDES3ECBEncryptData           MechType = C.CKM_DES3_ECB_ENCRYPT_DATA
	MechanismDES3CBCEncryptData           MechType = C.CKM_DES3_CBC_ENCRYPT_DATA
	MechanismAESECBEncryptData            MechType = C.CKM_AES_ECB_ENCRYPT_DATA
	MechanismAESCBCEncryptData            MechType = C.CKM_AES_CBC_ENCRYPT_DATA
	MechanismGOSTR3410KeyPairGen          MechType = C.CKM_GOSTR3410_KEY_PAIR_GEN
	MechanismGOSTR3410                    MechType = C.CKM_GOSTR3410
	MechanismGOSTR3410WithGOSTR3411       MechType = C.CKM_GOSTR3410_WITH_GOSTR3411
	MechanismGOSTR3410KeyWrap             MechType = C.CKM_GOSTR3410_KEY_WRAP
	MechanismGOSTR3410Derive              MechType = C.CKM_GOSTR3410_DERIVE
	MechanismGOSTR3411                    MechType = C.CKM_GOSTR3411
	MechanismGOSTR3411HMAC                MechType = C.CKM_GOSTR3411_HMAC
	MechanismGOST28147KeyGen              MechType = C.CKM_GOST28147_KEY_GEN
	MechanismGOST28147ECB                 MechType = C.CKM_GOST28147_ECB
	MechanismGOST28147                    MechType = C.CKM_GOST28147
	MechanismGOST28147MAC                 MechType = C.CKM_GOST28147_MAC
	MechanismGOST28147KeyWrap             MechType = C.CKM_GOST28147_KEY_WRAP
	MechanismChaCha20KeyGen               MechType = C.CKM_CHACHA20_KEY_GEN
	MechanismChaCha20                     MechType = C.CKM_CHACHA20
	MechanismPoly1305KeyGen               MechType = C.CKM_POLY1305_KEY_GEN
	MechanismPoly1305                     MechType = C.CKM_POLY1305
	MechanismDSAParameterGen              MechType = C.CKM_DSA_PARAMETER_GEN
	MechanismDHPKCSParameterGen           MechType = C.CKM_DH_PKCS_PARAMETER_GEN
	MechanismX9_42DHParameterGen          MechType = C.CKM_X9_42_DH_PARAMETER_GEN
	MechanismDSAProbabilisticParameterGen MechType = C.CKM_DSA_PROBABILISTIC_PARAMETER_GEN
	MechanismDSAShaweTaylorParameterGen   MechType = C.CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN
	MechanismDSAFIPSGGen                  MechType = C.CKM_DSA_FIPS_G_GEN
	MechanismAESOFB                       MechType = C.CKM_AES_OFB
	MechanismAESCFB64                     MechType = C.CKM_AES_CFB64
	MechanismAESCFB8                      MechType = C.CKM_AES_CFB8
	MechanismAESCFB128                    MechType = C.CKM_AES_CFB128
	MechanismAESCFB1                      MechType = C.CKM_AES_CFB1
	MechanismAESKeyWrap                   MechType = C.CKM_AES_KEY_WRAP
	MechanismAESKeyWrapPad                MechType = C.CKM_AES_KEY_WRAP_PAD
	MechanismAESKeyWrapKWP                MechType = C.CKM_AES_KEY_WRAP_KWP
	MechanismAESKeyWrapPKCS7              MechType = C.CKM_AES_KEY_WRAP_PKCS7
	MechanismRSAPKCSTPM1_1                MechType = C.CKM_RSA_PKCS_TPM_1_1
	MechanismRSAPKCSOAEPTPM1_1            MechType = C.CKM_RSA_PKCS_OAEP_TPM_1_1
	MechanismSHA1KeyGen                   MechType = C.CKM_SHA_1_KEY_GEN
	MechanismSHA224KeyGen                 MechType = C.CKM_SHA224_KEY_GEN
	MechanismSHA256KeyGen                 MechType = C.CKM_SHA256_KEY_GEN
	MechanismSHA384KeyGen                 MechType = C.CKM_SHA384_KEY_GEN
	MechanismSHA512KeyGen                 MechType = C.CKM_SHA512_KEY_GEN
	MechanismSHA512_224KeyGen             MechType = C.CKM_SHA512_224_KEY_GEN
	MechanismSHA512_256KeyGen             MechType = C.CKM_SHA512_256_KEY_GEN
	MechanismSHA512TKeyGen                MechType = C.CKM_SHA512_T_KEY_GEN
	MechanismNull                         MechType = C.CKM_NULL
	MechanismBLAKE2b160                   MechType = C.CKM_BLAKE2B_160
	MechanismBLAKE2b160HMAC               MechType = C.CKM_BLAKE2B_160_HMAC
	MechanismBLAKE2b160HMACGeneral        MechType = C.CKM_BLAKE2B_160_HMAC_GENERAL
	MechanismBLAKE2b160KeyDerive          MechType = C.CKM_BLAKE2B_160_KEY_DERIVE
	MechanismBLAKE2b160KeyGen             MechType = C.CKM_BLAKE2B_160_KEY_GEN
	MechanismBLAKE2b256                   MechType = C.CKM_BLAKE2B_256
	MechanismBLAKE2b256HMAC               MechType = C.CKM_BLAKE2B_256_HMAC
	MechanismBLAKE2b256HMACGeneral        MechType = C.CKM_BLAKE2B_256_HMAC_GENERAL
	MechanismBLAKE2b256KeyDerive          MechType = C.CKM_BLAKE2B_256_KEY_DERIVE
	MechanismBLAKE2b256KeyGen             MechType = C.CKM_BLAKE2B_256_KEY_GEN
	MechanismBLAKE2b384                   MechType = C.CKM_BLAKE2B_384
	MechanismBLAKE2b384HMAC               MechType = C.CKM_BLAKE2B_384_HMAC
	MechanismBLAKE2b384HMACGeneral        MechType = C.CKM_BLAKE2B_384_HMAC_GENERAL
	MechanismBLAKE2b384KeyDerive          MechType = C.CKM_BLAKE2B_384_KEY_DERIVE
	MechanismBLAKE2b384KeyGen             MechType = C.CKM_BLAKE2B_384_KEY_GEN
	MechanismBLAKE2b512                   MechType = C.CKM_BLAKE2B_512
	MechanismBLAKE2b512HMAC               MechType = C.CKM_BLAKE2B_512_HMAC
	MechanismBLAKE2b512HMACGeneral        MechType = C.CKM_BLAKE2B_512_HMAC_GENERAL
	MechanismBLAKE2b512KeyDerive          MechType = C.CKM_BLAKE2B_512_KEY_DERIVE
	MechanismBLAKE2b512KeyGen             MechType = C.CKM_BLAKE2B_512_KEY_GEN
	MechanismSalsa20                      MechType = C.CKM_SALSA20
	MechanismChacha20Poly1305             MechType = C.CKM_CHACHA20_POLY1305
	MechanismSalsa20Poly1305              MechType = C.CKM_SALSA20_POLY1305
	MechanismX3DHInitialize               MechType = C.CKM_X3DH_INITIALIZE
	MechanismX3DHRespond                  MechType = C.CKM_X3DH_RESPOND
	MechanismX2RatchetInitialize          MechType = C.CKM_X2RATCHET_INITIALIZE
	MechanismX2RatchetRespond             MechType = C.CKM_X2RATCHET_RESPOND
	MechanismX2RatchetEncrypt             MechType = C.CKM_X2RATCHET_ENCRYPT
	MechanismX2RatchetDecrypt             MechType = C.CKM_X2RATCHET_DECRYPT
	MechanismXEDDSA                       MechType = C.CKM_XEDDSA
	MechanismHKDFDerive                   MechType = C.CKM_HKDF_DERIVE
	MechanismHKDFData                     MechType = C.CKM_HKDF_DATA
	MechanismHKDFKeyGen                   MechType = C.CKM_HKDF_KEY_GEN
	MechanismSalsa20KeyGen                MechType = C.CKM_SALSA20_KEY_GEN
	MechanismECDSASHA3_224                MechType = C.CKM_ECDSA_SHA3_224
	MechanismECDSASHA3_256                MechType = C.CKM_ECDSA_SHA3_256
	MechanismECDSASHA3_384                MechType = C.CKM_ECDSA_SHA3_384
	MechanismECDSASHA3_512                MechType = C.CKM_ECDSA_SHA3_512
	MechanismECEdwardsKeyPairGen          MechType = C.CKM_EC_EDWARDS_KEY_PAIR_GEN
	MechanismECMontgomeryKeyPairGen       MechType = C.CKM_EC_MONTGOMERY_KEY_PAIR_GEN
	MechanismEDDSA                        MechType = C.CKM_EDDSA
	MechanismSP800_108CounterKDF          MechType = C.CKM_SP800_108_COUNTER_KDF
	MechanismSP800_108FeedbackKDF         MechType = C.CKM_SP800_108_FEEDBACK_KDF
	MechanismSP800_108DoublePipelineKDF   MechType = C.CKM_SP800_108_DOUBLE_PIPELINE_KDF
	MechanismIKE2PRFPlusDerive            MechType = C.CKM_IKE2_PRF_PLUS_DERIVE
	MechanismIKEPRFDerive                 MechType = C.CKM_IKE_PRF_DERIVE
	MechanismIKE1PRFDerive                MechType = C.CKM_IKE1_PRF_DERIVE
	MechanismIKE1ExtendedDerive           MechType = C.CKM_IKE1_EXTENDED_DERIVE
	MechanismHSSKeyPairGen                MechType = C.CKM_HSS_KEY_PAIR_GEN
	MechanismHSS                          MechType = C.CKM_HSS
	MechanismVendorDefined                MechType = C.CKM_VENDOR_DEFINED
)

var mechStr = map[MechType]string{
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

func (m MechType) String() string {
	if s, ok := mechStr[m]; ok {
		return s
	}
	return fmt.Sprintf("MechanismType(0x%08x)", uint(m))
}

// ObjectClass is the primary object type. Such as a certificate, public key, or private key.
type ObjectClass C.CK_OBJECT_CLASS

// Set of classes supported by this package.
const (
	ClassData             ObjectClass = C.CKO_DATA
	ClassCertificate      ObjectClass = C.CKO_CERTIFICATE
	ClassPublicKey        ObjectClass = C.CKO_PUBLIC_KEY
	ClassPrivateKey       ObjectClass = C.CKO_PRIVATE_KEY
	ClassSecretKey        ObjectClass = C.CKO_SECRET_KEY
	ClassHWFeature        ObjectClass = C.CKO_HW_FEATURE
	ClassDomainParameters ObjectClass = C.CKO_DOMAIN_PARAMETERS
	ClassMechanism        ObjectClass = C.CKO_MECHANISM
	ClassOTPKey           ObjectClass = C.CKO_OTP_KEY
	ClassProfile          ObjectClass = C.CKO_PROFILE
	ClassVendorDefined    ObjectClass = C.CKO_VENDOR_DEFINED
)

var classString = map[ObjectClass]string{
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
func (c ObjectClass) String() string {
	if s, ok := classString[c]; ok {
		return s
	}
	return fmt.Sprintf("Class(0x%08x)", uint(c))
}

type KType C.CK_KEY_TYPE

const (
	KeyRSA            KType = C.CKK_RSA
	KeyDSA            KType = C.CKK_DSA
	KeyDH             KType = C.CKK_DH
	KeyEC             KType = C.CKK_EC
	KeyX9_42DH        KType = C.CKK_X9_42_DH
	KeyKEA            KType = C.CKK_KEA
	KeyGenericSecret  KType = C.CKK_GENERIC_SECRET
	KeyRC2            KType = C.CKK_RC2
	KeyRC4            KType = C.CKK_RC4
	KeyDES            KType = C.CKK_DES
	KeyDES2           KType = C.CKK_DES2
	KeyDES3           KType = C.CKK_DES3
	KeyCAST           KType = C.CKK_CAST
	KeyCAST3          KType = C.CKK_CAST3
	KeyCAST128        KType = C.CKK_CAST128
	KeyRC5            KType = C.CKK_RC5
	KeyIDEA           KType = C.CKK_IDEA
	KeySkipjack       KType = C.CKK_SKIPJACK
	KeyBATON          KType = C.CKK_BATON
	KeyJuniper        KType = C.CKK_JUNIPER
	KeyCDMF           KType = C.CKK_CDMF
	KeyAES            KType = C.CKK_AES
	KeyBlowfish       KType = C.CKK_BLOWFISH
	KeyTwofish        KType = C.CKK_TWOFISH
	KeySecurID        KType = C.CKK_SECURID
	KeyHOTP           KType = C.CKK_HOTP
	KeyACTI           KType = C.CKK_ACTI
	KeyCamellia       KType = C.CKK_CAMELLIA
	KeyARIA           KType = C.CKK_ARIA
	KeyMD5HMAC        KType = C.CKK_MD5_HMAC
	KeySHA1HMAC       KType = C.CKK_SHA_1_HMAC
	KeyRIPEMD128HMAC  KType = C.CKK_RIPEMD128_HMAC
	KeyRIPEMD160HMAC  KType = C.CKK_RIPEMD160_HMAC
	KeySHA256HMAC     KType = C.CKK_SHA256_HMAC
	KeySHA384HMAC     KType = C.CKK_SHA384_HMAC
	KeySHA512HMAC     KType = C.CKK_SHA512_HMAC
	KeySHA224HMAC     KType = C.CKK_SHA224_HMAC
	KeySeed           KType = C.CKK_SEED
	KeyGOSTR3410      KType = C.CKK_GOSTR3410
	KeyGOSTR3411      KType = C.CKK_GOSTR3411
	KeyGOST28147      KType = C.CKK_GOST28147
	KeyChaCha20       KType = C.CKK_CHACHA20
	KeyPoly1305       KType = C.CKK_POLY1305
	KeyAESXTS         KType = C.CKK_AES_XTS
	KeySHA3_224HMAC   KType = C.CKK_SHA3_224_HMAC
	KeySHA3_256HMAC   KType = C.CKK_SHA3_256_HMAC
	KeySHA3_384HMAC   KType = C.CKK_SHA3_384_HMAC
	KeySHA3_512HMAC   KType = C.CKK_SHA3_512_HMAC
	KeyBLAKE2b160HMAC KType = C.CKK_BLAKE2B_160_HMAC
	KeyBLAKE2b256HMAC KType = C.CKK_BLAKE2B_256_HMAC
	KeyBLAKE2b384HMAC KType = C.CKK_BLAKE2B_384_HMAC
	KeyBLAKE2b512HMAC KType = C.CKK_BLAKE2B_512_HMAC
	KeySalsa20        KType = C.CKK_SALSA20
	KeyX2Ratchet      KType = C.CKK_X2RATCHET
	KeyECEdwards      KType = C.CKK_EC_EDWARDS
	KeyECMontgomery   KType = C.CKK_EC_MONTGOMERY
	KeyHKDF           KType = C.CKK_HKDF
	KeySHA512_224HMAC KType = C.CKK_SHA512_224_HMAC
	KeySHA512_256HMAC KType = C.CKK_SHA512_256_HMAC
	KeySHA512THMAC    KType = C.CKK_SHA512_T_HMAC
	KeyHSS            KType = C.CKK_HSS
	KeyVendorDefined  KType = C.CKK_VENDOR_DEFINED
)

var ktStr = map[KType]string{
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

func (k KType) String() string {
	if s, ok := ktStr[k]; ok {
		return s
	}
	return fmt.Sprintf("KeyType(0x%08x)", uint(k))
}

// CertType determines the kind of certificate a certificate object holds.
// This can be X.509, WTLS, GPG, etc.
//
// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#_Toc416959709
type CertType C.CK_CERTIFICATE_TYPE

// Certificate types supported by this package.
const (
	CertificateX509          CertType = C.CKC_X_509
	CertificateX509AttrCert  CertType = C.CKC_X_509_ATTR_CERT
	CertificateWTLS          CertType = C.CKC_WTLS
	CertificateVendorDefined CertType = C.CKC_VENDOR_DEFINED
)

func (t CertType) String() string {
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

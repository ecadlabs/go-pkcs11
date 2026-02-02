package main

import (
	"log"
	"os"
	"text/template"

	"github.com/ecadlabs/go-pkcs11/pkcs11/attr"
)

type desc struct {
	Name   string
	Member string
	Elem   string
}

var attributes = map[attr.Type]desc{
	attr.TypeToken:                   {"Token", "Bool", ""},
	attr.TypePrivate:                 {"Private", "Bool", ""},
	attr.TypeLabel:                   {"Label", "String", "byte"},
	attr.TypeUniqueID:                {"UniqueID", "String", "byte"},
	attr.TypeApplication:             {"Application", "String", "byte"},
	attr.TypeTrusted:                 {"Trusted", "Bool", ""},
	attr.TypeCertificateCategory:     {"CertificateCategory", "Uint", ""},
	attr.TypeJavaMIDPSecurityDomain:  {"JavaMIDPSecurityDomain", "Uint", ""},
	attr.TypeURL:                     {"URL", "String", "byte"},
	attr.TypeSensitive:               {"Sensitive", "Bool", ""},
	attr.TypeEncrypt:                 {"Encrypt", "Bool", ""},
	attr.TypeDecrypt:                 {"Decrypt", "Bool", ""},
	attr.TypeWrap:                    {"Wrap", "Bool", ""},
	attr.TypeUnwrap:                  {"Unwrap", "Bool", ""},
	attr.TypeSign:                    {"Sign", "Bool", ""},
	attr.TypeSignRecover:             {"SignRecover", "Bool", ""},
	attr.TypeVerify:                  {"Verify", "Bool", ""},
	attr.TypeVerifyRecover:           {"VerifyRecover", "Bool", ""},
	attr.TypeDerive:                  {"Derive", "Bool", ""},
	attr.TypeStartDate:               {"StartDate", "Date", ""},
	attr.TypeEndDate:                 {"EndDate", "Date", ""},
	attr.TypeModulus:                 {"Modulus", "BigInt", "byte"},
	attr.TypeModulusBits:             {"ModulusBits", "Uint", ""},
	attr.TypePublicExponent:          {"PublicExponent", "BigInt", "byte"},
	attr.TypePrivateExponent:         {"PrivateExponent", "BigInt", "byte"},
	attr.TypePrime_1:                 {"Prime_1", "BigInt", "byte"},
	attr.TypePrime_2:                 {"Prime_2", "BigInt", "byte"},
	attr.TypeExponent_1:              {"Exponent_1", "BigInt", "byte"},
	attr.TypeExponent_2:              {"Exponent_2", "BigInt", "byte"},
	attr.TypeCoefficient:             {"Coefficient", "BigInt", "byte"},
	attr.TypePrime:                   {"Prime", "BigInt", "byte"},
	attr.TypeSubprime:                {"Subprime", "BigInt", "byte"},
	attr.TypeBase:                    {"Base", "BigInt", "byte"},
	attr.TypePrimeBits:               {"PrimeBits", "Uint", ""},
	attr.TypeSubPrimeBits:            {"SubPrimeBits", "Uint", ""},
	attr.TypeValueBits:               {"ValueBits", "Uint", ""},
	attr.TypeValueLen:                {"ValueLen", "Uint", ""},
	attr.TypeExtractable:             {"Extractable", "Bool", ""},
	attr.TypeLocal:                   {"Local", "Bool", ""},
	attr.TypeNeverExtractable:        {"NeverExtractable", "Bool", ""},
	attr.TypeAlwaysSensitive:         {"AlwaysSensitive", "Bool", ""},
	attr.TypeModifiable:              {"Modifiable", "Bool", ""},
	attr.TypeCopyable:                {"Copyable", "Bool", ""},
	attr.TypeDestroyable:             {"Destroyable", "Bool", ""},
	attr.TypeAlwaysAuthenticate:      {"AlwaysAuthenticate", "Bool", ""},
	attr.TypeWrapWithTrusted:         {"WrapWithTrusted", "Bool", ""},
	attr.TypeOTPFormat:               {"OTPFormat", "Uint", ""},
	attr.TypeOTPLength:               {"OTPLength", "Uint", ""},
	attr.TypeOTPTimeInterval:         {"OTPTimeInterval", "Uint", ""},
	attr.TypeOTPUserFriendlyMode:     {"OTPUserFriendlyMode", "Bool", ""},
	attr.TypeOTPChallengeRequirement: {"OTPChallengeRequirement", "Uint", ""},
	attr.TypeOTPTimeRequirement:      {"OTPTimeRequirement", "Uint", ""},
	attr.TypeOTPCounterRequirement:   {"OTPCounterRequirement", "Uint", ""},
	attr.TypeOTPPinRequirement:       {"OTPPinRequirement", "Uint", ""},
	attr.TypeOTPTime:                 {"OTPTime", "String", "byte"},
	attr.TypeOTPUserIdentifier:       {"OTPUserIdentifier", "String", "byte"},
	attr.TypeOTPServiceIdentifier:    {"OTPServiceIdentifier", "String", "byte"},
	attr.TypeOTPServiceLogoType:      {"OTPServiceLogoType", "String", "byte"},
	attr.TypeHWFeatureType:           {"HWFeatureType", "Uint", ""},
	attr.TypeResetOnInit:             {"ResetOnInit", "Bool", ""},
	attr.TypeHasReset:                {"HasReset", "Bool", ""},
	attr.TypePixelX:                  {"PixelX", "Uint", ""},
	attr.TypePixelY:                  {"PixelY", "Uint", ""},
	attr.TypeResolution:              {"Resolution", "Uint", ""},
	attr.TypeCharRows:                {"CharRows", "Uint", ""},
	attr.TypeCharColumns:             {"CharColumns", "Uint", ""},
	attr.TypeColor:                   {"Color", "Bool", ""},
	attr.TypeBitsPerPixel:            {"BitsPerPixel", "Uint", ""},
	attr.TypeCharSets:                {"CharSets", "String", "byte"},
	attr.TypeEncodingMethods:         {"EncodingMethods", "String", "byte"},
	attr.TypeMimeTypes:               {"MimeTypes", "String", "byte"},
	attr.TypeProfileID:               {"ProfileID", "Uint", ""},
	attr.TypeX2RatchetBagSize:        {"X2RatchetBagSize", "Uint", ""},
	attr.TypeX2RatchetBobs1stMsg:     {"X2RatchetBobs1stMsg", "Bool", ""},
	attr.TypeX2RatchetIsAlice:        {"X2RatchetIsAlice", "Bool", ""},
	attr.TypeHSSLevels:               {"HSSLevels", "Uint", ""},
	attr.TypeHSSLMSType:              {"HSSLMSType", "Uint", ""},
	attr.TypeHSSLMOTSType:            {"HSSLMOTSType", "Uint", ""},
	attr.TypeHSSKeysRemaining:        {"HSSKeysRemaining", "Uint", ""},
	attr.TypeClass:                   {"Class", "ObjectClass", ""},
	attr.TypeKeyType:                 {"KeyType", "KType", ""},
	attr.TypeCertificateType:         {"CertificateType", "CertType", ""},
	attr.TypeMechanismType:           {"MechanismType", "MechType", ""},
	attr.TypeNameHashAlgorithm:       {"NameHashAlgorithm", "MechType", ""},
	attr.TypeKeyGenMechanism:         {"KeyGenMechanism", "MechType", ""},
	attr.TypeAllowedMechanisms:       {"AllowedMechanisms", "[]MechType", "MechType"},
	attr.TypeWrapTemplate:            {"WrapTemplate", "[]RawAttribute", "RawAttribute"},
	attr.TypeUnwrapTemplate:          {"UnwrapTemplate", "[]RawAttribute", "RawAttribute"},
	attr.TypeDeriveTemplate:          {"DeriveTemplate", "[]RawAttribute", "RawAttribute"},
	attr.TypeValue:                   {"Value", "Bytes", "byte"},
	attr.TypeObjectID:                {"ObjectID", "Bytes", "byte"},
	attr.TypeIssuer:                  {"Issuer", "Bytes", "byte"},
	attr.TypeSerialNumber:            {"SerialNumber", "Bytes", "byte"},
	attr.TypeACIssuer:                {"ACIssuer", "Bytes", "byte"},
	attr.TypeOwner:                   {"Owner", "Bytes", "byte"},
	attr.TypeAttrTypes:               {"AttrTypes", "Bytes", "byte"},
	attr.TypeHashOfSubjectPublicKey:  {"HashOfSubjectPublicKey", "Bytes", "byte"},
	attr.TypeHashOfIssuerPublicKey:   {"HashOfIssuerPublicKey", "Bytes", "byte"},
	attr.TypeCheckValue:              {"CheckValue", "Bytes", "byte"},
	attr.TypeSubject:                 {"Subject", "Bytes", "byte"},
	attr.TypeID:                      {"ID", "Bytes", "byte"},
	attr.TypePublicKeyInfo:           {"PublicKeyInfo", "Bytes", "byte"},
	attr.TypeECParams:                {"ECParams", "Bytes", "byte"},
	attr.TypeECPoint:                 {"ECPoint", "Bytes", "byte"},
	attr.TypeOTPCounter:              {"OTPCounter", "Bytes", "byte"},
	attr.TypeOTPServiceLogo:          {"OTPServiceLogo", "Bytes", "byte"},
	attr.TypeGOSTR3410Params:         {"GOSTR3410Params", "Bytes", "byte"},
	attr.TypeGOSTR3411Params:         {"GOSTR3411Params", "Bytes", "byte"},
	attr.TypeGOST28147Params:         {"GOST28147Params", "Bytes", "byte"},
	attr.TypeRequiredCMSAttributes:   {"RequiredCMSAttributes", "Bytes", "byte"},
	attr.TypeDefaultCMSAttributes:    {"DefaultCMSAttributes", "Bytes", "byte"},
	attr.TypeSupportedCMSAttributes:  {"SupportedCMSAttributes", "Bytes", "byte"},
	attr.TypeX2RatchetBag:            {"X2RatchetBag", "Bytes", "byte"},
	attr.TypeX2RatchetCKR:            {"X2RatchetCKR", "Bytes", "byte"},
	attr.TypeX2RatchetCKS:            {"X2RatchetCKS", "Bytes", "byte"},
	attr.TypeX2RatchetDHP:            {"X2RatchetDHP", "Bytes", "byte"},
	attr.TypeX2RatchetDHR:            {"X2RatchetDHR", "Bytes", "byte"},
	attr.TypeX2RatchetDHS:            {"X2RatchetDHS", "Bytes", "byte"},
	attr.TypeX2RatchetHKR:            {"X2RatchetHKR", "Bytes", "byte"},
	attr.TypeX2RatchetHKS:            {"X2RatchetHKS", "Bytes", "byte"},
	attr.TypeX2RatchetNHKR:           {"X2RatchetNHKR", "Bytes", "byte"},
	attr.TypeX2RatchetNHKS:           {"X2RatchetNHKS", "Bytes", "byte"},
	attr.TypeX2RatchetNR:             {"X2RatchetNR", "Bytes", "byte"},
	attr.TypeX2RatchetNS:             {"X2RatchetNS", "Bytes", "byte"},
	attr.TypeX2RatchetPNS:            {"X2RatchetPNS", "Bytes", "byte"},
	attr.TypeX2RatchetRK:             {"X2RatchetRK", "Bytes", "byte"},
	attr.TypeHSSLMSTypes:             {"HSSLMSTypes", "Bytes", "byte"},
	attr.TypeHSSLMOTSTypes:           {"HSSLMOTSTypes", "Bytes", "byte"},
	attr.TypeVendorDefined:           {"VendorDefined", "Bytes", "byte"},
}

var tplSrc = `package attr
// GENERATED, DO NOT EDIT.
{{range .}}
type Attr{{.Name}} struct {
	{{- if .Elem}}
	Array[{{.Member}}, {{.Elem}}]
	{{- else}}
	Scalar[{{.Member}}]
	{{- end}}
}

{{if .Elem -}}
func {{.Name}}(v {{.Member}}) *Attr{{.Name}} {
	return &Attr{{.Name}}{
		Array: Array[{{.Member}}, {{.Elem}}]{
			Value: v,
		},
	}
}
{{- else -}}
func {{.Name}}(v {{.Member}}) *Attr{{.Name}} {
	return &Attr{{.Name}}{
		Scalar: Scalar[{{.Member}}]{
			Value: v,
			Valid: true,
		},
	}
}
{{- end}}

func (*Attr{{.Name}}) Type() Type { return Type{{.Name}} }
{{end}}
`
var tpl = template.Must(template.New("attributes").Parse(tplSrc))

func main() {
	fd, err := os.Create("generated.go")
	if err != nil {
		log.Fatal(err)
	}
	defer fd.Close()
	if err := tpl.Execute(fd, attributes); err != nil {
		log.Fatal(err)
	}
}

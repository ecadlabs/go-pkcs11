package attr
// GENERATED, DO NOT EDIT.

type AttrClass struct {
	Scalar[ObjectClass]
}

func Class(v ObjectClass) *AttrClass {
	return &AttrClass{
		Scalar: Scalar[ObjectClass]{
			Value: v,
			Valid: true,
		},
	}
}

func (*AttrClass) Type() Type { return TypeClass }

type AttrToken struct {
	Scalar[Bool]
}

func Token(v Bool) *AttrToken {
	return &AttrToken{
		Scalar: Scalar[Bool]{
			Value: v,
			Valid: true,
		},
	}
}

func (*AttrToken) Type() Type { return TypeToken }

type AttrPrivate struct {
	Scalar[Bool]
}

func Private(v Bool) *AttrPrivate {
	return &AttrPrivate{
		Scalar: Scalar[Bool]{
			Value: v,
			Valid: true,
		},
	}
}

func (*AttrPrivate) Type() Type { return TypePrivate }

type AttrLabel struct {
	Array[String, byte]
}

func Label(v String) *AttrLabel {
	return &AttrLabel{
		Array: Array[String, byte]{
			Value: v,
		},
	}
}

func (*AttrLabel) Type() Type { return TypeLabel }

type AttrUniqueID struct {
	Array[String, byte]
}

func UniqueID(v String) *AttrUniqueID {
	return &AttrUniqueID{
		Array: Array[String, byte]{
			Value: v,
		},
	}
}

func (*AttrUniqueID) Type() Type { return TypeUniqueID }

type AttrApplication struct {
	Array[String, byte]
}

func Application(v String) *AttrApplication {
	return &AttrApplication{
		Array: Array[String, byte]{
			Value: v,
		},
	}
}

func (*AttrApplication) Type() Type { return TypeApplication }

type AttrValue struct {
	Array[Bytes, byte]
}

func Value(v Bytes) *AttrValue {
	return &AttrValue{
		Array: Array[Bytes, byte]{
			Value: v,
		},
	}
}

func (*AttrValue) Type() Type { return TypeValue }

type AttrObjectID struct {
	Array[Bytes, byte]
}

func ObjectID(v Bytes) *AttrObjectID {
	return &AttrObjectID{
		Array: Array[Bytes, byte]{
			Value: v,
		},
	}
}

func (*AttrObjectID) Type() Type { return TypeObjectID }

type AttrCertificateType struct {
	Scalar[CertType]
}

func CertificateType(v CertType) *AttrCertificateType {
	return &AttrCertificateType{
		Scalar: Scalar[CertType]{
			Value: v,
			Valid: true,
		},
	}
}

func (*AttrCertificateType) Type() Type { return TypeCertificateType }

type AttrIssuer struct {
	Array[Bytes, byte]
}

func Issuer(v Bytes) *AttrIssuer {
	return &AttrIssuer{
		Array: Array[Bytes, byte]{
			Value: v,
		},
	}
}

func (*AttrIssuer) Type() Type { return TypeIssuer }

type AttrSerialNumber struct {
	Array[Bytes, byte]
}

func SerialNumber(v Bytes) *AttrSerialNumber {
	return &AttrSerialNumber{
		Array: Array[Bytes, byte]{
			Value: v,
		},
	}
}

func (*AttrSerialNumber) Type() Type { return TypeSerialNumber }

type AttrACIssuer struct {
	Array[Bytes, byte]
}

func ACIssuer(v Bytes) *AttrACIssuer {
	return &AttrACIssuer{
		Array: Array[Bytes, byte]{
			Value: v,
		},
	}
}

func (*AttrACIssuer) Type() Type { return TypeACIssuer }

type AttrOwner struct {
	Array[Bytes, byte]
}

func Owner(v Bytes) *AttrOwner {
	return &AttrOwner{
		Array: Array[Bytes, byte]{
			Value: v,
		},
	}
}

func (*AttrOwner) Type() Type { return TypeOwner }

type AttrAttrTypes struct {
	Array[Bytes, byte]
}

func AttrTypes(v Bytes) *AttrAttrTypes {
	return &AttrAttrTypes{
		Array: Array[Bytes, byte]{
			Value: v,
		},
	}
}

func (*AttrAttrTypes) Type() Type { return TypeAttrTypes }

type AttrTrusted struct {
	Scalar[Bool]
}

func Trusted(v Bool) *AttrTrusted {
	return &AttrTrusted{
		Scalar: Scalar[Bool]{
			Value: v,
			Valid: true,
		},
	}
}

func (*AttrTrusted) Type() Type { return TypeTrusted }

type AttrCertificateCategory struct {
	Scalar[Uint]
}

func CertificateCategory(v Uint) *AttrCertificateCategory {
	return &AttrCertificateCategory{
		Scalar: Scalar[Uint]{
			Value: v,
			Valid: true,
		},
	}
}

func (*AttrCertificateCategory) Type() Type { return TypeCertificateCategory }

type AttrJavaMIDPSecurityDomain struct {
	Scalar[Uint]
}

func JavaMIDPSecurityDomain(v Uint) *AttrJavaMIDPSecurityDomain {
	return &AttrJavaMIDPSecurityDomain{
		Scalar: Scalar[Uint]{
			Value: v,
			Valid: true,
		},
	}
}

func (*AttrJavaMIDPSecurityDomain) Type() Type { return TypeJavaMIDPSecurityDomain }

type AttrURL struct {
	Array[String, byte]
}

func URL(v String) *AttrURL {
	return &AttrURL{
		Array: Array[String, byte]{
			Value: v,
		},
	}
}

func (*AttrURL) Type() Type { return TypeURL }

type AttrHashOfSubjectPublicKey struct {
	Array[Bytes, byte]
}

func HashOfSubjectPublicKey(v Bytes) *AttrHashOfSubjectPublicKey {
	return &AttrHashOfSubjectPublicKey{
		Array: Array[Bytes, byte]{
			Value: v,
		},
	}
}

func (*AttrHashOfSubjectPublicKey) Type() Type { return TypeHashOfSubjectPublicKey }

type AttrHashOfIssuerPublicKey struct {
	Array[Bytes, byte]
}

func HashOfIssuerPublicKey(v Bytes) *AttrHashOfIssuerPublicKey {
	return &AttrHashOfIssuerPublicKey{
		Array: Array[Bytes, byte]{
			Value: v,
		},
	}
}

func (*AttrHashOfIssuerPublicKey) Type() Type { return TypeHashOfIssuerPublicKey }

type AttrNameHashAlgorithm struct {
	Scalar[MechType]
}

func NameHashAlgorithm(v MechType) *AttrNameHashAlgorithm {
	return &AttrNameHashAlgorithm{
		Scalar: Scalar[MechType]{
			Value: v,
			Valid: true,
		},
	}
}

func (*AttrNameHashAlgorithm) Type() Type { return TypeNameHashAlgorithm }

type AttrCheckValue struct {
	Array[Bytes, byte]
}

func CheckValue(v Bytes) *AttrCheckValue {
	return &AttrCheckValue{
		Array: Array[Bytes, byte]{
			Value: v,
		},
	}
}

func (*AttrCheckValue) Type() Type { return TypeCheckValue }

type AttrKeyType struct {
	Scalar[KType]
}

func KeyType(v KType) *AttrKeyType {
	return &AttrKeyType{
		Scalar: Scalar[KType]{
			Value: v,
			Valid: true,
		},
	}
}

func (*AttrKeyType) Type() Type { return TypeKeyType }

type AttrSubject struct {
	Array[Bytes, byte]
}

func Subject(v Bytes) *AttrSubject {
	return &AttrSubject{
		Array: Array[Bytes, byte]{
			Value: v,
		},
	}
}

func (*AttrSubject) Type() Type { return TypeSubject }

type AttrID struct {
	Array[Bytes, byte]
}

func ID(v Bytes) *AttrID {
	return &AttrID{
		Array: Array[Bytes, byte]{
			Value: v,
		},
	}
}

func (*AttrID) Type() Type { return TypeID }

type AttrSensitive struct {
	Scalar[Bool]
}

func Sensitive(v Bool) *AttrSensitive {
	return &AttrSensitive{
		Scalar: Scalar[Bool]{
			Value: v,
			Valid: true,
		},
	}
}

func (*AttrSensitive) Type() Type { return TypeSensitive }

type AttrEncrypt struct {
	Scalar[Bool]
}

func Encrypt(v Bool) *AttrEncrypt {
	return &AttrEncrypt{
		Scalar: Scalar[Bool]{
			Value: v,
			Valid: true,
		},
	}
}

func (*AttrEncrypt) Type() Type { return TypeEncrypt }

type AttrDecrypt struct {
	Scalar[Bool]
}

func Decrypt(v Bool) *AttrDecrypt {
	return &AttrDecrypt{
		Scalar: Scalar[Bool]{
			Value: v,
			Valid: true,
		},
	}
}

func (*AttrDecrypt) Type() Type { return TypeDecrypt }

type AttrWrap struct {
	Scalar[Bool]
}

func Wrap(v Bool) *AttrWrap {
	return &AttrWrap{
		Scalar: Scalar[Bool]{
			Value: v,
			Valid: true,
		},
	}
}

func (*AttrWrap) Type() Type { return TypeWrap }

type AttrUnwrap struct {
	Scalar[Bool]
}

func Unwrap(v Bool) *AttrUnwrap {
	return &AttrUnwrap{
		Scalar: Scalar[Bool]{
			Value: v,
			Valid: true,
		},
	}
}

func (*AttrUnwrap) Type() Type { return TypeUnwrap }

type AttrSign struct {
	Scalar[Bool]
}

func Sign(v Bool) *AttrSign {
	return &AttrSign{
		Scalar: Scalar[Bool]{
			Value: v,
			Valid: true,
		},
	}
}

func (*AttrSign) Type() Type { return TypeSign }

type AttrSignRecover struct {
	Scalar[Bool]
}

func SignRecover(v Bool) *AttrSignRecover {
	return &AttrSignRecover{
		Scalar: Scalar[Bool]{
			Value: v,
			Valid: true,
		},
	}
}

func (*AttrSignRecover) Type() Type { return TypeSignRecover }

type AttrVerify struct {
	Scalar[Bool]
}

func Verify(v Bool) *AttrVerify {
	return &AttrVerify{
		Scalar: Scalar[Bool]{
			Value: v,
			Valid: true,
		},
	}
}

func (*AttrVerify) Type() Type { return TypeVerify }

type AttrVerifyRecover struct {
	Scalar[Bool]
}

func VerifyRecover(v Bool) *AttrVerifyRecover {
	return &AttrVerifyRecover{
		Scalar: Scalar[Bool]{
			Value: v,
			Valid: true,
		},
	}
}

func (*AttrVerifyRecover) Type() Type { return TypeVerifyRecover }

type AttrDerive struct {
	Scalar[Bool]
}

func Derive(v Bool) *AttrDerive {
	return &AttrDerive{
		Scalar: Scalar[Bool]{
			Value: v,
			Valid: true,
		},
	}
}

func (*AttrDerive) Type() Type { return TypeDerive }

type AttrStartDate struct {
	Scalar[Date]
}

func StartDate(v Date) *AttrStartDate {
	return &AttrStartDate{
		Scalar: Scalar[Date]{
			Value: v,
			Valid: true,
		},
	}
}

func (*AttrStartDate) Type() Type { return TypeStartDate }

type AttrEndDate struct {
	Scalar[Date]
}

func EndDate(v Date) *AttrEndDate {
	return &AttrEndDate{
		Scalar: Scalar[Date]{
			Value: v,
			Valid: true,
		},
	}
}

func (*AttrEndDate) Type() Type { return TypeEndDate }

type AttrModulus struct {
	Array[BigInt, byte]
}

func Modulus(v BigInt) *AttrModulus {
	return &AttrModulus{
		Array: Array[BigInt, byte]{
			Value: v,
		},
	}
}

func (*AttrModulus) Type() Type { return TypeModulus }

type AttrModulusBits struct {
	Scalar[Uint]
}

func ModulusBits(v Uint) *AttrModulusBits {
	return &AttrModulusBits{
		Scalar: Scalar[Uint]{
			Value: v,
			Valid: true,
		},
	}
}

func (*AttrModulusBits) Type() Type { return TypeModulusBits }

type AttrPublicExponent struct {
	Array[BigInt, byte]
}

func PublicExponent(v BigInt) *AttrPublicExponent {
	return &AttrPublicExponent{
		Array: Array[BigInt, byte]{
			Value: v,
		},
	}
}

func (*AttrPublicExponent) Type() Type { return TypePublicExponent }

type AttrPrivateExponent struct {
	Array[BigInt, byte]
}

func PrivateExponent(v BigInt) *AttrPrivateExponent {
	return &AttrPrivateExponent{
		Array: Array[BigInt, byte]{
			Value: v,
		},
	}
}

func (*AttrPrivateExponent) Type() Type { return TypePrivateExponent }

type AttrPrime_1 struct {
	Array[BigInt, byte]
}

func Prime_1(v BigInt) *AttrPrime_1 {
	return &AttrPrime_1{
		Array: Array[BigInt, byte]{
			Value: v,
		},
	}
}

func (*AttrPrime_1) Type() Type { return TypePrime_1 }

type AttrPrime_2 struct {
	Array[BigInt, byte]
}

func Prime_2(v BigInt) *AttrPrime_2 {
	return &AttrPrime_2{
		Array: Array[BigInt, byte]{
			Value: v,
		},
	}
}

func (*AttrPrime_2) Type() Type { return TypePrime_2 }

type AttrExponent_1 struct {
	Array[BigInt, byte]
}

func Exponent_1(v BigInt) *AttrExponent_1 {
	return &AttrExponent_1{
		Array: Array[BigInt, byte]{
			Value: v,
		},
	}
}

func (*AttrExponent_1) Type() Type { return TypeExponent_1 }

type AttrExponent_2 struct {
	Array[BigInt, byte]
}

func Exponent_2(v BigInt) *AttrExponent_2 {
	return &AttrExponent_2{
		Array: Array[BigInt, byte]{
			Value: v,
		},
	}
}

func (*AttrExponent_2) Type() Type { return TypeExponent_2 }

type AttrCoefficient struct {
	Array[BigInt, byte]
}

func Coefficient(v BigInt) *AttrCoefficient {
	return &AttrCoefficient{
		Array: Array[BigInt, byte]{
			Value: v,
		},
	}
}

func (*AttrCoefficient) Type() Type { return TypeCoefficient }

type AttrPublicKeyInfo struct {
	Array[Bytes, byte]
}

func PublicKeyInfo(v Bytes) *AttrPublicKeyInfo {
	return &AttrPublicKeyInfo{
		Array: Array[Bytes, byte]{
			Value: v,
		},
	}
}

func (*AttrPublicKeyInfo) Type() Type { return TypePublicKeyInfo }

type AttrPrime struct {
	Array[BigInt, byte]
}

func Prime(v BigInt) *AttrPrime {
	return &AttrPrime{
		Array: Array[BigInt, byte]{
			Value: v,
		},
	}
}

func (*AttrPrime) Type() Type { return TypePrime }

type AttrSubprime struct {
	Array[BigInt, byte]
}

func Subprime(v BigInt) *AttrSubprime {
	return &AttrSubprime{
		Array: Array[BigInt, byte]{
			Value: v,
		},
	}
}

func (*AttrSubprime) Type() Type { return TypeSubprime }

type AttrBase struct {
	Array[BigInt, byte]
}

func Base(v BigInt) *AttrBase {
	return &AttrBase{
		Array: Array[BigInt, byte]{
			Value: v,
		},
	}
}

func (*AttrBase) Type() Type { return TypeBase }

type AttrPrimeBits struct {
	Scalar[Uint]
}

func PrimeBits(v Uint) *AttrPrimeBits {
	return &AttrPrimeBits{
		Scalar: Scalar[Uint]{
			Value: v,
			Valid: true,
		},
	}
}

func (*AttrPrimeBits) Type() Type { return TypePrimeBits }

type AttrSubPrimeBits struct {
	Scalar[Uint]
}

func SubPrimeBits(v Uint) *AttrSubPrimeBits {
	return &AttrSubPrimeBits{
		Scalar: Scalar[Uint]{
			Value: v,
			Valid: true,
		},
	}
}

func (*AttrSubPrimeBits) Type() Type { return TypeSubPrimeBits }

type AttrValueBits struct {
	Scalar[Uint]
}

func ValueBits(v Uint) *AttrValueBits {
	return &AttrValueBits{
		Scalar: Scalar[Uint]{
			Value: v,
			Valid: true,
		},
	}
}

func (*AttrValueBits) Type() Type { return TypeValueBits }

type AttrValueLen struct {
	Scalar[Uint]
}

func ValueLen(v Uint) *AttrValueLen {
	return &AttrValueLen{
		Scalar: Scalar[Uint]{
			Value: v,
			Valid: true,
		},
	}
}

func (*AttrValueLen) Type() Type { return TypeValueLen }

type AttrExtractable struct {
	Scalar[Bool]
}

func Extractable(v Bool) *AttrExtractable {
	return &AttrExtractable{
		Scalar: Scalar[Bool]{
			Value: v,
			Valid: true,
		},
	}
}

func (*AttrExtractable) Type() Type { return TypeExtractable }

type AttrLocal struct {
	Scalar[Bool]
}

func Local(v Bool) *AttrLocal {
	return &AttrLocal{
		Scalar: Scalar[Bool]{
			Value: v,
			Valid: true,
		},
	}
}

func (*AttrLocal) Type() Type { return TypeLocal }

type AttrNeverExtractable struct {
	Scalar[Bool]
}

func NeverExtractable(v Bool) *AttrNeverExtractable {
	return &AttrNeverExtractable{
		Scalar: Scalar[Bool]{
			Value: v,
			Valid: true,
		},
	}
}

func (*AttrNeverExtractable) Type() Type { return TypeNeverExtractable }

type AttrAlwaysSensitive struct {
	Scalar[Bool]
}

func AlwaysSensitive(v Bool) *AttrAlwaysSensitive {
	return &AttrAlwaysSensitive{
		Scalar: Scalar[Bool]{
			Value: v,
			Valid: true,
		},
	}
}

func (*AttrAlwaysSensitive) Type() Type { return TypeAlwaysSensitive }

type AttrKeyGenMechanism struct {
	Scalar[MechType]
}

func KeyGenMechanism(v MechType) *AttrKeyGenMechanism {
	return &AttrKeyGenMechanism{
		Scalar: Scalar[MechType]{
			Value: v,
			Valid: true,
		},
	}
}

func (*AttrKeyGenMechanism) Type() Type { return TypeKeyGenMechanism }

type AttrModifiable struct {
	Scalar[Bool]
}

func Modifiable(v Bool) *AttrModifiable {
	return &AttrModifiable{
		Scalar: Scalar[Bool]{
			Value: v,
			Valid: true,
		},
	}
}

func (*AttrModifiable) Type() Type { return TypeModifiable }

type AttrCopyable struct {
	Scalar[Bool]
}

func Copyable(v Bool) *AttrCopyable {
	return &AttrCopyable{
		Scalar: Scalar[Bool]{
			Value: v,
			Valid: true,
		},
	}
}

func (*AttrCopyable) Type() Type { return TypeCopyable }

type AttrDestroyable struct {
	Scalar[Bool]
}

func Destroyable(v Bool) *AttrDestroyable {
	return &AttrDestroyable{
		Scalar: Scalar[Bool]{
			Value: v,
			Valid: true,
		},
	}
}

func (*AttrDestroyable) Type() Type { return TypeDestroyable }

type AttrECParams struct {
	Array[Bytes, byte]
}

func ECParams(v Bytes) *AttrECParams {
	return &AttrECParams{
		Array: Array[Bytes, byte]{
			Value: v,
		},
	}
}

func (*AttrECParams) Type() Type { return TypeECParams }

type AttrECPoint struct {
	Array[Bytes, byte]
}

func ECPoint(v Bytes) *AttrECPoint {
	return &AttrECPoint{
		Array: Array[Bytes, byte]{
			Value: v,
		},
	}
}

func (*AttrECPoint) Type() Type { return TypeECPoint }

type AttrAlwaysAuthenticate struct {
	Scalar[Bool]
}

func AlwaysAuthenticate(v Bool) *AttrAlwaysAuthenticate {
	return &AttrAlwaysAuthenticate{
		Scalar: Scalar[Bool]{
			Value: v,
			Valid: true,
		},
	}
}

func (*AttrAlwaysAuthenticate) Type() Type { return TypeAlwaysAuthenticate }

type AttrWrapWithTrusted struct {
	Scalar[Bool]
}

func WrapWithTrusted(v Bool) *AttrWrapWithTrusted {
	return &AttrWrapWithTrusted{
		Scalar: Scalar[Bool]{
			Value: v,
			Valid: true,
		},
	}
}

func (*AttrWrapWithTrusted) Type() Type { return TypeWrapWithTrusted }

type AttrOTPFormat struct {
	Scalar[Uint]
}

func OTPFormat(v Uint) *AttrOTPFormat {
	return &AttrOTPFormat{
		Scalar: Scalar[Uint]{
			Value: v,
			Valid: true,
		},
	}
}

func (*AttrOTPFormat) Type() Type { return TypeOTPFormat }

type AttrOTPLength struct {
	Scalar[Uint]
}

func OTPLength(v Uint) *AttrOTPLength {
	return &AttrOTPLength{
		Scalar: Scalar[Uint]{
			Value: v,
			Valid: true,
		},
	}
}

func (*AttrOTPLength) Type() Type { return TypeOTPLength }

type AttrOTPTimeInterval struct {
	Scalar[Uint]
}

func OTPTimeInterval(v Uint) *AttrOTPTimeInterval {
	return &AttrOTPTimeInterval{
		Scalar: Scalar[Uint]{
			Value: v,
			Valid: true,
		},
	}
}

func (*AttrOTPTimeInterval) Type() Type { return TypeOTPTimeInterval }

type AttrOTPUserFriendlyMode struct {
	Scalar[Bool]
}

func OTPUserFriendlyMode(v Bool) *AttrOTPUserFriendlyMode {
	return &AttrOTPUserFriendlyMode{
		Scalar: Scalar[Bool]{
			Value: v,
			Valid: true,
		},
	}
}

func (*AttrOTPUserFriendlyMode) Type() Type { return TypeOTPUserFriendlyMode }

type AttrOTPChallengeRequirement struct {
	Scalar[Uint]
}

func OTPChallengeRequirement(v Uint) *AttrOTPChallengeRequirement {
	return &AttrOTPChallengeRequirement{
		Scalar: Scalar[Uint]{
			Value: v,
			Valid: true,
		},
	}
}

func (*AttrOTPChallengeRequirement) Type() Type { return TypeOTPChallengeRequirement }

type AttrOTPTimeRequirement struct {
	Scalar[Uint]
}

func OTPTimeRequirement(v Uint) *AttrOTPTimeRequirement {
	return &AttrOTPTimeRequirement{
		Scalar: Scalar[Uint]{
			Value: v,
			Valid: true,
		},
	}
}

func (*AttrOTPTimeRequirement) Type() Type { return TypeOTPTimeRequirement }

type AttrOTPCounterRequirement struct {
	Scalar[Uint]
}

func OTPCounterRequirement(v Uint) *AttrOTPCounterRequirement {
	return &AttrOTPCounterRequirement{
		Scalar: Scalar[Uint]{
			Value: v,
			Valid: true,
		},
	}
}

func (*AttrOTPCounterRequirement) Type() Type { return TypeOTPCounterRequirement }

type AttrOTPPinRequirement struct {
	Scalar[Uint]
}

func OTPPinRequirement(v Uint) *AttrOTPPinRequirement {
	return &AttrOTPPinRequirement{
		Scalar: Scalar[Uint]{
			Value: v,
			Valid: true,
		},
	}
}

func (*AttrOTPPinRequirement) Type() Type { return TypeOTPPinRequirement }

type AttrOTPUserIdentifier struct {
	Array[String, byte]
}

func OTPUserIdentifier(v String) *AttrOTPUserIdentifier {
	return &AttrOTPUserIdentifier{
		Array: Array[String, byte]{
			Value: v,
		},
	}
}

func (*AttrOTPUserIdentifier) Type() Type { return TypeOTPUserIdentifier }

type AttrOTPServiceIdentifier struct {
	Array[String, byte]
}

func OTPServiceIdentifier(v String) *AttrOTPServiceIdentifier {
	return &AttrOTPServiceIdentifier{
		Array: Array[String, byte]{
			Value: v,
		},
	}
}

func (*AttrOTPServiceIdentifier) Type() Type { return TypeOTPServiceIdentifier }

type AttrOTPServiceLogo struct {
	Array[Bytes, byte]
}

func OTPServiceLogo(v Bytes) *AttrOTPServiceLogo {
	return &AttrOTPServiceLogo{
		Array: Array[Bytes, byte]{
			Value: v,
		},
	}
}

func (*AttrOTPServiceLogo) Type() Type { return TypeOTPServiceLogo }

type AttrOTPServiceLogoType struct {
	Array[String, byte]
}

func OTPServiceLogoType(v String) *AttrOTPServiceLogoType {
	return &AttrOTPServiceLogoType{
		Array: Array[String, byte]{
			Value: v,
		},
	}
}

func (*AttrOTPServiceLogoType) Type() Type { return TypeOTPServiceLogoType }

type AttrOTPCounter struct {
	Array[Bytes, byte]
}

func OTPCounter(v Bytes) *AttrOTPCounter {
	return &AttrOTPCounter{
		Array: Array[Bytes, byte]{
			Value: v,
		},
	}
}

func (*AttrOTPCounter) Type() Type { return TypeOTPCounter }

type AttrOTPTime struct {
	Array[String, byte]
}

func OTPTime(v String) *AttrOTPTime {
	return &AttrOTPTime{
		Array: Array[String, byte]{
			Value: v,
		},
	}
}

func (*AttrOTPTime) Type() Type { return TypeOTPTime }

type AttrGOSTR3410Params struct {
	Array[Bytes, byte]
}

func GOSTR3410Params(v Bytes) *AttrGOSTR3410Params {
	return &AttrGOSTR3410Params{
		Array: Array[Bytes, byte]{
			Value: v,
		},
	}
}

func (*AttrGOSTR3410Params) Type() Type { return TypeGOSTR3410Params }

type AttrGOSTR3411Params struct {
	Array[Bytes, byte]
}

func GOSTR3411Params(v Bytes) *AttrGOSTR3411Params {
	return &AttrGOSTR3411Params{
		Array: Array[Bytes, byte]{
			Value: v,
		},
	}
}

func (*AttrGOSTR3411Params) Type() Type { return TypeGOSTR3411Params }

type AttrGOST28147Params struct {
	Array[Bytes, byte]
}

func GOST28147Params(v Bytes) *AttrGOST28147Params {
	return &AttrGOST28147Params{
		Array: Array[Bytes, byte]{
			Value: v,
		},
	}
}

func (*AttrGOST28147Params) Type() Type { return TypeGOST28147Params }

type AttrHWFeatureType struct {
	Scalar[Uint]
}

func HWFeatureType(v Uint) *AttrHWFeatureType {
	return &AttrHWFeatureType{
		Scalar: Scalar[Uint]{
			Value: v,
			Valid: true,
		},
	}
}

func (*AttrHWFeatureType) Type() Type { return TypeHWFeatureType }

type AttrResetOnInit struct {
	Scalar[Bool]
}

func ResetOnInit(v Bool) *AttrResetOnInit {
	return &AttrResetOnInit{
		Scalar: Scalar[Bool]{
			Value: v,
			Valid: true,
		},
	}
}

func (*AttrResetOnInit) Type() Type { return TypeResetOnInit }

type AttrHasReset struct {
	Scalar[Bool]
}

func HasReset(v Bool) *AttrHasReset {
	return &AttrHasReset{
		Scalar: Scalar[Bool]{
			Value: v,
			Valid: true,
		},
	}
}

func (*AttrHasReset) Type() Type { return TypeHasReset }

type AttrPixelX struct {
	Scalar[Uint]
}

func PixelX(v Uint) *AttrPixelX {
	return &AttrPixelX{
		Scalar: Scalar[Uint]{
			Value: v,
			Valid: true,
		},
	}
}

func (*AttrPixelX) Type() Type { return TypePixelX }

type AttrPixelY struct {
	Scalar[Uint]
}

func PixelY(v Uint) *AttrPixelY {
	return &AttrPixelY{
		Scalar: Scalar[Uint]{
			Value: v,
			Valid: true,
		},
	}
}

func (*AttrPixelY) Type() Type { return TypePixelY }

type AttrResolution struct {
	Scalar[Uint]
}

func Resolution(v Uint) *AttrResolution {
	return &AttrResolution{
		Scalar: Scalar[Uint]{
			Value: v,
			Valid: true,
		},
	}
}

func (*AttrResolution) Type() Type { return TypeResolution }

type AttrCharRows struct {
	Scalar[Uint]
}

func CharRows(v Uint) *AttrCharRows {
	return &AttrCharRows{
		Scalar: Scalar[Uint]{
			Value: v,
			Valid: true,
		},
	}
}

func (*AttrCharRows) Type() Type { return TypeCharRows }

type AttrCharColumns struct {
	Scalar[Uint]
}

func CharColumns(v Uint) *AttrCharColumns {
	return &AttrCharColumns{
		Scalar: Scalar[Uint]{
			Value: v,
			Valid: true,
		},
	}
}

func (*AttrCharColumns) Type() Type { return TypeCharColumns }

type AttrColor struct {
	Scalar[Bool]
}

func Color(v Bool) *AttrColor {
	return &AttrColor{
		Scalar: Scalar[Bool]{
			Value: v,
			Valid: true,
		},
	}
}

func (*AttrColor) Type() Type { return TypeColor }

type AttrBitsPerPixel struct {
	Scalar[Uint]
}

func BitsPerPixel(v Uint) *AttrBitsPerPixel {
	return &AttrBitsPerPixel{
		Scalar: Scalar[Uint]{
			Value: v,
			Valid: true,
		},
	}
}

func (*AttrBitsPerPixel) Type() Type { return TypeBitsPerPixel }

type AttrCharSets struct {
	Array[String, byte]
}

func CharSets(v String) *AttrCharSets {
	return &AttrCharSets{
		Array: Array[String, byte]{
			Value: v,
		},
	}
}

func (*AttrCharSets) Type() Type { return TypeCharSets }

type AttrEncodingMethods struct {
	Array[String, byte]
}

func EncodingMethods(v String) *AttrEncodingMethods {
	return &AttrEncodingMethods{
		Array: Array[String, byte]{
			Value: v,
		},
	}
}

func (*AttrEncodingMethods) Type() Type { return TypeEncodingMethods }

type AttrMimeTypes struct {
	Array[String, byte]
}

func MimeTypes(v String) *AttrMimeTypes {
	return &AttrMimeTypes{
		Array: Array[String, byte]{
			Value: v,
		},
	}
}

func (*AttrMimeTypes) Type() Type { return TypeMimeTypes }

type AttrMechanismType struct {
	Scalar[MechType]
}

func MechanismType(v MechType) *AttrMechanismType {
	return &AttrMechanismType{
		Scalar: Scalar[MechType]{
			Value: v,
			Valid: true,
		},
	}
}

func (*AttrMechanismType) Type() Type { return TypeMechanismType }

type AttrRequiredCMSAttributes struct {
	Array[Bytes, byte]
}

func RequiredCMSAttributes(v Bytes) *AttrRequiredCMSAttributes {
	return &AttrRequiredCMSAttributes{
		Array: Array[Bytes, byte]{
			Value: v,
		},
	}
}

func (*AttrRequiredCMSAttributes) Type() Type { return TypeRequiredCMSAttributes }

type AttrDefaultCMSAttributes struct {
	Array[Bytes, byte]
}

func DefaultCMSAttributes(v Bytes) *AttrDefaultCMSAttributes {
	return &AttrDefaultCMSAttributes{
		Array: Array[Bytes, byte]{
			Value: v,
		},
	}
}

func (*AttrDefaultCMSAttributes) Type() Type { return TypeDefaultCMSAttributes }

type AttrSupportedCMSAttributes struct {
	Array[Bytes, byte]
}

func SupportedCMSAttributes(v Bytes) *AttrSupportedCMSAttributes {
	return &AttrSupportedCMSAttributes{
		Array: Array[Bytes, byte]{
			Value: v,
		},
	}
}

func (*AttrSupportedCMSAttributes) Type() Type { return TypeSupportedCMSAttributes }

type AttrProfileID struct {
	Scalar[Uint]
}

func ProfileID(v Uint) *AttrProfileID {
	return &AttrProfileID{
		Scalar: Scalar[Uint]{
			Value: v,
			Valid: true,
		},
	}
}

func (*AttrProfileID) Type() Type { return TypeProfileID }

type AttrX2RatchetBag struct {
	Array[Bytes, byte]
}

func X2RatchetBag(v Bytes) *AttrX2RatchetBag {
	return &AttrX2RatchetBag{
		Array: Array[Bytes, byte]{
			Value: v,
		},
	}
}

func (*AttrX2RatchetBag) Type() Type { return TypeX2RatchetBag }

type AttrX2RatchetBagSize struct {
	Scalar[Uint]
}

func X2RatchetBagSize(v Uint) *AttrX2RatchetBagSize {
	return &AttrX2RatchetBagSize{
		Scalar: Scalar[Uint]{
			Value: v,
			Valid: true,
		},
	}
}

func (*AttrX2RatchetBagSize) Type() Type { return TypeX2RatchetBagSize }

type AttrX2RatchetBobs1stMsg struct {
	Scalar[Bool]
}

func X2RatchetBobs1stMsg(v Bool) *AttrX2RatchetBobs1stMsg {
	return &AttrX2RatchetBobs1stMsg{
		Scalar: Scalar[Bool]{
			Value: v,
			Valid: true,
		},
	}
}

func (*AttrX2RatchetBobs1stMsg) Type() Type { return TypeX2RatchetBobs1stMsg }

type AttrX2RatchetCKR struct {
	Array[Bytes, byte]
}

func X2RatchetCKR(v Bytes) *AttrX2RatchetCKR {
	return &AttrX2RatchetCKR{
		Array: Array[Bytes, byte]{
			Value: v,
		},
	}
}

func (*AttrX2RatchetCKR) Type() Type { return TypeX2RatchetCKR }

type AttrX2RatchetCKS struct {
	Array[Bytes, byte]
}

func X2RatchetCKS(v Bytes) *AttrX2RatchetCKS {
	return &AttrX2RatchetCKS{
		Array: Array[Bytes, byte]{
			Value: v,
		},
	}
}

func (*AttrX2RatchetCKS) Type() Type { return TypeX2RatchetCKS }

type AttrX2RatchetDHP struct {
	Array[Bytes, byte]
}

func X2RatchetDHP(v Bytes) *AttrX2RatchetDHP {
	return &AttrX2RatchetDHP{
		Array: Array[Bytes, byte]{
			Value: v,
		},
	}
}

func (*AttrX2RatchetDHP) Type() Type { return TypeX2RatchetDHP }

type AttrX2RatchetDHR struct {
	Array[Bytes, byte]
}

func X2RatchetDHR(v Bytes) *AttrX2RatchetDHR {
	return &AttrX2RatchetDHR{
		Array: Array[Bytes, byte]{
			Value: v,
		},
	}
}

func (*AttrX2RatchetDHR) Type() Type { return TypeX2RatchetDHR }

type AttrX2RatchetDHS struct {
	Array[Bytes, byte]
}

func X2RatchetDHS(v Bytes) *AttrX2RatchetDHS {
	return &AttrX2RatchetDHS{
		Array: Array[Bytes, byte]{
			Value: v,
		},
	}
}

func (*AttrX2RatchetDHS) Type() Type { return TypeX2RatchetDHS }

type AttrX2RatchetHKR struct {
	Array[Bytes, byte]
}

func X2RatchetHKR(v Bytes) *AttrX2RatchetHKR {
	return &AttrX2RatchetHKR{
		Array: Array[Bytes, byte]{
			Value: v,
		},
	}
}

func (*AttrX2RatchetHKR) Type() Type { return TypeX2RatchetHKR }

type AttrX2RatchetHKS struct {
	Array[Bytes, byte]
}

func X2RatchetHKS(v Bytes) *AttrX2RatchetHKS {
	return &AttrX2RatchetHKS{
		Array: Array[Bytes, byte]{
			Value: v,
		},
	}
}

func (*AttrX2RatchetHKS) Type() Type { return TypeX2RatchetHKS }

type AttrX2RatchetIsAlice struct {
	Scalar[Bool]
}

func X2RatchetIsAlice(v Bool) *AttrX2RatchetIsAlice {
	return &AttrX2RatchetIsAlice{
		Scalar: Scalar[Bool]{
			Value: v,
			Valid: true,
		},
	}
}

func (*AttrX2RatchetIsAlice) Type() Type { return TypeX2RatchetIsAlice }

type AttrX2RatchetNHKR struct {
	Array[Bytes, byte]
}

func X2RatchetNHKR(v Bytes) *AttrX2RatchetNHKR {
	return &AttrX2RatchetNHKR{
		Array: Array[Bytes, byte]{
			Value: v,
		},
	}
}

func (*AttrX2RatchetNHKR) Type() Type { return TypeX2RatchetNHKR }

type AttrX2RatchetNHKS struct {
	Array[Bytes, byte]
}

func X2RatchetNHKS(v Bytes) *AttrX2RatchetNHKS {
	return &AttrX2RatchetNHKS{
		Array: Array[Bytes, byte]{
			Value: v,
		},
	}
}

func (*AttrX2RatchetNHKS) Type() Type { return TypeX2RatchetNHKS }

type AttrX2RatchetNR struct {
	Array[Bytes, byte]
}

func X2RatchetNR(v Bytes) *AttrX2RatchetNR {
	return &AttrX2RatchetNR{
		Array: Array[Bytes, byte]{
			Value: v,
		},
	}
}

func (*AttrX2RatchetNR) Type() Type { return TypeX2RatchetNR }

type AttrX2RatchetNS struct {
	Array[Bytes, byte]
}

func X2RatchetNS(v Bytes) *AttrX2RatchetNS {
	return &AttrX2RatchetNS{
		Array: Array[Bytes, byte]{
			Value: v,
		},
	}
}

func (*AttrX2RatchetNS) Type() Type { return TypeX2RatchetNS }

type AttrX2RatchetPNS struct {
	Array[Bytes, byte]
}

func X2RatchetPNS(v Bytes) *AttrX2RatchetPNS {
	return &AttrX2RatchetPNS{
		Array: Array[Bytes, byte]{
			Value: v,
		},
	}
}

func (*AttrX2RatchetPNS) Type() Type { return TypeX2RatchetPNS }

type AttrX2RatchetRK struct {
	Array[Bytes, byte]
}

func X2RatchetRK(v Bytes) *AttrX2RatchetRK {
	return &AttrX2RatchetRK{
		Array: Array[Bytes, byte]{
			Value: v,
		},
	}
}

func (*AttrX2RatchetRK) Type() Type { return TypeX2RatchetRK }

type AttrHSSLevels struct {
	Scalar[Uint]
}

func HSSLevels(v Uint) *AttrHSSLevels {
	return &AttrHSSLevels{
		Scalar: Scalar[Uint]{
			Value: v,
			Valid: true,
		},
	}
}

func (*AttrHSSLevels) Type() Type { return TypeHSSLevels }

type AttrHSSLMSType struct {
	Scalar[Uint]
}

func HSSLMSType(v Uint) *AttrHSSLMSType {
	return &AttrHSSLMSType{
		Scalar: Scalar[Uint]{
			Value: v,
			Valid: true,
		},
	}
}

func (*AttrHSSLMSType) Type() Type { return TypeHSSLMSType }

type AttrHSSLMOTSType struct {
	Scalar[Uint]
}

func HSSLMOTSType(v Uint) *AttrHSSLMOTSType {
	return &AttrHSSLMOTSType{
		Scalar: Scalar[Uint]{
			Value: v,
			Valid: true,
		},
	}
}

func (*AttrHSSLMOTSType) Type() Type { return TypeHSSLMOTSType }

type AttrHSSLMSTypes struct {
	Array[Bytes, byte]
}

func HSSLMSTypes(v Bytes) *AttrHSSLMSTypes {
	return &AttrHSSLMSTypes{
		Array: Array[Bytes, byte]{
			Value: v,
		},
	}
}

func (*AttrHSSLMSTypes) Type() Type { return TypeHSSLMSTypes }

type AttrHSSLMOTSTypes struct {
	Array[Bytes, byte]
}

func HSSLMOTSTypes(v Bytes) *AttrHSSLMOTSTypes {
	return &AttrHSSLMOTSTypes{
		Array: Array[Bytes, byte]{
			Value: v,
		},
	}
}

func (*AttrHSSLMOTSTypes) Type() Type { return TypeHSSLMOTSTypes }

type AttrHSSKeysRemaining struct {
	Scalar[Uint]
}

func HSSKeysRemaining(v Uint) *AttrHSSKeysRemaining {
	return &AttrHSSKeysRemaining{
		Scalar: Scalar[Uint]{
			Value: v,
			Valid: true,
		},
	}
}

func (*AttrHSSKeysRemaining) Type() Type { return TypeHSSKeysRemaining }

type AttrWrapTemplate struct {
	Array[[]RawAttribute, RawAttribute]
}

func WrapTemplate(v []RawAttribute) *AttrWrapTemplate {
	return &AttrWrapTemplate{
		Array: Array[[]RawAttribute, RawAttribute]{
			Value: v,
		},
	}
}

func (*AttrWrapTemplate) Type() Type { return TypeWrapTemplate }

type AttrUnwrapTemplate struct {
	Array[[]RawAttribute, RawAttribute]
}

func UnwrapTemplate(v []RawAttribute) *AttrUnwrapTemplate {
	return &AttrUnwrapTemplate{
		Array: Array[[]RawAttribute, RawAttribute]{
			Value: v,
		},
	}
}

func (*AttrUnwrapTemplate) Type() Type { return TypeUnwrapTemplate }

type AttrDeriveTemplate struct {
	Array[[]RawAttribute, RawAttribute]
}

func DeriveTemplate(v []RawAttribute) *AttrDeriveTemplate {
	return &AttrDeriveTemplate{
		Array: Array[[]RawAttribute, RawAttribute]{
			Value: v,
		},
	}
}

func (*AttrDeriveTemplate) Type() Type { return TypeDeriveTemplate }

type AttrAllowedMechanisms struct {
	Array[[]MechType, MechType]
}

func AllowedMechanisms(v []MechType) *AttrAllowedMechanisms {
	return &AttrAllowedMechanisms{
		Array: Array[[]MechType, MechType]{
			Value: v,
		},
	}
}

func (*AttrAllowedMechanisms) Type() Type { return TypeAllowedMechanisms }

type AttrVendorDefined struct {
	Array[Bytes, byte]
}

func VendorDefined(v Bytes) *AttrVendorDefined {
	return &AttrVendorDefined{
		Array: Array[Bytes, byte]{
			Value: v,
		},
	}
}

func (*AttrVendorDefined) Type() Type { return TypeVendorDefined }


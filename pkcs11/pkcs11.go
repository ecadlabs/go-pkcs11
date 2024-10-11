// Copyright 2021 Google LLC
// Copyright 2024 ECAD Labs Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package pkcs11 implements logic for using PKCS #11 shared libraries.
package pkcs11

//go:generate go run ../gen/generate.go -i platform.h -g generated.go -p pkcs11

/*
#cgo linux LDFLAGS: -ldl

#include <dlfcn.h>

#include "platform.h"

CK_RV open_library(const char *path, void **module, CK_FUNCTION_LIST_PTR_PTR p) {
	*module = dlopen(path, RTLD_LAZY);
	if (*module == NULL) {
		return (CK_RV)(-1);
	}
	CK_C_GetFunctionList getFunctionList = dlsym(*module, "C_GetFunctionList");
	if (getFunctionList == NULL) {
		dlclose(*module);
		*module = NULL;
		return (CK_RV)(-1);
	}
	return getFunctionList(p);
}
*/
import "C"
import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	asn1enc "encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"runtime"
	"strings"
	"sync"
	"unsafe"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

var ErrPublicKey = errors.New("pkcs11: no corresponding public key object found")

// Module represents an opened shared library. By default, this package
// requests locking support from the module, but concurrent safety may
// depend on the underlying library.
type Module struct {
	// mod is a pointer to the dlopen handle. Kept around to dlfree
	// when the Module is closed.
	mod unsafe.Pointer
	// List of C functions provided by the module.
	ft   functionTable
	info ModuleInfo
}

// Open dlopens a shared library by path, initializing the module.
func Open(path string) (*Module, error) {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	var (
		module unsafe.Pointer
		funcs  C.CK_FUNCTION_LIST_PTR
	)

	ret := C.open_library(cPath, &module, &funcs)
	if ret != C.CKR_OK {
		if module == nil {
			return nil, fmt.Errorf("pkcs11: error opening library: %s", C.GoString(C.dlerror()))
		}
		return nil, &Error{fnName: "C_GetFunctionList", code: ret}
	}
	ft := functionTable{t: funcs}

	args := C.CK_C_INITIALIZE_ARGS{
		flags: C.CKF_OS_LOCKING_OK,
	}
	if err := ft.C_Initialize(C.CK_VOID_PTR(unsafe.Pointer(&args))); err != nil {
		C.dlclose(module)
		return nil, err
	}

	var info C.CK_INFO
	if err := ft.C_GetInfo(&info); err != nil {
		C.dlclose(module)
		return nil, err
	}

	return &Module{
		mod: module,
		ft:  ft,
		info: ModuleInfo{
			CryptokiVersion: newVersion(info.cryptokiVersion),
			Manufacturer:    trimPadding(info.manufacturerID[:]),
			Version:         newVersion(info.libraryVersion),
			Description:     trimPadding(info.libraryDescription[:]),
		},
	}, nil
}

// Close finalizes the module and releases any resources associated with the
// shared library.
func (m *Module) Close() error {
	if err := m.ft.C_Finalize(nil); err != nil {
		return err
	}
	if C.dlclose(m.mod) != 0 {
		return fmt.Errorf("pkcs11: dlclose error: %s", C.GoString(C.dlerror()))
	}
	return nil
}

// SlotIDs returns the IDs of all slots associated with this module, including
// ones that haven't been initialized.
func (m *Module) SlotIDs() ([]uint, error) {
	var n C.CK_ULONG
	if err := m.ft.C_GetSlotList(C.CK_FALSE, nil, &n); err != nil {
		return nil, err
	}

	l := make([]C.CK_SLOT_ID, int(n))
	if err := m.ft.C_GetSlotList(C.CK_FALSE, &l[0], &n); err != nil {
		return nil, err
	}
	if int(n) > len(l) {
		return nil, fmt.Errorf("pkcs11: C_GetSlotList returned too many elements, got %d, want %d", int(n), len(l))
	}
	l = l[:int(n)]

	ids := make([]uint, len(l))
	for i, id := range l {
		ids[i] = uint(id)
	}
	return ids, nil
}

// Version holds a major and minor version.
type Version struct {
	Major uint8
	Minor uint8
}

func newVersion(v C.CK_VERSION) Version {
	return Version{
		Major: uint8(v.major),
		Minor: uint8(v.minor),
	}
}

func (v Version) String() string {
	return fmt.Sprintf("%d.%d", v.Major, v.Minor)
}

// ModuleInfo holds global information about the module.
type ModuleInfo struct {
	CryptokiVersion Version
	// Manufacturer of the implementation. When multiple PKCS #11 devices are
	// present this is used to differentiate devices.
	Manufacturer string
	// Version of the module.
	Version Version
	// Human readable description of the module.
	Description string
}

// SlotInfo holds information about the slot and underlying token.
type SlotInfo struct {
	Description     string
	Manufacturer    string
	Flags           SlotFlags
	HardwareVersion Version
	FirmwareVersion Version

	Token *TokenInfo
}

type SlotFlags uint

const (
	SlotTokenPresent    SlotFlags = C.CKF_TOKEN_PRESENT
	SlotRemovableDevice SlotFlags = C.CKF_REMOVABLE_DEVICE
	SlotHWSlot          SlotFlags = C.CKF_HW_SLOT
)

type TokenInfo struct {
	Label              string
	Manufacturer       string
	Model              string
	SerialNumber       []byte
	Flags              TokenFlags
	MaxSessionCount    uint
	SessionCount       uint
	MaxRwSessionCount  uint
	RwSessionCount     uint
	MaxPinLen          uint
	MinPinLen          uint
	TotalPublicMemory  uint
	FreePublicMemory   uint
	TotalPrivateMemory uint
	FreePrivateMemory  uint
	HardwareVersion    Version
	FirmwareVersion    Version
	UTCTime            []byte
}

type TokenFlags uint

const (
	TokenRNG                         TokenFlags = C.CKF_RNG
	TokenWriteProtected              TokenFlags = C.CKF_WRITE_PROTECTED
	TokenLoginRequired               TokenFlags = C.CKF_LOGIN_REQUIRED
	TokenUserPinInitialized          TokenFlags = C.CKF_USER_PIN_INITIALIZED
	TokenRestoreKeyNotNeeded         TokenFlags = C.CKF_RESTORE_KEY_NOT_NEEDED
	TokenClockOnToken                TokenFlags = C.CKF_CLOCK_ON_TOKEN
	TokenProtectedAuthenticationPath TokenFlags = C.CKF_PROTECTED_AUTHENTICATION_PATH
	TokenDualCryptoOperations        TokenFlags = C.CKF_DUAL_CRYPTO_OPERATIONS
	TokenTokenInitialized            TokenFlags = C.CKF_TOKEN_INITIALIZED
	TokenSecondaryAuthentication     TokenFlags = C.CKF_SECONDARY_AUTHENTICATION
	TokenUserPinCountLow             TokenFlags = C.CKF_USER_PIN_COUNT_LOW
	TokenUserPinFinalTry             TokenFlags = C.CKF_USER_PIN_FINAL_TRY
	TokenUserPinLocked               TokenFlags = C.CKF_USER_PIN_LOCKED
	TokenUserPinToBeChanged          TokenFlags = C.CKF_USER_PIN_TO_BE_CHANGED
	TokenSOPinCountLow               TokenFlags = C.CKF_SO_PIN_COUNT_LOW
	TokenSOPinFinalTry               TokenFlags = C.CKF_SO_PIN_FINAL_TRY
	TokenSOPinLocked                 TokenFlags = C.CKF_SO_PIN_LOCKED
	TokenSOPinToBeChanged            TokenFlags = C.CKF_SO_PIN_TO_BE_CHANGED
	TokenErrorState                  TokenFlags = C.CKF_ERROR_STATE
)

func trimPadding(b []C.CK_UTF8CHAR) string {
	return strings.TrimRight(string(b), " ")
}

// Info returns additional information about the module.
func (m *Module) Info() *ModuleInfo {
	return &m.info
}

// SlotInfo queries for information about the slot, such as the label.
func (m *Module) SlotInfo(id uint) (*SlotInfo, error) {
	var cSlotInfo C.CK_SLOT_INFO
	slotID := C.CK_SLOT_ID(id)
	if err := m.ft.C_GetSlotInfo(slotID, &cSlotInfo); err != nil {
		return nil, err
	}
	info := SlotInfo{
		Description:     trimPadding(cSlotInfo.slotDescription[:]),
		Manufacturer:    trimPadding(cSlotInfo.manufacturerID[:]),
		Flags:           SlotFlags(cSlotInfo.flags),
		HardwareVersion: newVersion(cSlotInfo.hardwareVersion),
		FirmwareVersion: newVersion(cSlotInfo.firmwareVersion),
	}
	if (cSlotInfo.flags & C.CKF_TOKEN_PRESENT) == 0 {
		return &info, nil
	}

	var cTokenInfo C.CK_TOKEN_INFO
	if err := m.ft.C_GetTokenInfo(slotID, &cTokenInfo); err != nil {
		return nil, err
	}

	info.Token = &TokenInfo{
		Label:              trimPadding(cTokenInfo.label[:]),
		Manufacturer:       trimPadding(cTokenInfo.manufacturerID[:]),
		Model:              trimPadding(cTokenInfo.model[:]),
		SerialNumber:       unsafe.Slice((*byte)(&cTokenInfo.serialNumber[0]), len(cTokenInfo.serialNumber)),
		Flags:              TokenFlags(cTokenInfo.flags),
		MaxSessionCount:    uint(cTokenInfo.ulMaxSessionCount),
		SessionCount:       uint(cTokenInfo.ulSessionCount),
		MaxRwSessionCount:  uint(cTokenInfo.ulMaxRwSessionCount),
		RwSessionCount:     uint(cTokenInfo.ulRwSessionCount),
		MaxPinLen:          uint(cTokenInfo.ulMaxPinLen),
		MinPinLen:          uint(cTokenInfo.ulMinPinLen),
		TotalPublicMemory:  uint(cTokenInfo.ulTotalPublicMemory),
		FreePublicMemory:   uint(cTokenInfo.ulFreePublicMemory),
		TotalPrivateMemory: uint(cTokenInfo.ulTotalPrivateMemory),
		FreePrivateMemory:  uint(cTokenInfo.ulFreePrivateMemory),
		HardwareVersion:    newVersion(cTokenInfo.hardwareVersion),
		FirmwareVersion:    newVersion(cTokenInfo.firmwareVersion),
		UTCTime:            unsafe.Slice((*byte)(&cTokenInfo.utcTime[0]), len(cTokenInfo.utcTime)),
	}
	return &info, nil
}

// Slot represents a session to a slot.
//
// A slot holds a listable set of objects, such as certificates and
// cryptographic keys.
type Slot struct {
	ft  functionTable
	h   C.CK_SESSION_HANDLE
	mtx sync.Mutex
}

type SlotOption func(o *slotOptions)

type slotOptions struct {
	pin      string
	userType UserType
	flags    C.CK_FLAGS
}

// UserType represents a user type
type UserType uint

const (
	UserTypeNormal          = UserType(C.CKU_USER)
	UserTypeSecurityOfficer = UserType(C.CKU_SO)
)

func (u UserType) String() string {
	switch u {
	case UserTypeNormal:
		return "CKU_USER"
	case UserTypeSecurityOfficer:
		return "CKU_SO"
	default:
		return fmt.Sprintf("UserType(0x%08x)", uint(u))
	}
}

// OptPIN sets PIN for logging into a slot
func OptPIN(pin string) SlotOption {
	return func(o *slotOptions) { o.pin = pin }
}

// OptUserPIN is an alias for OptPIN + OptUserType(UserTypeNormal)
func OptUserPIN(pin string) SlotOption {
	return func(o *slotOptions) {
		o.pin = pin
		o.userType = UserTypeNormal
	}
}

// OptUserPIN is an alias for OptPIN + OptUserType(UserTypeSecurityOfficer)
func OptSecurityOfficerPIN(pin string) SlotOption {
	return func(o *slotOptions) {
		o.pin = pin
		o.userType = UserTypeSecurityOfficer
	}
}

// OptPIN sets a user type for logging into a slot
func OptUserType(ut UserType) SlotOption {
	return func(o *slotOptions) { o.userType = ut }
}

// OptReadWrite sets a read-write session mode
func OptReadWrite(o *slotOptions) { o.flags |= C.CKF_RW_SESSION }

// Slot creates a session with the given slot, by default read-only. Users
// must call Close to release the session.
//
// The returned Slot's behavior is undefined once the Module is closed.
func (m *Module) Slot(id uint, opts ...SlotOption) (*Slot, error) {
	var so slotOptions
	for _, o := range opts {
		o(&so)
	}

	var (
		h C.CK_SESSION_HANDLE
		// "For legacy reasons, the CKF_SERIAL_SESSION bit MUST always be set".
		//
		// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#_Toc416959742
		flags C.CK_FLAGS = C.CKF_SERIAL_SESSION
	)
	flags |= so.flags

	if err := m.ft.C_OpenSession(C.CK_SLOT_ID(id), flags, nil, nil, &h); err != nil {
		return nil, err
	}

	s := &Slot{ft: m.ft, h: h}
	if so.pin != "" {
		cPIN := []C.CK_UTF8CHAR(so.pin)
		if err := s.ft.C_Login(s.h, C.CK_USER_TYPE(so.userType), &cPIN[0], C.CK_ULONG(len(cPIN))); err != nil {
			s.Close()
			return nil, err
		}
	}

	return s, nil
}

// Close releases the slot session.
func (s *Slot) Close() error {
	return s.ft.C_CloseSession(s.h)
}

func (s *Slot) newObject(o C.CK_OBJECT_HANDLE) (*Object, error) {
	obj := Object{slot: s, h: o}

	var pinner runtime.Pinner
	defer pinner.Unpin()

	pinner.Pin(&obj.class)
	attrs := []C.CK_ATTRIBUTE{
		{
			_type:      C.CKA_CLASS,
			pValue:     C.CK_VOID_PTR(&obj.class),
			ulValueLen: C.CK_ULONG(unsafe.Sizeof(obj.class)),
		},
		{
			_type: C.CKA_ID,
		},
		{
			_type: C.CKA_LABEL,
		},
	}
	if err := s.ft.C_GetAttributeValue(s.h, o, &attrs[0], C.CK_ULONG(len(attrs))); err != nil && !errors.Is(err, ErrAttributeValueInvalid) {
		return nil, err
	}
	if ln := attrs[0].ulValueLen; ln == C.CK_UNAVAILABLE_INFORMATION || ln == 0 {
		return nil, errors.New("pkcs11: can't get object class")
	}

	var attrs2 []C.CK_ATTRIBUTE
	if ln := attrs[1].ulValueLen; ln != C.CK_UNAVAILABLE_INFORMATION && ln != 0 {
		// id is available
		obj.id = make([]byte, ln)
		pinner.Pin(&obj.id[0])
		attrs2 = append(attrs2, C.CK_ATTRIBUTE{
			_type:      C.CKA_ID,
			pValue:     C.CK_VOID_PTR(&obj.id[0]),
			ulValueLen: C.CK_ULONG(len(obj.id)),
		})
	}
	if ln := attrs[2].ulValueLen; ln != C.CK_UNAVAILABLE_INFORMATION && ln != 0 {
		// label is available
		obj.label = make([]byte, ln)
		pinner.Pin(&obj.label[0])
		attrs2 = append(attrs2, C.CK_ATTRIBUTE{
			_type:      C.CKA_LABEL,
			pValue:     C.CK_VOID_PTR(&obj.label[0]),
			ulValueLen: C.CK_ULONG(len(obj.label)),
		})
	}

	if len(attrs2) != 0 {
		// get additional attributes
		if err := s.ft.C_GetAttributeValue(s.h, o, &attrs2[0], C.CK_ULONG(len(attrs2))); err != nil {
			return nil, err
		}
	}

	return &obj, nil
}

func (s *Slot) NewObject(h uint) (*Object, error) {
	return s.newObject(C.CK_OBJECT_HANDLE(h))
}

type filterOpt struct {
	class *Class
	label string
	id    []byte
	kt    *KeyType
}

type Filter func(f *filterOpt)

func FilterClass(c Class) Filter {
	return func(f *filterOpt) {
		f.class = &c
	}
}

func FilterLabel(label string) Filter {
	return func(f *filterOpt) {
		f.label = label
	}
}

func FilterID(id []byte) Filter {
	return func(f *filterOpt) {
		f.id = id
	}
}

func FilterKeyType(kt KeyType) Filter {
	return func(f *filterOpt) {
		f.kt = &kt
	}
}

// Objects searches a slot for objects that match the given options, or all
// objects if no options are provided.
//
// The returned objects behavior is undefined once the Slot object is closed.
func (s *Slot) Objects(opts ...Filter) (objs []*Object, err error) {
	var fil filterOpt
	for _, f := range opts {
		f(&fil)
	}
	var pinner runtime.Pinner
	defer pinner.Unpin()

	var attrs []C.CK_ATTRIBUTE
	if fil.label != "" {
		cs := []byte(fil.label)
		pinner.Pin(&cs[0])
		attrs = append(attrs, C.CK_ATTRIBUTE{
			C.CKA_LABEL,
			C.CK_VOID_PTR(&cs[0]),
			C.CK_ULONG(len(fil.label)),
		})
	}

	if fil.class != nil {
		objClass := C.CK_OBJECT_CLASS(*fil.class)
		pinner.Pin(&objClass)
		attrs = append(attrs, C.CK_ATTRIBUTE{
			_type:      C.CKA_CLASS,
			pValue:     C.CK_VOID_PTR(&objClass),
			ulValueLen: C.CK_ULONG(unsafe.Sizeof(objClass)),
		})
	}

	if fil.id != nil {
		pinner.Pin(&fil.id[0])
		attrs = append(attrs, C.CK_ATTRIBUTE{
			_type:      C.CKA_CLASS,
			pValue:     C.CK_VOID_PTR(&fil.id[0]),
			ulValueLen: C.CK_ULONG(len(fil.id)),
		})
	}

	if fil.kt != nil {
		kt := C.CK_KEY_TYPE(*fil.kt)
		pinner.Pin(&kt)
		attrs = append(attrs, C.CK_ATTRIBUTE{
			_type:      C.CKA_KEY_TYPE,
			pValue:     C.CK_VOID_PTR(&kt),
			ulValueLen: C.CK_ULONG(unsafe.Sizeof(kt)),
		})
	}

	s.mtx.Lock()
	defer s.mtx.Unlock()

	if len(attrs) > 0 {
		err = s.ft.C_FindObjectsInit(s.h, &attrs[0], C.CK_ULONG(len(attrs)))
	} else {
		err = s.ft.C_FindObjectsInit(s.h, nil, 0)
	}
	if err != nil {
		return nil, err
	}
	defer func() {
		if ferr := s.ft.C_FindObjectsFinal(s.h); ferr != nil && err == nil {
			err = ferr
		}
	}()

	var handles []C.CK_OBJECT_HANDLE
	const objectsAtATime = 16
	for {
		cObjHandles := make([]C.CK_OBJECT_HANDLE, objectsAtATime)
		var n C.CK_ULONG
		if err := s.ft.C_FindObjects(s.h, &cObjHandles[0], C.CK_ULONG(objectsAtATime), &n); err != nil {
			return nil, err
		}
		if n == 0 {
			break
		}
		handles = append(handles, cObjHandles[:int(n)]...)
	}

	for _, h := range handles {
		o, err := s.newObject(h)
		if err != nil {
			return nil, err
		}
		objs = append(objs, o)
	}
	return objs, nil
}

// Class is the primary object type. Such as a certificate, public key, or private key.
type Class uint

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

type KeyType uint

const (
	KeyRSA              KeyType = C.CKK_RSA
	KeyDSA              KeyType = C.CKK_DSA
	KeyDH               KeyType = C.CKK_DH
	KeyEC               KeyType = C.CKK_EC
	KeyX9_42_DH         KeyType = C.CKK_X9_42_DH
	KeyKEA              KeyType = C.CKK_KEA
	KeyGenericSecret    KeyType = C.CKK_GENERIC_SECRET
	KeyRC2              KeyType = C.CKK_RC2
	KeyRC4              KeyType = C.CKK_RC4
	KeyDES              KeyType = C.CKK_DES
	KeyDES2             KeyType = C.CKK_DES2
	KeyDES3             KeyType = C.CKK_DES3
	KeyCAST             KeyType = C.CKK_CAST
	KeyCAST3            KeyType = C.CKK_CAST3
	KeyCAST128          KeyType = C.CKK_CAST128
	KeyRC5              KeyType = C.CKK_RC5
	KeyIDEA             KeyType = C.CKK_IDEA
	KeySkipjack         KeyType = C.CKK_SKIPJACK
	KeyBATON            KeyType = C.CKK_BATON
	KeyJuniper          KeyType = C.CKK_JUNIPER
	KeyCDMF             KeyType = C.CKK_CDMF
	KeyAES              KeyType = C.CKK_AES
	KeyBlowfish         KeyType = C.CKK_BLOWFISH
	KeyTwofish          KeyType = C.CKK_TWOFISH
	KeySecurID          KeyType = C.CKK_SECURID
	KeyHOTP             KeyType = C.CKK_HOTP
	KeyACTI             KeyType = C.CKK_ACTI
	KeyCamellia         KeyType = C.CKK_CAMELLIA
	KeyARIA             KeyType = C.CKK_ARIA
	KeyMD5_HMAC         KeyType = C.CKK_MD5_HMAC
	KeySHA1_HMAC        KeyType = C.CKK_SHA_1_HMAC
	KeyRIPEMD128_HMAC   KeyType = C.CKK_RIPEMD128_HMAC
	KeyRIPEMD160_HMAC   KeyType = C.CKK_RIPEMD160_HMAC
	KeySHA256_HMAC      KeyType = C.CKK_SHA256_HMAC
	KeySHA384_HMAC      KeyType = C.CKK_SHA384_HMAC
	KeySHA512_HMAC      KeyType = C.CKK_SHA512_HMAC
	KeySHA224_HMAC      KeyType = C.CKK_SHA224_HMAC
	KeySeed             KeyType = C.CKK_SEED
	KeyGOSTR3410        KeyType = C.CKK_GOSTR3410
	KeyGOSTR3411        KeyType = C.CKK_GOSTR3411
	KeyGOST28147        KeyType = C.CKK_GOST28147
	KeyChaCha20         KeyType = C.CKK_CHACHA20
	KeyPoly1305         KeyType = C.CKK_POLY1305
	KeyAES_XTS          KeyType = C.CKK_AES_XTS
	KeySHA3_224_HMAC    KeyType = C.CKK_SHA3_224_HMAC
	KeySHA3_256_HMAC    KeyType = C.CKK_SHA3_256_HMAC
	KeySHA3_384_HMAC    KeyType = C.CKK_SHA3_384_HMAC
	KeySHA3_512_HMAC    KeyType = C.CKK_SHA3_512_HMAC
	KeyBLAKE2b_160_HMAC KeyType = C.CKK_BLAKE2B_160_HMAC
	KeyBLAKE2b_256_HMAC KeyType = C.CKK_BLAKE2B_256_HMAC
	KeyBLAKE2b_384_HMAC KeyType = C.CKK_BLAKE2B_384_HMAC
	KeyBLAKE2b_512_HMAC KeyType = C.CKK_BLAKE2B_512_HMAC
	KeySalsa20          KeyType = C.CKK_SALSA20
	KeyX2Ratchet        KeyType = C.CKK_X2RATCHET
	KeyEC_Edwards       KeyType = C.CKK_EC_EDWARDS
	KeyEC_Montgomery    KeyType = C.CKK_EC_MONTGOMERY
	KeyHKDF             KeyType = C.CKK_HKDF
	KeySHA512_224_HMAC  KeyType = C.CKK_SHA512_224_HMAC
	KeySHA512_256_HMAC  KeyType = C.CKK_SHA512_256_HMAC
	KeySHA512_T_HMAC    KeyType = C.CKK_SHA512_T_HMAC
	KeyHSS              KeyType = C.CKK_HSS
	KeyVendorDefined    KeyType = C.CKK_VENDOR_DEFINED
)

var ktStr = map[KeyType]string{
	KeyRSA:              "CKK_RSA",
	KeyDSA:              "CKK_DSA",
	KeyDH:               "CKK_DH",
	KeyEC:               "CKK_EC",
	KeyX9_42_DH:         "CKK_X9_42_DH",
	KeyKEA:              "CKK_KEA",
	KeyGenericSecret:    "CKK_GENERIC_SECRET",
	KeyRC2:              "CKK_RC2",
	KeyRC4:              "CKK_RC4",
	KeyDES:              "CKK_DES",
	KeyDES2:             "CKK_DES2",
	KeyDES3:             "CKK_DES3",
	KeyCAST:             "CKK_CAST",
	KeyCAST3:            "CKK_CAST3",
	KeyCAST128:          "CKK_CAST128",
	KeyRC5:              "CKK_RC5",
	KeyIDEA:             "CKK_IDEA",
	KeySkipjack:         "CKK_SKIPJACK",
	KeyBATON:            "CKK_BATON",
	KeyJuniper:          "CKK_JUNIPER",
	KeyCDMF:             "CKK_CDMF",
	KeyAES:              "CKK_AES",
	KeyBlowfish:         "CKK_BLOWFISH",
	KeyTwofish:          "CKK_TWOFISH",
	KeySecurID:          "CKK_SECURID",
	KeyHOTP:             "CKK_HOTP",
	KeyACTI:             "CKK_ACTI",
	KeyCamellia:         "CKK_CAMELLIA",
	KeyARIA:             "CKK_ARIA",
	KeyMD5_HMAC:         "CKK_MD5_HMAC",
	KeySHA1_HMAC:        "CKK_SHA_1_HMAC",
	KeyRIPEMD128_HMAC:   "CKK_RIPEMD128_HMAC",
	KeyRIPEMD160_HMAC:   "CKK_RIPEMD160_HMAC",
	KeySHA256_HMAC:      "CKK_SHA256_HMAC",
	KeySHA384_HMAC:      "CKK_SHA384_HMAC",
	KeySHA512_HMAC:      "CKK_SHA512_HMAC",
	KeySHA224_HMAC:      "CKK_SHA224_HMAC",
	KeySeed:             "CKK_SEED",
	KeyGOSTR3410:        "CKK_GOSTR3410",
	KeyGOSTR3411:        "CKK_GOSTR3411",
	KeyGOST28147:        "CKK_GOST28147",
	KeyChaCha20:         "CKK_CHACHA20",
	KeyPoly1305:         "CKK_POLY1305",
	KeyAES_XTS:          "CKK_AES_XTS",
	KeySHA3_224_HMAC:    "CKK_SHA3_224_HMAC",
	KeySHA3_256_HMAC:    "CKK_SHA3_256_HMAC",
	KeySHA3_384_HMAC:    "CKK_SHA3_384_HMAC",
	KeySHA3_512_HMAC:    "CKK_SHA3_512_HMAC",
	KeyBLAKE2b_160_HMAC: "CKK_BLAKE2B_160_HMAC",
	KeyBLAKE2b_256_HMAC: "CKK_BLAKE2B_256_HMAC",
	KeyBLAKE2b_384_HMAC: "CKK_BLAKE2B_384_HMAC",
	KeyBLAKE2b_512_HMAC: "CKK_BLAKE2B_512_HMAC",
	KeySalsa20:          "CKK_SALSA20",
	KeyX2Ratchet:        "CKK_X2RATCHET",
	KeyEC_Edwards:       "CKK_EC_EDWARDS",
	KeyEC_Montgomery:    "CKK_EC_MONTGOMERY",
	KeyHKDF:             "CKK_HKDF",
	KeySHA512_224_HMAC:  "CKK_SHA512_224_HMAC",
	KeySHA512_256_HMAC:  "CKK_SHA512_256_HMAC",
	KeySHA512_T_HMAC:    "CKK_SHA512_T_HMAC",
	KeyHSS:              "CKK_HSS",
	KeyVendorDefined:    "CKK_VENDOR_DEFINED",
}

func (k KeyType) String() string {
	if s, ok := ktStr[k]; ok {
		return s
	}
	return fmt.Sprintf("KeyType(0x%08x)", uint(k))
}

// Object represents a single object stored within a slot. For example a key or
// certificate.
type Object struct {
	slot  *Slot
	h     C.CK_OBJECT_HANDLE
	class C.CK_OBJECT_CLASS
	id    []byte
	label []byte
}

// Class returns the type of the object stored. For example, certificate, public
// key, or private key.
func (o *Object) Class() Class {
	return Class(o.class)
}

type attrType C.CK_ATTRIBUTE_TYPE

func (o *Object) getAttributesBytes(types []attrType) ([][]byte, error) {
	attrs := make([]C.CK_ATTRIBUTE, len(types))
	for i, t := range types {
		attrs[i]._type = C.CK_ATTRIBUTE_TYPE(t)
	}
	if err := o.slot.ft.C_GetAttributeValue(o.slot.h, o.h, &attrs[0], C.CK_ULONG(len(attrs))); err != nil {
		return nil, err
	}

	var pinner runtime.Pinner
	defer pinner.Unpin()

	out := make([][]byte, len(attrs))
	for i := range attrs {
		buf := make([]byte, attrs[i].ulValueLen)
		pinner.Pin(&buf[0])
		attrs[i].pValue = C.CK_VOID_PTR(&buf[0])
		out[i] = buf
	}
	if err := o.slot.ft.C_GetAttributeValue(o.slot.h, o.h, &attrs[0], C.CK_ULONG(len(attrs))); err != nil {
		return nil, err
	}
	return out, nil
}

func getAttribute[T any](o *Object, typ C.CK_ATTRIBUTE_TYPE) (T, bool, error) {
	var (
		value, nullVal T
		pinner         runtime.Pinner
	)
	pinner.Pin(&value)
	defer pinner.Unpin()
	attr := C.CK_ATTRIBUTE{
		_type:      typ,
		pValue:     C.CK_VOID_PTR(&value),
		ulValueLen: C.CK_ULONG(unsafe.Sizeof(value)),
	}
	if err := o.slot.ft.C_GetAttributeValue(o.slot.h, o.h, &attr, 1); err != nil {
		return nullVal, false, err
	}
	return value, true, nil
}

func (o *Object) setAttribute(attrs []C.CK_ATTRIBUTE) error {
	return o.slot.ft.C_SetAttributeValue(o.slot.h, o.h, &attrs[0], C.CK_ULONG(len(attrs)))
}

// Label returns a string value attached to an object, which can be used to
// identify or group sets of keys and certificates.
func (o *Object) Label() string {
	return string(o.label)
}

func (o *Object) ID() []byte {
	return o.id
}

func (o *Object) Handle() uint {
	return uint(o.h)
}

// Certificate parses the underlying object as a certificate. If the object
// isn't a certificate, this method fails.
func (o *Object) Certificate() (*Certificate, error) {
	if o.Class() != ClassCertificate {
		return nil, fmt.Errorf("pkcs11: expected object class %v, got %v", ClassCertificate, o.Class())
	}
	ct, _, err := getAttribute[C.CK_CERTIFICATE_TYPE](o, C.CKA_CERTIFICATE_TYPE)
	if err != nil {
		return nil, err
	}
	return &Certificate{o, ct}, nil
}

// PublicKey parses the underlying object as a public key. Both RSA and ECDSA
// keys are supported.
//
// If the object isn't a public key, this method fails.
func (o *Object) PublicKey() (crypto.PublicKey, error) {
	if o.Class() != ClassPublicKey {
		return nil, fmt.Errorf("pkcs11: expected object class %v, got %v", ClassPublicKey, o.Class())
	}

	kt, _, err := getAttribute[C.CK_KEY_TYPE](o, C.CKA_KEY_TYPE)
	if err != nil {
		return nil, err
	}
	switch kt {
	case C.CKK_EC:
		return o.ecdsaPublicKey()
	//case C.CKK_RSA:
	//	return o.rsaPublicKey()
	default:
		return nil, fmt.Errorf("unsupported key type: 0x%08x", kt)
	}
}

var (
	oidCurveP224 = asn1enc.ObjectIdentifier{1, 3, 132, 0, 33}
	oidCurveP256 = asn1enc.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidCurveP384 = asn1enc.ObjectIdentifier{1, 3, 132, 0, 34}
	oidCurveP521 = asn1enc.ObjectIdentifier{1, 3, 132, 0, 35}
	oidCurveS256 = asn1enc.ObjectIdentifier{1, 3, 132, 0, 10} // http://www.secg.org/sec2-v2.pdf
)

func (o *Object) ecdsaPublicKey() (*ecdsa.PublicKey, error) {
	// http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cs01/pkcs11-curr-v2.40-cs01.html#_Toc399398881
	attrs, err := o.getAttributesBytes([]attrType{C.CKA_EC_PARAMS, C.CKA_EC_POINT})
	if err != nil {
		return nil, err
	}

	pointBytes := attrs[1]
	paramBytes := cryptobyte.String(attrs[0])
	var oid asn1enc.ObjectIdentifier
	if !paramBytes.ReadASN1ObjectIdentifier(&oid) {
		return nil, errors.New("pkcs11: error reading key OID")
	}

	var curve elliptic.Curve
	switch {
	case oid.Equal(oidCurveP224):
		curve = elliptic.P224()
	case oid.Equal(oidCurveP256):
		curve = elliptic.P256()
	case oid.Equal(oidCurveP384):
		curve = elliptic.P384()
	case oid.Equal(oidCurveP521):
		curve = elliptic.P521()
	case oid.Equal(oidCurveS256):
		curve = secp256k1.S256()
	default:
		return nil, errors.New("pkcs11: unsupported curve OID")
	}

	ptObj := cryptobyte.String(pointBytes)
	var pt cryptobyte.String
	if !ptObj.ReadASN1(&pt, asn1.OCTET_STRING) {
		return nil, fmt.Errorf("pkcs11: error decoding ec point: %w", err)
	}
	x, y := elliptic.Unmarshal(curve, pt)
	if x == nil {
		return nil, errors.New("pkcs11: invalid point format")
	}
	return &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}, nil
}

func (o *Object) findPublicKey(kt KeyType, flags MatchFlags) (*Object, error) {
	objects, err := o.slot.Objects(FilterClass(ClassPublicKey), FilterKeyType(kt))
	if err != nil {
		return nil, err
	}
	if len(objects) == 0 {
		return nil, nil
	}
	var pubObj *Object
	if len(objects) == 1 {
		pubObj = objects[0]
	} else {
		if o.id == nil && o.label == nil {
			return nil, nil
		}
		for _, x := range objects {
			if flags&MatchID != 0 && x.id != nil && bytes.Equal(x.id, o.id) ||
				flags&MatchLabel != 0 && x.label != nil && bytes.Equal(x.label, o.label) {
				pubObj = x
				break
			}
		}
	}
	return pubObj, nil
}

// KeyPair represents a complete key pair. It implements crypto.Signer and optionally crypto.Decrypter (for RSA)
type KeyPair interface {
	crypto.Signer
	Public() crypto.PublicKey
}

type MatchFlags uint

const (
	MatchLabel MatchFlags = 1 << iota
	MatchID
)

// PrivateKey is a private key object without a corresponding public key. It implements Signer and optionally Decrypter
// interfaces (for RSA) but not crypto.Signer and crypto.Decrypter
type PrivateKey interface {
	Signer
	// KeyPair finds an adjacent public key in the same slot. If there is more than one public key found then
	// it returns one with the matching ID if the latter is present
	KeyPair(flags MatchFlags) (KeyPair, error)
	AddPublic(pub crypto.PublicKey) (KeyPair, error)
}

type Signer interface {
	Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error)
}

type Decrypter interface {
	Decrypt(rand io.Reader, msg []byte, opts crypto.DecrypterOpts) (plaintext []byte, err error)
}

// PrivateKey parses the underlying object as a private key. Both RSA and ECDSA
// keys are supported.
//
// If the object isn't a public key, this method fails.
func (o *Object) PrivateKey() (PrivateKey, error) {
	if o.Class() != ClassPrivateKey {
		return nil, fmt.Errorf("pkcs11: expected object class %v, got %v", ClassPrivateKey, o.Class())
	}

	kt, _, err := getAttribute[C.CK_KEY_TYPE](o, C.CKA_KEY_TYPE)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: error getting certificate type: %w", err)
	}
	switch kt {
	case C.CKK_EC:
		return (*ecdsaPrivateKey)(o), nil
	//case C.CKK_RSA:
	//	return o.rsaPrivateKey()
	default:
		return nil, fmt.Errorf("pkcs11: unsupported key type: 0x%08x", kt)
	}
}

type ecdsaPrivateKey Object

func (e *ecdsaPrivateKey) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	e.slot.mtx.Lock()
	defer e.slot.mtx.Unlock()

	// http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cs01/pkcs11-curr-v2.40-cs01.html#_Toc399398884
	m := C.CK_MECHANISM{
		mechanism: C.CKM_ECDSA,
	}
	if err := e.slot.ft.C_SignInit(e.slot.h, &m, e.h); err != nil {
		return nil, err
	}
	var sigLen C.CK_ULONG
	if err := e.slot.ft.C_Sign(e.slot.h, (*C.CK_BYTE)(&digest[0]), C.CK_ULONG(len(digest)), nil, &sigLen); err != nil {
		return nil, err
	}
	sig := make([]byte, sigLen)
	if err := e.slot.ft.C_Sign(e.slot.h, (*C.CK_BYTE)(&digest[0]), C.CK_ULONG(len(digest)), (*C.CK_BYTE)(&sig[0]), &sigLen); err != nil {
		return nil, err
	}

	r := new(big.Int).SetBytes(sig[:len(sig)/2])
	s := new(big.Int).SetBytes(sig[len(sig)/2:])

	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1BigInt(r)
		b.AddASN1BigInt(s)
	})

	return b.Bytes()
}

func (e *ecdsaPrivateKey) AddPublic(pub crypto.PublicKey) (KeyPair, error) {
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("pkcs11: invalid public key type %T", pub)
	}
	return &ecdsaKeyPair{
		ecdsaPrivateKey: e,
		pub:             ecPub,
	}, nil
}

func (e *ecdsaPrivateKey) KeyPair(flags MatchFlags) (KeyPair, error) {
	pubObj, err := (*Object)(e).findPublicKey(KeyEC, flags)
	if err != nil {
		return nil, err
	}
	if pubObj == nil {
		return nil, ErrPublicKey
	}
	pub, err := pubObj.ecdsaPublicKey()
	if err != nil {
		return nil, err
	}
	return &ecdsaKeyPair{
		ecdsaPrivateKey: e,
		pub:             pub,
	}, nil
}

type ecdsaKeyPair struct {
	*ecdsaPrivateKey
	pub *ecdsa.PublicKey
}

func (p *ecdsaKeyPair) Public() crypto.PublicKey {
	return p.pub
}

// CertificateType determines the kind of certificate a certificate object holds.
// This can be X.509, WTLS, GPG, etc.
//
// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#_Toc416959709
type CertificateType uint

// Certificate types supported by this package.
const (
	CertificateX509          = CertificateType(C.CKC_X_509)
	CertificateX509AttrCert  = CertificateType(C.CKC_X_509_ATTR_CERT)
	CertificateWTLS          = CertificateType(C.CKC_WTLS)
	CertificateVendorDefined = CertificateType(C.CKC_VENDOR_DEFINED)
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

// Certificate holds a certificate object. Because certificates object can hold
// various kinds of certificates, callers should check the type before calling
// methods that parse the certificate.
//
//	cert, err := obj.Certificate()
//	if err != nil {
//		// ...
//	}
//	if cert.Type() != pkcs11.CertificateX509 {
//		// unexpected kind of certificate ...
//	}
//	x509Cert, err := cert.X509()
type Certificate struct {
	o *Object
	t C.CK_CERTIFICATE_TYPE
}

// Type returns the format of the underlying certificate.
func (c *Certificate) Type() CertificateType {
	return CertificateType(c.t)
}

// X509 parses the underlying certificate as an X.509 certificate.
//
// If the certificate holds a different type of certificate, this method
// returns an error.
func (c *Certificate) X509() (*x509.Certificate, error) {
	// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#_Toc416959712
	if c.t != C.CKC_X_509 {
		return nil, fmt.Errorf("pkcs11: invalid certificate type: %v", CertificateType(c.t))
	}

	raw, err := c.o.getAttributesBytes([]attrType{C.CKA_VALUE})
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(raw[0])
	if err != nil {
		return nil, fmt.Errorf("pkcs11: error parsing certificate: %w", err)
	}
	return cert, nil
}

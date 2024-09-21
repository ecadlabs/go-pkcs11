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
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io"
	"math/big"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

// ckStringPadded copies a string into b, padded with ' '. If the string is larger
// than the provided buffer, this function returns false.
func ckStringPadded(b []C.CK_UTF8CHAR, s string) bool {
	if len(s) > len(b) {
		return false
	}
	copy(b, []C.CK_UTF8CHAR(s))
	for i := len(s); i < len(b); i++ {
		b[i] = ' '
	}
	return true
}

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
	C.CKR_FUNCTION_REJECTED:                "CKR_FUNCTION_REJECTED",
	C.CKR_VENDOR_DEFINED:                   "CKR_VENDOR_DEFINED",
}

// Module represents an opened shared library. By default, this package
// requests locking support from the module, but concurrent safety may
// depend on the underlying library.
type Module struct {
	// mod is a pointer to the dlopen handle. Kept around to dlfree
	// when the Module is closed.
	mod unsafe.Pointer
	// List of C functions provided by the module.
	ft functionTable
	// Version of the module, used for compatibility.
	version C.CK_VERSION

	info Info
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
		mod:     module,
		ft:      ft,
		version: info.cryptokiVersion,
		info: Info{
			Manufacturer: trimPadding(info.manufacturerID[:]),
			Version: Version{
				Major: uint8(info.libraryVersion.major),
				Minor: uint8(info.libraryVersion.minor),
			},
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

// createSlot configures a slot object. Internally this calls C_InitToken and
// C_InitPIN to set the admin and user PIN on the slot.
func (m *Module) createSlot(id uint, opts createSlotOptions) error {
	if opts.Label == "" {
		return fmt.Errorf("no label provided")
	}
	if opts.UserPIN == "" {
		return fmt.Errorf("no user pin provided")
	}
	if opts.SecurityOfficerPIN == "" {
		return fmt.Errorf("no admin pin provided")
	}

	var cLabel [32]C.CK_UTF8CHAR
	if !ckStringPadded(cLabel[:], opts.Label) {
		return fmt.Errorf("label is too long")
	}

	cPIN := []C.CK_UTF8CHAR(opts.SecurityOfficerPIN)
	cPINLen := C.CK_ULONG(len(cPIN))

	err := m.ft.C_InitToken(
		C.CK_SLOT_ID(id),
		&cPIN[0],
		cPINLen,
		&cLabel[0],
	)
	if err != nil {
		return err
	}

	s, err := m.Slot(id, OptSecurityOfficerPIN(opts.SecurityOfficerPIN), OptReadWrite)
	if err != nil {
		return fmt.Errorf("getting slot: %w", err)
	}
	defer s.Close()
	if err := s.initPIN(opts.UserPIN); err != nil {
		return fmt.Errorf("configuring user pin: %w", err)
	}
	if err := s.logout(); err != nil {
		return fmt.Errorf("logout: %w", err)
	}
	return nil
}

// SlotIDs returns the IDs of all slots associated with this module, including
// ones that haven't been initialized.
func (m *Module) SlotIDs() ([]uint32, error) {
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

	ids := make([]uint32, len(l))
	for i, id := range l {
		ids[i] = uint32(id)
	}
	return ids, nil
}

// Version holds a major and minor version.
type Version struct {
	Major uint8
	Minor uint8
}

// Info holds global information about the module.
type Info struct {
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
	Label  string
	Model  string
	Serial string

	Description string
}

func trimPadding(b []C.CK_UTF8CHAR) string {
	return strings.TrimRight(string(b), " ")
}

// Info returns additional information about the module.
func (m *Module) Info() Info {
	return m.info
}

// SlotInfo queries for information about the slot, such as the label.
func (m *Module) SlotInfo(id uint32) (*SlotInfo, error) {
	var (
		cSlotInfo  C.CK_SLOT_INFO
		cTokenInfo C.CK_TOKEN_INFO
		slotID     = C.CK_SLOT_ID(id)
	)
	if err := m.ft.C_GetSlotInfo(slotID, &cSlotInfo); err != nil {
		return nil, err
	}
	info := SlotInfo{
		Description: trimPadding(cSlotInfo.slotDescription[:]),
	}
	if (cSlotInfo.flags & C.CKF_TOKEN_PRESENT) == 0 {
		return &info, nil
	}

	if err := m.ft.C_GetTokenInfo(slotID, &cTokenInfo); err != nil {
		return nil, err
	}
	info.Label = trimPadding(cTokenInfo.label[:])
	info.Model = trimPadding(cTokenInfo.model[:])
	info.Serial = trimPadding(cTokenInfo.serialNumber[:])
	return &info, nil
}

// Slot represents a session to a slot.
//
// A slot holds a listable set of objects, such as certificates and
// cryptographic keys.
type Slot struct {
	ft functionTable
	h  C.CK_SESSION_HANDLE
}

type createSlotOptions struct {
	SecurityOfficerPIN string
	UserPIN            string
	Label              string
}

type SlotOption func(o *slotOptions)

type slotOptions struct {
	pin      string
	userType UserType
	flags    C.CK_FLAGS
}

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

func OptUserType(ut UserType) SlotOption {
	return func(o *slotOptions) { o.userType = ut }
}

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

// TODO(ericchiang): merge with SlotInitialize.
func (s *Slot) initPIN(pin string) error {
	if pin == "" {
		return fmt.Errorf("invalid pin")
	}
	cPIN := []C.CK_UTF8CHAR(pin)
	cPINLen := C.CK_ULONG(len(cPIN))
	return s.ft.C_InitPIN(s.h, &cPIN[0], cPINLen)
}

func (s *Slot) logout() error {
	return s.ft.C_Logout(s.h)
}

// Class is the primary object type. Such as a certificate, public key, or
// private key.
type Class uint

// Set of classes supported by this package.
const (
	ClassData             = Class(C.CKO_DATA)
	ClassCertificate      = Class(C.CKO_CERTIFICATE)
	ClassPublicKey        = Class(C.CKO_PUBLIC_KEY)
	ClassPrivateKey       = Class(C.CKO_PRIVATE_KEY)
	ClassSecretKey        = Class(C.CKO_SECRET_KEY)
	ClassHWFeature        = Class(C.CKO_HW_FEATURE)
	ClassDomainParameters = Class(C.CKO_DOMAIN_PARAMETERS)
	ClassMechanism        = Class(C.CKO_MECHANISM)
	ClassOTPKey           = Class(C.CKO_OTP_KEY)
	ClassVendorDefined    = Class(C.CKO_VENDOR_DEFINED)
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
	ClassVendorDefined:    "CKO_VENDOR_DEFINED",
}

// String returns a human readable version of the object class.
func (c Class) String() string {
	if s, ok := classString[c]; ok {
		return s
	}
	return fmt.Sprintf("Class(0x%08x)", uint(c))
}

func (s *Slot) newObject(o C.CK_OBJECT_HANDLE) (Object, error) {
	obj := Object{ft: s.ft, h: s.h, o: o}
	objClass, err := getAttribute[C.CK_OBJECT_CLASS](&obj, C.CKA_CLASS)
	if err != nil {
		return Object{}, err
	}
	obj.c = objClass
	return obj, nil
}

type createOptions struct {
	Label string

	X509Certificate *x509.Certificate
}

func (s *Slot) create(opts createOptions) (*Object, error) {
	if opts.X509Certificate != nil {
		return s.createX509Certificate(opts)
	}
	return nil, fmt.Errorf("no objects provided to import")
}

// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#_Toc416959709
func (s *Slot) createX509Certificate(opts createOptions) (*Object, error) {
	if opts.X509Certificate == nil {
		return nil, fmt.Errorf("no certificate provided")
	}

	objClass := C.CK_OBJECT_CLASS(C.CKO_CERTIFICATE)
	ct := C.CK_CERTIFICATE_TYPE(C.CKC_X_509)

	var pinner runtime.Pinner
	defer pinner.Unpin()
	pinner.Pin(&objClass)
	pinner.Pin(&ct)
	pinner.Pin(&opts.X509Certificate.RawSubject[0])
	pinner.Pin(&opts.X509Certificate.Raw[0])

	attrs := []C.CK_ATTRIBUTE{
		{C.CKA_CLASS, C.CK_VOID_PTR(&objClass), C.CK_ULONG(unsafe.Sizeof(objClass))},
		{C.CKA_CERTIFICATE_TYPE, C.CK_VOID_PTR(&ct), C.CK_ULONG(unsafe.Sizeof(ct))},
		{C.CKA_SUBJECT, C.CK_VOID_PTR(&opts.X509Certificate.RawSubject[0]), C.CK_ULONG(len(opts.X509Certificate.RawSubject))},
		{C.CKA_VALUE, C.CK_VOID_PTR(&opts.X509Certificate.Raw[0]), C.CK_ULONG(len(opts.X509Certificate.Raw))},
	}

	if opts.Label != "" {
		cs := []byte(opts.Label)
		pinner.Pin(&cs[0])
		attrs = append(attrs, C.CK_ATTRIBUTE{
			C.CKA_LABEL,
			C.CK_VOID_PTR(&cs[0]),
			C.CK_ULONG(len(opts.Label)),
		})
	}

	var h C.CK_OBJECT_HANDLE
	if err := s.ft.C_CreateObject(s.h, &attrs[0], C.CK_ULONG(len(attrs)), &h); err != nil {
		return nil, err
	}
	obj, err := s.newObject(h)
	if err != nil {
		return nil, err
	}
	return &obj, nil
}

type filterOpt struct {
	class *Class
	label string
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

// Objects searches a slot for objects that match the given options, or all
// objects if no options are provided.
//
// The returned objects behavior is undefined once the Slot object is closed.
func (s *Slot) Objects(opts ...Filter) (objs []Object, err error) {
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

// Object represents a single object stored within a slot. For example a key or
// certificate.
type Object struct {
	ft functionTable
	h  C.CK_SESSION_HANDLE
	o  C.CK_OBJECT_HANDLE
	c  C.CK_OBJECT_CLASS
}

// Class returns the type of the object stored. For example, certificate, public
// key, or private key.
func (o *Object) Class() Class {
	return Class(o.c)
}

type attrType C.CK_ATTRIBUTE_TYPE

func (o *Object) getAttributesBytes(types []attrType, allowMissing bool) ([][]byte, error) {
	attrs := make([]C.CK_ATTRIBUTE, len(types))
	for i, t := range types {
		attrs[i]._type = C.CK_ATTRIBUTE_TYPE(t)
	}
	if err := o.ft.C_GetAttributeValue(o.h, o.o, &attrs[0], C.CK_ULONG(len(attrs))); err != nil {
		return nil, err
	}

	var pinner runtime.Pinner
	defer pinner.Unpin()

	out := make([][]byte, len(attrs))
	for i := range attrs {
		if attrs[i].ulValueLen == 0 {
			if !allowMissing {
				return nil, fmt.Errorf("pkcs11: missing attribute 0x%08x", attrs[i]._type)
			}
		} else {
			buf := make([]byte, attrs[i].ulValueLen)
			pinner.Pin(&buf[0])
			attrs[i].pValue = C.CK_VOID_PTR(&buf[0])
			out[i] = buf
		}
	}
	if err := o.ft.C_GetAttributeValue(o.h, o.o, &attrs[0], C.CK_ULONG(len(attrs))); err != nil {
		return nil, err
	}
	return out, nil
}

func getAttribute[T any](o *Object, typ C.CK_ATTRIBUTE_TYPE) (T, error) {
	var (
		value  T
		pinner runtime.Pinner
	)
	pinner.Pin(&value)
	defer pinner.Unpin()
	attr := C.CK_ATTRIBUTE{
		_type:      typ,
		pValue:     C.CK_VOID_PTR(&value),
		ulValueLen: C.CK_ULONG(unsafe.Sizeof(value)),
	}
	if err := o.ft.C_GetAttributeValue(o.h, o.o, &attr, 1); err != nil {
		return value, err
	}
	if attr.ulValueLen == 0 {
		return value, fmt.Errorf("pkcs11: missing attribute 0x%08x", typ)
	}
	return value, nil
}

func (o *Object) setAttribute(attrs []C.CK_ATTRIBUTE) error {
	return o.ft.C_SetAttributeValue(o.h, o.o, &attrs[0], C.CK_ULONG(len(attrs)))
}

// Label returns a string value attached to an object, which can be used to
// identify or group sets of keys and certificates.
func (o *Object) Label() (string, error) {
	v, err := o.getAttributesBytes([]attrType{C.CKA_LABEL}, false)
	if err != nil {
		return "", err
	}
	return string(v[0]), err
}

// setLabel sets the label of the object overwriting any previous value.
func (o *Object) setLabel(s string) error {
	var pinner runtime.Pinner
	defer pinner.Unpin()

	cs := []byte(s)
	pinner.Pin(&cs[0])

	attrs := []C.CK_ATTRIBUTE{{C.CKA_LABEL, C.CK_VOID_PTR(&cs[0]), C.CK_ULONG(len(s))}}
	return o.setAttribute(attrs)
}

// Certificate parses the underlying object as a certificate. If the object
// isn't a certificate, this method fails.
func (o *Object) Certificate() (*Certificate, error) {
	if o.Class() != ClassCertificate {
		return nil, fmt.Errorf("pkcs11: expected object class %v, got %v", ClassCertificate, o.Class())
	}
	ct, err := getAttribute[C.CK_CERTIFICATE_TYPE](o, C.CKA_CERTIFICATE_TYPE)
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

	kt, err := getAttribute[C.CK_KEY_TYPE](o, C.CKA_KEY_TYPE)
	if err != nil {
		return nil, err
	}
	switch kt {
	case C.CKK_EC:
		return o.ecdsaPublicKey()
	case C.CKK_RSA:
		return o.rsaPublicKey()
	default:
		return nil, fmt.Errorf("unsupported key type: 0x%08x", kt)
	}
}

func (o *Object) rsaPublicKey() (crypto.PublicKey, error) {
	// http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cs01/pkcs11-curr-v2.40-cs01.html#_Toc399398838
	attrs, err := o.getAttributesBytes([]attrType{C.CKA_MODULUS, C.CKA_PUBLIC_EXPONENT}, false)
	if err != nil {
		return nil, err
	}
	var n, e big.Int
	n.SetBytes(attrs[0])
	e.SetBytes(attrs[1])
	return &rsa.PublicKey{N: &n, E: int(e.Int64())}, nil
}

func (o *Object) ecdsaPublicKey() (crypto.PublicKey, error) {
	// http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cs01/pkcs11-curr-v2.40-cs01.html#_Toc399398881
	attrs, err := o.getAttributesBytes([]attrType{C.CKA_EC_PARAMS, C.CKA_EC_POINT}, false)
	if err != nil {
		return nil, err
	}

	paramBytes := attrs[0]
	pointBytes := attrs[1]

	var curve elliptic.Curve
	if bytes.Equal(paramBytes, p256OIDRaw) {
		curve = elliptic.P256()
	} else if bytes.Equal(paramBytes, p384OIDRaw) {
		curve = elliptic.P384()
	} else if bytes.Equal(paramBytes, p521OIDRaw) {
		curve = elliptic.P521()
	} else {
		return nil, fmt.Errorf("pkcs11: unsupported curve OID")
	}

	ptObj := cryptobyte.String(pointBytes)
	var pt cryptobyte.String
	if !ptObj.ReadASN1(&pt, asn1.OCTET_STRING) {
		return nil, fmt.Errorf("pkcs11: error decoding ec point: %w", err)
	}
	x, y := elliptic.Unmarshal(curve, pt)
	if x == nil {
		return nil, fmt.Errorf("pkcs11: invalid point format")
	}
	return &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}, nil
}

// PrivateKey parses the underlying object as a private key. Both RSA and ECDSA
// keys are supported.
//
// The returned PrivateKey implements crypto.Signer and optionally crypto.Decrypter
// depending on the supported mechanisms.
//
// If the object isn't a public key, this method fails.
func (o *Object) PrivateKey(pub crypto.PublicKey) (crypto.PrivateKey, error) {
	if o.Class() != ClassPrivateKey {
		return nil, fmt.Errorf("pkcs11: expected object class %v, got %v", ClassPrivateKey, o.Class())
	}

	kt, err := getAttribute[C.CK_KEY_TYPE](o, C.CKA_KEY_TYPE)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: error getting certificate type: %w", err)
	}
	switch kt {
	case C.CKK_EC:
		p, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("pkcs11: expected ecdsa public key, got: %T", pub)
		}
		return &ecdsaPrivateKey{o, p}, nil
	case C.CKK_RSA:
		p, ok := pub.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("pkcs11: expected rsa public key, got: %T", pub)
		}
		return &rsaPrivateKey{o, p}, nil
	default:
		return nil, fmt.Errorf("pkcs11: unsupported key type: 0x%08x", kt)
	}
}

// Precomputed ASN1 signature prefixes.
//
// Borrowed from crypto/rsa.
var hashPrefixes = map[crypto.Hash][]byte{
	crypto.SHA224: {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c},
	crypto.SHA256: {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},
	crypto.SHA384: {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30},
	crypto.SHA512: {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40},
}

type rsaPrivateKey struct {
	o   *Object
	pub *rsa.PublicKey
}

func (r *rsaPrivateKey) Public() crypto.PublicKey {
	return r.pub
}

func (r *rsaPrivateKey) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if o, ok := opts.(*rsa.PSSOptions); ok {
		return r.signPSS(digest, o)
	}

	// http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cs01/pkcs11-curr-v2.40-cs01.html#_Toc399398842
	size := opts.HashFunc().Size()
	if size != len(digest) {
		return nil, fmt.Errorf("pkcs11: input must be hashed")
	}
	prefix, ok := hashPrefixes[opts.HashFunc()]
	if !ok {
		return nil, fmt.Errorf("pkcs11: unsupported hash function: %v", opts.HashFunc())
	}

	preAndDigest := append(prefix, digest...)

	sig := make([]byte, r.pub.Size())
	sigLen := C.CK_ULONG(len(sig))

	m := C.CK_MECHANISM{
		mechanism: C.CKM_RSA_PKCS,
	}
	if err := r.o.ft.C_SignInit(r.o.h, &m, r.o.o); err != nil {
		return nil, err
	}
	if err := r.o.ft.C_Sign(r.o.h, (*C.CK_BYTE)(&preAndDigest[0]), C.CK_ULONG(len(preAndDigest)), (*C.CK_BYTE)(&sig[0]), &sigLen); err != nil {
		return nil, err
	}

	if int(sigLen) != len(sig) {
		return nil, fmt.Errorf("pkcs11: expected signature of length %d, got %d", len(sig), sigLen)
	}
	return sig, nil
}

func (r *rsaPrivateKey) signPSS(digest []byte, opts *rsa.PSSOptions) ([]byte, error) {
	// http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cs01/pkcs11-curr-v2.40-cs01.html#_Toc399398846
	// http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cs01/pkcs11-curr-v2.40-cs01.html#_Toc399398845
	var cParam C.CK_RSA_PKCS_PSS_PARAMS

	switch opts.Hash {
	case crypto.SHA256:
		cParam.hashAlg = C.CKM_SHA256
		cParam.mgf = C.CKG_MGF1_SHA256
	case crypto.SHA384:
		cParam.hashAlg = C.CKM_SHA384
		cParam.mgf = C.CKG_MGF1_SHA384
	case crypto.SHA512:
		cParam.hashAlg = C.CKM_SHA512
		cParam.mgf = C.CKG_MGF1_SHA512
	default:
		return nil, fmt.Errorf("pkcs11: unsupported hash algorithm: %v", opts.Hash)
	}

	switch opts.SaltLength {
	case rsa.PSSSaltLengthAuto:
		// Same logic as crypto/rsa.
		l := (r.pub.N.BitLen()-1+7)/8 - 2 - opts.Hash.Size()
		cParam.sLen = C.CK_ULONG(l)
	case rsa.PSSSaltLengthEqualsHash:
		cParam.sLen = C.CK_ULONG(opts.Hash.Size())
	default:
		cParam.sLen = C.CK_ULONG(opts.SaltLength)
	}

	sig := make([]byte, r.pub.Size())
	sigLen := C.CK_ULONG(len(sig))

	var pinner runtime.Pinner
	defer pinner.Unpin()
	pinner.Pin(&cParam)

	m := C.CK_MECHANISM{
		mechanism:      C.CKM_RSA_PKCS_PSS,
		pParameter:     C.CK_VOID_PTR(&cParam),
		ulParameterLen: C.CK_ULONG(unsafe.Sizeof(cParam)),
	}

	if err := r.o.ft.C_SignInit(r.o.h, &m, r.o.o); err != nil {
		return nil, err
	}
	if err := r.o.ft.C_Sign(r.o.h, (*C.CK_BYTE)(&digest[0]), C.CK_ULONG(len(digest)), (*C.CK_BYTE)(&sig[0]), &sigLen); err != nil {
		return nil, err
	}

	if int(sigLen) != len(sig) {
		return nil, fmt.Errorf("pkcs11: expected signature of length %d, got %d", len(sig), sigLen)
	}
	return []byte(sig), nil
}

type ecdsaPrivateKey struct {
	o   *Object
	pub *ecdsa.PublicKey
}

func (e *ecdsaPrivateKey) Public() crypto.PublicKey {
	return e.pub
}

func (e *ecdsaPrivateKey) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	// http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cs01/pkcs11-curr-v2.40-cs01.html#_Toc399398884
	m := C.CK_MECHANISM{
		mechanism: C.CKM_ECDSA,
	}
	if err := e.o.ft.C_SignInit(e.o.h, &m, e.o.o); err != nil {
		return nil, err
	}

	byteLen := (e.pub.Curve.Params().BitSize + 7) / 8
	sig := make([]byte, byteLen*2)
	sigLen := C.CK_ULONG(len(sig))

	if err := e.o.ft.C_Sign(e.o.h, (*C.CK_BYTE)(&digest[0]), C.CK_ULONG(len(digest)), (*C.CK_BYTE)(&sig[0]), &sigLen); err != nil {
		return nil, err
	}

	if int(sigLen) != len(sig) {
		return nil, fmt.Errorf("pkcs11: expected signature of length %d, got %d", len(sig), sigLen)
	}

	var (
		r = big.NewInt(0)
		s = big.NewInt(0)
	)
	r.SetBytes(sig[:len(sig)/2])
	s.SetBytes(sig[len(sig)/2:])

	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1BigInt(r)
		b.AddASN1BigInt(s)
	})

	return b.Bytes()
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

	raw, err := c.o.getAttributesBytes([]attrType{C.CKA_VALUE}, false)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(raw[0])
	if err != nil {
		return nil, fmt.Errorf("pkcs11: error parsing certificate: %w", err)
	}
	return cert, nil
}

// keyOptions holds parameters used for generating a private key.
type keyOptions struct {
	// RSABits indicates that the generated key should be a RSA key and also
	// provides the number of bits.
	RSABits int
	// ECDSACurve indicates that the generated key should be an ECDSA key and
	// identifies the curve used to generate the key.
	ECDSACurve elliptic.Curve

	// Label for the final object.
	LabelPublic  string
	LabelPrivate string
}

// https://datatracker.ietf.org/doc/html/rfc5480#section-2.1.1.1

// Generate a private key on the slot, creating associated private and public
// key objects.
func (s *Slot) generate(opts keyOptions) (crypto.PrivateKey, error) {
	if opts.ECDSACurve != nil && opts.RSABits != 0 {
		return nil, fmt.Errorf("conflicting key parameters provided")
	}
	if opts.ECDSACurve != nil {
		return s.generateECDSA(opts)
	}
	if opts.RSABits != 0 {
		return s.generateRSA(opts)
	}
	return nil, fmt.Errorf("no key parameters provided")
}

// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#_Toc416959719
// http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/os/pkcs11-curr-v2.40-os.html#_Toc416959971
func (s *Slot) generateRSA(o keyOptions) (crypto.PrivateKey, error) {
	var (
		mechanism = C.CK_MECHANISM{
			mechanism: C.CKM_RSA_PKCS_KEY_PAIR_GEN,
		}
		pubH  C.CK_OBJECT_HANDLE
		privH C.CK_OBJECT_HANDLE
	)

	var pinner runtime.Pinner
	defer pinner.Unpin()

	cTrue := C.CK_BBOOL(C.CK_TRUE)
	cFalse := C.CK_BBOOL(C.CK_FALSE)
	cModBits := C.CK_ULONG(o.RSABits)

	pinner.Pin(&cTrue)
	pinner.Pin(&cFalse)
	pinner.Pin(&cModBits)

	privTmpl := []C.CK_ATTRIBUTE{
		{C.CKA_PRIVATE, C.CK_VOID_PTR(&cTrue), C.CK_ULONG(unsafe.Sizeof(cTrue))},
		{C.CKA_SENSITIVE, C.CK_VOID_PTR(&cTrue), C.CK_ULONG(unsafe.Sizeof(cTrue))},
		{C.CKA_SIGN, C.CK_VOID_PTR(&cTrue), C.CK_ULONG(unsafe.Sizeof(cTrue))},
	}

	if o.LabelPrivate != "" {
		cs := []byte(o.LabelPrivate)
		pinner.Pin(&cs[0])

		privTmpl = append(privTmpl, C.CK_ATTRIBUTE{
			C.CKA_LABEL,
			C.CK_VOID_PTR(&cs[0]),
			C.CK_ULONG(len(o.LabelPrivate)),
		})
	}

	pubTmpl := []C.CK_ATTRIBUTE{
		{C.CKA_MODULUS_BITS, C.CK_VOID_PTR(&cModBits), C.CK_ULONG(unsafe.Sizeof(cModBits))},
		{C.CKA_VERIFY, C.CK_VOID_PTR(&cTrue), C.CK_ULONG(unsafe.Sizeof(cTrue))},
	}

	if o.LabelPublic != "" {
		cs := []byte(o.LabelPublic)
		pinner.Pin(&cs[0])

		pubTmpl = append(pubTmpl, C.CK_ATTRIBUTE{
			C.CKA_LABEL,
			C.CK_VOID_PTR(&cs[0]),
			C.CK_ULONG(len(o.LabelPublic)),
		})
	}

	err := s.ft.C_GenerateKeyPair(
		s.h, &mechanism,
		&pubTmpl[0], C.CK_ULONG(len(pubTmpl)),
		&privTmpl[0], C.CK_ULONG(len(privTmpl)),
		&pubH, &privH,
	)

	if err != nil {
		return nil, err
	}

	pubObj, err := s.newObject(pubH)
	if err != nil {
		return nil, fmt.Errorf("public key object: %w", err)
	}
	privObj, err := s.newObject(privH)
	if err != nil {
		return nil, fmt.Errorf("private key object: %w", err)
	}
	pub, err := pubObj.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("parsing public key: %w", err)
	}
	priv, err := privObj.PrivateKey(pub)
	if err != nil {
		return nil, fmt.Errorf("parsing private key: %w", err)
	}
	return priv, nil
}

// https://datatracker.ietf.org/doc/html/rfc5480#section-2.1.1.1
//
// Generated with https://play.golang.org/p/tkqXov5Xpwp
var (
	p256OIDRaw = []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}
	p384OIDRaw = []byte{0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22}
	p521OIDRaw = []byte{0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23}
)

// generateECDSA implements the CKM_ECDSA_KEY_PAIR_GEN mechanism.
//
// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#_Toc416959719
// https://datatracker.ietf.org/doc/html/rfc5480#section-2.1.1.1
// http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/os/pkcs11-curr-v2.40-os.html#_Toc416960014
func (s *Slot) generateECDSA(o keyOptions) (crypto.PrivateKey, error) {
	var (
		mechanism = C.CK_MECHANISM{
			mechanism: C.CKM_EC_KEY_PAIR_GEN,
		}
		pubH  C.CK_OBJECT_HANDLE
		privH C.CK_OBJECT_HANDLE
	)

	if o.ECDSACurve == nil {
		return nil, fmt.Errorf("no curve provided")
	}

	var pinner runtime.Pinner
	defer pinner.Unpin()

	var oid []byte
	switch o.ECDSACurve.Params().Name {
	case "P-256":
		oid = p256OIDRaw
	case "P-384":
		oid = p384OIDRaw
	case "P-521":
		oid = p521OIDRaw
	default:
		return nil, fmt.Errorf("unsupported ECDSA curve")
	}
	pinner.Pin(&oid[0])

	cTrue := C.CK_BBOOL(C.CK_TRUE)
	cFalse := C.CK_BBOOL(C.CK_FALSE)
	pinner.Pin(&cTrue)
	pinner.Pin(&cFalse)

	privTmpl := []C.CK_ATTRIBUTE{
		{C.CKA_PRIVATE, C.CK_VOID_PTR(&cTrue), C.CK_ULONG(unsafe.Sizeof(cTrue))},
		{C.CKA_SENSITIVE, C.CK_VOID_PTR(&cTrue), C.CK_ULONG(unsafe.Sizeof(cTrue))},
		{C.CKA_SIGN, C.CK_VOID_PTR(&cTrue), C.CK_ULONG(unsafe.Sizeof(cTrue))},
	}

	if o.LabelPrivate != "" {
		cs := []byte(o.LabelPrivate)
		pinner.Pin(&cs[0])

		privTmpl = append(privTmpl, C.CK_ATTRIBUTE{
			C.CKA_LABEL,
			C.CK_VOID_PTR(&cs[0]),
			C.CK_ULONG(len(o.LabelPrivate)),
		})
	}

	pubTmpl := []C.CK_ATTRIBUTE{
		{C.CKA_EC_PARAMS, C.CK_VOID_PTR(&oid[0]), C.CK_ULONG(len(oid))},
		{C.CKA_VERIFY, C.CK_VOID_PTR(&cTrue), C.CK_ULONG(unsafe.Sizeof(cTrue))},
	}
	if o.LabelPublic != "" {
		cs := []byte(o.LabelPublic)
		pinner.Pin(&cs[0])

		pubTmpl = append(pubTmpl, C.CK_ATTRIBUTE{
			C.CKA_LABEL,
			C.CK_VOID_PTR(&cs[0]),
			C.CK_ULONG(len(o.LabelPublic)),
		})
	}

	err := s.ft.C_GenerateKeyPair(
		s.h, &mechanism,
		&pubTmpl[0], C.CK_ULONG(len(pubTmpl)),
		&privTmpl[0], C.CK_ULONG(len(privTmpl)),
		&pubH, &privH,
	)

	if err != nil {
		return nil, err
	}

	pubObj, err := s.newObject(pubH)
	if err != nil {
		return nil, fmt.Errorf("public key object: %w", err)
	}
	privObj, err := s.newObject(privH)
	if err != nil {
		return nil, fmt.Errorf("private key object: %w", err)
	}
	pub, err := pubObj.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("parsing public key: %w", err)
	}
	priv, err := privObj.PrivateKey(pub)
	if err != nil {
		return nil, fmt.Errorf("parsing private key: %w", err)
	}
	return priv, nil
}

func (r *rsaPrivateKey) Decrypt(_ io.Reader, encryptedData []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	var m C.CK_MECHANISM

	if o, ok := opts.(*rsa.OAEPOptions); ok {
		var cParam C.CK_RSA_PKCS_OAEP_PARAMS

		switch o.Hash {
		case crypto.SHA256:
			cParam.hashAlg = C.CKM_SHA256
			cParam.mgf = C.CKG_MGF1_SHA256
		case crypto.SHA384:
			cParam.hashAlg = C.CKM_SHA384
			cParam.mgf = C.CKG_MGF1_SHA384
		case crypto.SHA512:
			cParam.hashAlg = C.CKM_SHA512
			cParam.mgf = C.CKG_MGF1_SHA512
		case crypto.SHA1:
			cParam.hashAlg = C.CKM_SHA_1
			cParam.mgf = C.CKG_MGF1_SHA1
		default:
			return nil, fmt.Errorf("pkcs11: unsupported hash algorithm: %v", o.Hash)
		}

		cParam.source = C.CKZ_DATA_SPECIFIED
		cParam.pSourceData = nil
		cParam.ulSourceDataLen = 0

		var pinner runtime.Pinner
		defer pinner.Unpin()
		pinner.Pin(&cParam)

		m = C.CK_MECHANISM{
			mechanism:      C.CKM_RSA_PKCS_OAEP,
			pParameter:     C.CK_VOID_PTR(&cParam),
			ulParameterLen: C.CK_ULONG(unsafe.Sizeof(cParam)),
		}
	} else {
		m = C.CK_MECHANISM{C.CKM_RSA_PKCS, nil, 0}
	}

	if err := r.o.ft.C_DecryptInit(r.o.h, &m, r.o.o); err != nil {
		return nil, err
	}

	var cDecryptedLen C.CK_ULONG

	// First call is used to determine length necessary to hold decrypted data (PKCS #11 5.2)
	if err := r.o.ft.C_Decrypt(r.o.h, (*C.CK_BYTE)(&encryptedData[0]), C.CK_ULONG(len(encryptedData)), nil, &cDecryptedLen); err != nil {
		return nil, err
	}

	decrypted := make([]byte, cDecryptedLen)

	if err := r.o.ft.C_Decrypt(r.o.h, (*C.CK_BYTE)(&encryptedData[0]), C.CK_ULONG(len(encryptedData)), (*C.CK_BYTE)(&decrypted[0]), &cDecryptedLen); err != nil {
		return nil, err
	}

	// Removes null padding (PKCS#11 5.2): http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#_Toc416959738
	return bytes.Trim(decrypted, "\x00"), nil
}

func toCBytes(data []byte) []C.CK_BYTE {
	cBytes := make([]C.CK_BYTE, len(data))
	for i, b := range data {
		cBytes[i] = C.CK_BYTE(b)
	}
	return cBytes
}

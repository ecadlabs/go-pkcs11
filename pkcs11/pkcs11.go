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

//go:generate go run ../gen/generate.go -i generate.h -h platform.h -g generated.go -p pkcs11

/*
#include "platform.h"
*/
import "C"
import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"runtime"
	"strings"
	"sync"
	"time"
	"unsafe"
)

type dynLibrary interface {
	close() error
}

type functionList = C.CK_FUNCTION_LIST

var ErrPublicKey = errors.New("pkcs11: no corresponding public key object found")
var ErrNonUnique = errors.New("pkcs11: non unique public key object")

// Module represents an opened shared library. By default, this package
// requests locking support from the module, but concurrent safety may
// depend on the underlying library.
type Module struct {
	// mod is a pointer to the dlopen handle. Kept around to dlfree
	// when the Module is closed.
	mod dynLibrary
	// List of C functions provided by the module.
	ft   functionTable
	info ModuleInfo
}

type OpenOption func(o *openOptions)

func OptLibraryCantCreateOsThreads(o *openOptions) {
	if o.args == nil {
		o.args = new(C.CK_C_INITIALIZE_ARGS)
	}
	o.args.flags |= C.CKF_LIBRARY_CANT_CREATE_OS_THREADS
}

func OptOsLockingOk(o *openOptions) {
	if o.args == nil {
		o.args = new(C.CK_C_INITIALIZE_ARGS)
	}
	o.args.flags |= C.CKF_OS_LOCKING_OK
}

type openOptions struct {
	args *C.CK_C_INITIALIZE_ARGS
}

// Open dlopens a shared library by path, initializing the module.
func Open(path string, opt ...OpenOption) (*Module, error) {
	funcs, module, err := openLibrary(path)
	if err != nil {
		return nil, err
	}

	ft := functionTable{t: funcs}

	var initOptions openOptions
	for _, o := range opt {
		o(&initOptions)
	}

	if err := ft.C_Initialize(C.CK_VOID_PTR(unsafe.Pointer(initOptions.args))); err != nil {
		module.close()
		return nil, err
	}

	var info C.CK_INFO
	if err := ft.C_GetInfo(&info); err != nil {
		module.close()
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
	return m.mod.close()
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

var slotFlagStr = []*struct {
	f   SlotFlags
	str string
}{
	{SlotTokenPresent, "CKF_TOKEN_PRESENT"},
	{SlotRemovableDevice, "CKF_REMOVABLE_DEVICE"},
	{SlotHWSlot, "CKF_HW_SLOT"},
}

func (s SlotFlags) String() string {
	var x []string
	for _, f := range slotFlagStr {
		if s&f.f != 0 {
			x = append(x, f.str)
		}
	}
	return strings.Join(x, "|")
}

type TokenInfo struct {
	Label              string
	Manufacturer       string
	Model              string
	SerialNumber       string
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
	UTCTime            time.Time
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

var tokenFlagStr = []*struct {
	f   TokenFlags
	str string
}{
	{TokenRNG, "CKF_RNG"},
	{TokenWriteProtected, "CKF_WRITE_PROTECTED"},
	{TokenLoginRequired, "CKF_LOGIN_REQUIRED"},
	{TokenUserPinInitialized, "CKF_USER_PIN_INITIALIZED"},
	{TokenRestoreKeyNotNeeded, "CKF_RESTORE_KEY_NOT_NEEDED"},
	{TokenClockOnToken, "CKF_CLOCK_ON_TOKEN"},
	{TokenProtectedAuthenticationPath, "CKF_PROTECTED_AUTHENTICATION_PATH"},
	{TokenDualCryptoOperations, "CKF_DUAL_CRYPTO_OPERATIONS"},
	{TokenTokenInitialized, "CKF_TOKEN_INITIALIZED"},
	{TokenSecondaryAuthentication, "CKF_SECONDARY_AUTHENTICATION"},
	{TokenUserPinCountLow, "CKF_USER_PIN_COUNT_LOW"},
	{TokenUserPinFinalTry, "CKF_USER_PIN_FINAL_TRY"},
	{TokenUserPinLocked, "CKF_USER_PIN_LOCKED"},
	{TokenUserPinToBeChanged, "CKF_USER_PIN_TO_BE_CHANGED"},
	{TokenSOPinCountLow, "CKF_SO_PIN_COUNT_LOW"},
	{TokenSOPinFinalTry, "CKF_SO_PIN_FINAL_TRY"},
	{TokenSOPinLocked, "CKF_SO_PIN_LOCKED"},
	{TokenSOPinToBeChanged, "CKF_SO_PIN_TO_BE_CHANGED"},
	{TokenErrorState, "CKF_ERROR_STATE"},
}

func (t TokenFlags) String() string {
	var x []string
	for _, f := range tokenFlagStr {
		if t&f.f != 0 {
			x = append(x, f.str)
		}
	}
	return strings.Join(x, "|")
}

func trimPadding(b []C.CK_UTF8CHAR) string {
	return strings.TrimRight(string(b), " ")
}

// Info returns additional information about the module.
func (m *Module) Info() *ModuleInfo {
	return &m.info
}

func parseUTCTime(data *[16]C.uchar) time.Time {
	b := unsafe.Slice((*byte)(&data[0]), len(*data))
	t, _ := time.Parse("2006010215040500", string(b))
	return t
}

func slotInfo(ft functionTable, slotID C.CK_SLOT_ID) (*SlotInfo, error) {
	var cSlotInfo C.CK_SLOT_INFO
	if err := ft.C_GetSlotInfo(slotID, &cSlotInfo); err != nil {
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
	if err := ft.C_GetTokenInfo(slotID, &cTokenInfo); err != nil {
		return nil, err
	}

	info.Token = &TokenInfo{
		Label:              trimPadding(cTokenInfo.label[:]),
		Manufacturer:       trimPadding(cTokenInfo.manufacturerID[:]),
		Model:              trimPadding(cTokenInfo.model[:]),
		SerialNumber:       trimPadding(cTokenInfo.serialNumber[:]),
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
		UTCTime:            parseUTCTime(&cTokenInfo.utcTime),
	}
	return &info, nil
}

// SlotInfo queries for information about the slot, such as the label.
func (m *Module) SlotInfo(id uint) (*SlotInfo, error) {
	return slotInfo(m.ft, C.CK_SLOT_ID(id))
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
func OptPIN(pin string) SessionOption {
	return func(o *sessionOptions) { o.pin = pin }
}

// OptUserPIN is an alias for OptPIN + OptUserType(UserTypeNormal)
func OptUserPIN(pin string) SessionOption {
	return func(o *sessionOptions) {
		o.pin = pin
		o.userType = UserTypeNormal
	}
}

// OptUserPIN is an alias for OptPIN + OptUserType(UserTypeSecurityOfficer)
func OptSecurityOfficerPIN(pin string) SessionOption {
	return func(o *sessionOptions) {
		o.pin = pin
		o.userType = UserTypeSecurityOfficer
	}
}

// OptPIN sets a user type for logging into a slot
func OptUserType(ut UserType) SessionOption {
	return func(o *sessionOptions) { o.userType = ut }
}

// OptReadWrite sets a read-write session mode
func OptReadWrite(o *sessionOptions) { o.flags |= C.CKF_RW_SESSION }

// NewSession creates a session with the given slot, by default read-only. Users
// must call Close to release the session.
//
// The returned NewSession's behavior is undefined once the Module is closed.
func (m *Module) NewSession(id uint, opts ...SessionOption) (*Session, error) {
	var so sessionOptions
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

	s := &Session{ft: m.ft, h: h, slotID: id}
	if so.pin != "" {
		cPIN := []C.CK_UTF8CHAR(so.pin)
		if err := s.ft.C_Login(s.h, C.CK_USER_TYPE(so.userType), &cPIN[0], C.CK_ULONG(len(cPIN))); err != nil {
			s.Close()
			return nil, err
		}
	}

	return s, nil
}

// Session represents a session to a slot.
//
// A slot holds a listable set of objects, such as certificates and
// cryptographic keys.
type Session struct {
	slotID uint
	ft     functionTable
	h      C.CK_SESSION_HANDLE
	mtx    sync.Mutex
}

type SessionOption func(o *sessionOptions)

type sessionOptions struct {
	pin      string
	userType UserType
	flags    C.CK_FLAGS
}

func (s *Session) SlotInfo() (*SlotInfo, error) {
	return slotInfo(s.ft, C.CK_SLOT_ID(s.slotID))
}

func (s *Session) SlotID() uint {
	return uint(s.slotID)
}

// Close releases the slot session.
func (s *Session) Close() error {
	return s.ft.C_CloseSession(s.h)
}

func (s *Session) newObject(o C.CK_OBJECT_HANDLE) (*Object, error) {
	obj := Object{slot: s, h: o}

	class := NewScalar[Class]()
	id := NewArray[[]byte](nil)
	label := NewArray[String](nil)
	if err := obj.GetAttributes(
		TypeValue{AttributeClass, class},
		TypeValue{AttributeID, id},
		TypeValue{AttributeLabel, label},
	); err != nil && !errors.Is(err, ErrAttributeTypeInvalid) && !errors.Is(err, ErrAttributeSensitive) {
		return nil, err
	}
	if class.IsNil() {
		return nil, errors.New("pkcs11: can't get object class")
	}
	obj.class = class.Value
	if !id.IsNil() {
		obj.id = id.Value
	}
	if !label.IsNil() {
		obj.label = label.Value
	}
	return &obj, nil
}

func (s *Session) NewObject(h uint) (*Object, error) {
	return s.newObject(C.CK_OBJECT_HANDLE(h))
}

// Objects searches a slot for objects that match the given options, or all
// objects if no options are provided.
//
// The returned objects behavior is undefined once the Session object is closed.
func (s *Session) Objects(filter ...TypeValue) (objs []*Object, err error) {
	var pinner runtime.Pinner
	defer pinner.Unpin()

	var attrs []C.CK_ATTRIBUTE
	if len(filter) != 0 {
		attrs = make([]C.CK_ATTRIBUTE, len(filter))
		for i, a := range filter {
			ptr := a.Value.ptr()
			pinner.Pin(ptr)
			attrs[i] = C.CK_ATTRIBUTE{
				_type:      C.CK_ATTRIBUTE_TYPE(a.Type),
				pValue:     C.CK_VOID_PTR(ptr),
				ulValueLen: C.CK_ULONG(a.Value.len()),
			}
		}
	}

	s.mtx.Lock()
	defer s.mtx.Unlock()

	if attrs != nil {
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

type KeyOptions struct {
	Label string
	ID    []byte
	Token bool
}

func (k *KeyOptions) fillTemplate(tpl *[]C.CK_ATTRIBUTE, pinner *runtime.Pinner) {
	cToken := C.CK_BBOOL(C.CK_FALSE)
	if k.Token {
		cToken = C.CK_BBOOL(C.CK_TRUE)
	}
	pinner.Pin(&cToken)
	*tpl = append(*tpl, C.CK_ATTRIBUTE{C.CKA_TOKEN, C.CK_VOID_PTR(&cToken), C.CK_ULONG(unsafe.Sizeof(cToken))})
	if k.Label != "" {
		cs := []byte(k.Label)
		pinner.Pin(&cs[0])
		*tpl = append(*tpl, C.CK_ATTRIBUTE{
			C.CKA_LABEL,
			C.CK_VOID_PTR(&cs[0]),
			C.CK_ULONG(len(cs)),
		})
	}
	if len(k.ID) != 0 {
		pinner.Pin(&k.ID[0])
		*tpl = append(*tpl, C.CK_ATTRIBUTE{
			C.CKA_OBJECT_ID,
			C.CK_VOID_PTR(&k.ID[0]),
			C.CK_ULONG(len(k.ID)),
		})
	}
}

// Object represents a single object stored within a slot. For example a key or
// certificate.
type Object struct {
	slot  *Session
	h     C.CK_OBJECT_HANDLE
	class Class
	id    []byte
	label []byte
}

// Class returns the type of the object stored. For example, certificate, public
// key, or private key.
func (o *Object) Class() Class {
	return o.class
}

func (o *Object) GetAttributes(attributes ...TypeValue) error {
	attrs := make([]C.CK_ATTRIBUTE, len(attributes))
	for i, a := range attributes {
		attrs[i]._type = C.CK_ATTRIBUTE_TYPE(a.Type)
	}
	if err := o.slot.ft.C_GetAttributeValue(o.slot.h, o.h, &attrs[0], C.CK_ULONG(len(attrs))); err != nil && !errors.Is(err, ErrAttributeTypeInvalid) && !errors.Is(err, ErrAttributeSensitive) {
		return err
	}
	var pinner runtime.Pinner
	defer pinner.Unpin()
	for i, a := range attributes {
		if ln := attrs[i].ulValueLen; ln != C.CK_UNAVAILABLE_INFORMATION {
			a.Value.allocate(int(ln))
			ptr := a.Value.ptr()
			pinner.Pin(ptr)
			attrs[i].pValue = C.CK_VOID_PTR(ptr)
		}
	}
	return o.slot.ft.C_GetAttributeValue(o.slot.h, o.h, &attrs[0], C.CK_ULONG(len(attrs)))
}

func (o *Object) GetAttribute(typ AttributeType, val Value) error {
	return o.GetAttributes(TypeValue{Type: typ, Value: val})
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
	ct := NewScalar[CertificateType]()
	if err := o.GetAttribute(AttributeCertificateType, ct); err != nil {
		return nil, err
	}
	return &Certificate{o, ct.Value}, nil
}

// PublicKey parses the underlying object as a public key. Both RSA and ECDSA
// keys are supported.
//
// If the object isn't a public key, this method fails.
func (o *Object) PublicKey() (PublicKey, error) {
	if o.Class() != ClassPublicKey {
		return nil, fmt.Errorf("pkcs11: expected object class %v, got %v", ClassPublicKey, o.Class())
	}

	kt := NewScalar[KeyType]()
	if err := o.GetAttribute(AttributeKeyType, kt); err != nil {
		return nil, err
	}
	return o.publicKey(kt.Value)
}

func (o *Object) publicKey(kt KeyType) (PublicKey, error) {
	switch kt {
	case KeyEC:
		return newECDSAPublicKey(o, nil)
	case KeyECEdwards:
		return newEd25519PublicKey(o, true)
	case KeyRSA:
		return newRSAPrivateKey(o)
	default:
		return nil, fmt.Errorf("unsupported key type: 0x%08x", kt)
	}
}

func (o *Object) sign(m *C.CK_MECHANISM, digest []byte) ([]byte, error) {
	o.slot.mtx.Lock()
	defer o.slot.mtx.Unlock()

	if err := o.slot.ft.C_SignInit(o.slot.h, m, o.h); err != nil {
		return nil, err
	}
	var sigLen C.CK_ULONG
	if err := o.slot.ft.C_Sign(o.slot.h, (*C.CK_BYTE)(&digest[0]), C.CK_ULONG(len(digest)), nil, &sigLen); err != nil {
		return nil, err
	}
	sig := make([]byte, sigLen)
	if err := o.slot.ft.C_Sign(o.slot.h, (*C.CK_BYTE)(&digest[0]), C.CK_ULONG(len(digest)), (*C.CK_BYTE)(&sig[0]), &sigLen); err != nil {
		return nil, err
	}
	return sig[:sigLen], nil
}

func (o *Object) decrypt(m *C.CK_MECHANISM, ciphertext []byte) ([]byte, error) {
	o.slot.mtx.Lock()
	defer o.slot.mtx.Unlock()

	if err := o.slot.ft.C_DecryptInit(o.slot.h, m, o.h); err != nil {
		return nil, err
	}
	var plainLen C.CK_ULONG
	if err := o.slot.ft.C_Decrypt(o.slot.h, (*C.CK_BYTE)(&ciphertext[0]), C.CK_ULONG(len(ciphertext)), nil, &plainLen); err != nil {
		return nil, err
	}
	plainText := make([]byte, plainLen)
	if err := o.slot.ft.C_Decrypt(o.slot.h, (*C.CK_BYTE)(&ciphertext[0]), C.CK_ULONG(len(ciphertext)), (*C.CK_BYTE)(&plainText[0]), &plainLen); err != nil {
		return nil, err
	}
	return plainText[:plainLen], nil
}

func (o *Object) encrypt(m *C.CK_MECHANISM, data []byte) ([]byte, error) {
	o.slot.mtx.Lock()
	defer o.slot.mtx.Unlock()

	if err := o.slot.ft.C_EncryptInit(o.slot.h, m, o.h); err != nil {
		return nil, err
	}
	var ciphertextLen C.CK_ULONG
	if err := o.slot.ft.C_Encrypt(o.slot.h, (*C.CK_BYTE)(&data[0]), C.CK_ULONG(len(data)), nil, &ciphertextLen); err != nil {
		return nil, err
	}
	ciphertext := make([]byte, ciphertextLen)
	if err := o.slot.ft.C_Encrypt(o.slot.h, (*C.CK_BYTE)(&data[0]), C.CK_ULONG(len(data)), (*C.CK_BYTE)(&ciphertext[0]), &ciphertextLen); err != nil {
		return nil, err
	}
	return ciphertext[:ciphertextLen], nil
}

type PublicKey interface {
	Object() *Object
	Public() crypto.PublicKey // Public returns stdlib compatible public key
}

type MatchFlags uint

const (
	MatchLabel MatchFlags = 1 << iota
	MatchID
)

// PrivateKey is a private key object without a corresponding public key.
// EdDSA and ECDSA private keys may optionally implement PublicKey if the object has a public key info.
// RSA private key also implements Decrypter.
type PrivateKey interface {
	Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error)
	Object() *Object

	kt() KeyType
	pubFilter() []TypeValue
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

	kt := NewScalar[KeyType]()
	if err := o.GetAttribute(AttributeKeyType, kt); err != nil {
		return nil, fmt.Errorf("pkcs11: error getting EC params: %w", err)
	}

	switch kt.Value {
	case KeyEC:
		return newECDSAPrivateKey(o, nil)
	case KeyECEdwards:
		return newEd25519PrivateKey(o, true)
	case KeyRSA:
		return newRSAPrivateKey(o)
	default:
		return nil, fmt.Errorf("pkcs11: unsupported key type: %v", kt.Value)
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
	t CertificateType
}

// Type returns the format of the underlying certificate.
func (c *Certificate) Type() CertificateType {
	return CertificateType(c.t)
}

func (c *Certificate) Object() *Object { return c.o }

// X509 parses the underlying certificate as an X.509 certificate.
//
// If the certificate holds a different type of certificate, this method
// returns an error.
func (c *Certificate) X509() (*x509.Certificate, error) {
	// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#_Toc416959712
	if c.t != CertificateX509 {
		return nil, fmt.Errorf("pkcs11: invalid certificate type: %v", CertificateType(c.t))
	}
	raw := NewArray[[]byte](nil)
	if err := c.o.GetAttribute(AttributeValue, raw); err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(raw.Value)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: error parsing certificate: %w", err)
	}
	return cert, nil
}

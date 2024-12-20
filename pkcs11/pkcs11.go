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
	"crypto/ecdsa"
	"crypto/ed25519"
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
	"time"
	"unsafe"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
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

func decodeOctetString(src []byte) []byte {
	x := cryptobyte.String(src)
	var pt cryptobyte.String
	if !x.ReadASN1(&pt, asn1.OCTET_STRING) {
		return nil
	}
	return pt
}

func decodeOID(src []byte) asn1enc.ObjectIdentifier {
	x := cryptobyte.String(src)
	var oid asn1enc.ObjectIdentifier
	if !x.ReadASN1ObjectIdentifier(&oid) {
		return nil
	}
	return oid
}

func decodePrintable(src []byte) (string, bool) {
	x := cryptobyte.String(src)
	var curve cryptobyte.String
	if !x.ReadASN1(&curve, asn1.PrintableString) {
		return "", false
	}
	return string(curve), true
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
func (o *Object) PublicKey() (crypto.PublicKey, error) {
	if o.Class() != ClassPublicKey {
		return nil, fmt.Errorf("pkcs11: expected object class %v, got %v", ClassPublicKey, o.Class())
	}

	kt := NewScalar[KeyType]()
	if err := o.GetAttribute(AttributeKeyType, kt); err != nil {
		return nil, err
	}
	return o.publicKey(kt.Value)
}

func (o *Object) publicKey(kt KeyType) (crypto.PublicKey, error) {
	switch kt {
	case KeyEC:
		return o.ecdsaPublicKey()
	case KeyECEdwards:
		return o.ed25519PublicKey()
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
	ecParams := NewArray[[]byte](nil)
	ecPoint := NewArray[[]byte](nil)
	if err := o.GetAttributes(TypeValue{AttributeECParams, ecParams}, TypeValue{AttributeECPoint, ecPoint}); err != nil {
		return nil, err
	}

	oid := decodeOID(ecParams.Value)
	if oid == nil {
		return nil, errors.New("pkcs11: error decoding curve OID")
	}
	curve := oidToCurve(oid)
	if curve == nil {
		return nil, fmt.Errorf("pkcs11: unsupported curve %v", oid)
	}

	pt := decodeOctetString(ecPoint.Value)
	if pt == nil {
		return nil, fmt.Errorf("pkcs11: error decoding EC point")
	}

	x, y := elliptic.Unmarshal(curve, pt)
	if x == nil {
		return nil, errors.New("pkcs11: invalid EC point format")
	}
	return &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}, nil
}

func oidToCurve(oid asn1enc.ObjectIdentifier) elliptic.Curve {
	switch {
	case oid.Equal(oidCurveP224):
		return elliptic.P224()
	case oid.Equal(oidCurveP256):
		return elliptic.P256()
	case oid.Equal(oidCurveP384):
		return elliptic.P384()
	case oid.Equal(oidCurveP521):
		return elliptic.P521()
	case oid.Equal(oidCurveS256):
		return secp256k1.S256()
	default:
		return nil
	}
}

func (o *Object) ed25519PublicKey() (ed25519.PublicKey, error) {
	ecParams := NewArray[[]byte](nil)
	ecPoint := NewArray[[]byte](nil)
	if err := o.GetAttributes(TypeValue{AttributeECParams, ecParams}, TypeValue{AttributeECPoint, ecPoint}); err != nil {
		return nil, err
	}

	curve, ok := decodePrintable(ecParams.Value)
	if !ok {
		return nil, fmt.Errorf("pkcs11: error decoding curve ID")
	}
	if curve != ed25519Curve {
		return nil, fmt.Errorf("pkcs11: unsupported curve %s", string(curve))
	}

	pt := decodeOctetString(ecPoint.Value)
	if pt == nil {
		return nil, fmt.Errorf("pkcs11: error decoding EC point")
	}
	if len(pt) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("pkcs11: invalid Ed25519 public key length %d", len(pt))
	}
	return ed25519.PublicKey(pt), nil
}

func (o *Object) publicKeyReuseOrAdjacent(flags MatchFlags, kt KeyType, optFilter ...TypeValue) (crypto.PublicKey, error) {
	if flags&ExtendedPrivate != 0 {
		pub, err := o.publicKey(kt)
		if err == nil {
			return pub, nil
		} else if !errors.Is(err, ErrAttributeTypeInvalid) {
			return nil, err
		}
	}

	fl := make([]TypeValue, 0, 4+len(optFilter))
	fl = append(fl, TypeValue{AttributeClass, NewScalarV(ClassPublicKey)}, TypeValue{AttributeKeyType, NewScalarV(kt)})
	if flags&MatchLabel != 0 && len(o.label) != 0 {
		fl = append(fl, TypeValue{AttributeLabel, NewArray(o.label)})
	}
	if flags&MatchID != 0 && len(o.id) != 0 {
		fl = append(fl, TypeValue{AttributeID, NewArray(o.id)})
	}
	fl = append(fl, optFilter...)

	objects, err := o.slot.Objects(fl...)
	if err != nil {
		return nil, err
	}
	if len(objects) == 0 {
		return nil, ErrPublicKey
	} else if len(objects) > 1 {
		return nil, ErrNonUnique
	}
	return objects[0].publicKey(kt)
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
	// ExtendedPrivate makes KeyPair to read public key value from the private key object. It's present in some implementations
	ExtendedPrivate
)

// PrivateKey is a private key object without a corresponding public key. It implements Signer and optionally Decrypter
// interfaces (for RSA) but not crypto.Signer and crypto.Decrypter
type PrivateKey interface {
	Signer
	// KeyPair finds an adjacent public key in the same slot. If there is more than one public key found then
	// it returns one with the matching ID if the latter is present
	KeyPair(flags MatchFlags) (KeyPair, error)
	AddPublic(pub crypto.PublicKey) (KeyPair, error)
	Handle() uint
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

	kt := NewScalar[KeyType]()
	if err := o.GetAttribute(AttributeKeyType, kt); err != nil {
		return nil, fmt.Errorf("pkcs11: error getting EC params: %w", err)
	}

	switch kt.Value {
	case KeyEC:
		return newECDSAPrivateKey(o)
	case KeyECEdwards:
		return newEd25519PrivateKey(o)
	default:
		return nil, fmt.Errorf("pkcs11: unsupported key type: %v", kt.Value)
	}
}

type ECDSAPrivateKey struct {
	o   *Object
	oid asn1enc.ObjectIdentifier
}

func newECDSAPrivateKey(o *Object) (*ECDSAPrivateKey, error) {
	ecParams := NewArray[[]byte](nil)
	if err := o.GetAttribute(AttributeECParams, ecParams); err != nil {
		return nil, err
	}
	oid := decodeOID(ecParams.Value)
	if oid == nil {
		return nil, errors.New("pkcs11: error decoding curve OID")
	}
	return &ECDSAPrivateKey{
		o:   o,
		oid: oid,
	}, nil
}

func (e *ECDSAPrivateKey) Handle() uint { return e.o.Handle() }

func (e *ECDSAPrivateKey) ecParams() []byte {
	var b cryptobyte.Builder
	b.AddASN1ObjectIdentifier(e.oid)
	return b.BytesOrPanic()
}

func (e *ECDSAPrivateKey) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	e.o.slot.mtx.Lock()
	defer e.o.slot.mtx.Unlock()

	// http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cs01/pkcs11-curr-v2.40-cs01.html#_Toc399398884
	m := C.CK_MECHANISM{
		mechanism: C.CKM_ECDSA,
	}
	if err := e.o.slot.ft.C_SignInit(e.o.slot.h, &m, e.o.h); err != nil {
		return nil, err
	}
	var sigLen C.CK_ULONG
	if err := e.o.slot.ft.C_Sign(e.o.slot.h, (*C.CK_BYTE)(&digest[0]), C.CK_ULONG(len(digest)), nil, &sigLen); err != nil {
		return nil, err
	}
	sig := make([]byte, sigLen)
	if err := e.o.slot.ft.C_Sign(e.o.slot.h, (*C.CK_BYTE)(&digest[0]), C.CK_ULONG(len(digest)), (*C.CK_BYTE)(&sig[0]), &sigLen); err != nil {
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

func curveEq(a, b elliptic.Curve) bool {
	ap, bp := a.Params(), b.Params()
	return ap.BitSize == bp.BitSize &&
		ap.P.Cmp(bp.P) == 0 &&
		ap.N.Cmp(bp.N) == 0 &&
		ap.B.Cmp(bp.B) == 0 &&
		ap.Gx.Cmp(bp.Gx) == 0 &&
		ap.Gy.Cmp(bp.Gy) == 0
}

func (e *ECDSAPrivateKey) AddPublic(pub crypto.PublicKey) (KeyPair, error) {
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("pkcs11: invalid public key type %T", pub)
	}
	curve := oidToCurve(e.oid)
	if curve == nil {
		return nil, fmt.Errorf("pkcs11: unsupported curve %v", e.oid)
	}
	if !curveEq(ecPub.Curve, curve) {
		return nil, fmt.Errorf("pkcs11: mismatched curve type, got %T, expected %T", ecPub.Curve, curve)
	}

	return &ECDSAKeyPair{
		ECDSAPrivateKey: e,
		PublicKey:       ecPub,
	}, nil
}

func (e *ECDSAPrivateKey) KeyPair(flags MatchFlags) (KeyPair, error) {
	pub, err := e.o.publicKeyReuseOrAdjacent(flags, KeyEC, TypeValue{AttributeECParams, NewArray(e.ecParams())})
	if err != nil {
		return nil, err
	}
	return &ECDSAKeyPair{
		ECDSAPrivateKey: e,
		PublicKey:       pub.(*ecdsa.PublicKey),
	}, nil
}

type ECDSAKeyPair struct {
	*ECDSAPrivateKey
	PublicKey *ecdsa.PublicKey
}

func (p *ECDSAKeyPair) Public() crypto.PublicKey {
	return p.PublicKey
}

const ed25519Curve = "edwards25519"

type Ed25519PrivateKey Object

func encodePrintable(src string) []byte {
	var b cryptobyte.Builder
	b.AddASN1(asn1.PrintableString, func(child *cryptobyte.Builder) {
		child.AddBytes([]byte(src))
	})
	return b.BytesOrPanic()
}

func newEd25519PrivateKey(o *Object) (*Ed25519PrivateKey, error) {
	ecParams := NewArray[[]byte](nil)
	if err := o.GetAttribute(AttributeECParams, ecParams); err != nil {
		return nil, err
	}

	curve, ok := decodePrintable(ecParams.Value)
	if !ok {
		return nil, fmt.Errorf("pkcs11: error decoding curve ID")
	}
	if curve != ed25519Curve {
		return nil, fmt.Errorf("pkcs11: unsupported curve %s", string(curve))
	}
	return (*Ed25519PrivateKey)(o), nil
}

func (e *Ed25519PrivateKey) Handle() uint { return (*Object)(e).Handle() }

func (e *Ed25519PrivateKey) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	e.slot.mtx.Lock()
	defer e.slot.mtx.Unlock()

	m := C.CK_MECHANISM{
		mechanism: C.CKM_EDDSA,
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
	return sig, nil
}

func (e *Ed25519PrivateKey) KeyPair(flags MatchFlags) (KeyPair, error) {
	pub, err := (*Object)(e).publicKeyReuseOrAdjacent(flags, KeyECEdwards, TypeValue{AttributeECParams, NewArray(encodePrintable(ed25519Curve))})
	if err != nil {
		return nil, err
	}
	return &Ed25519KeyPair{
		Ed25519PrivateKey: e,
		PublicKey:         pub.(ed25519.PublicKey),
	}, nil
}

type Ed25519KeyPair struct {
	*Ed25519PrivateKey
	PublicKey ed25519.PublicKey
}

func (p *Ed25519KeyPair) Public() crypto.PublicKey {
	return p.PublicKey
}

func (e *Ed25519PrivateKey) AddPublic(pub crypto.PublicKey) (KeyPair, error) {
	edPub, ok := pub.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("pkcs11: invalid public key type %T", pub)
	}
	if len(edPub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("pkcs11: invalid ed25519 public key length %d", len(edPub))
	}
	return &Ed25519KeyPair{
		Ed25519PrivateKey: e,
		PublicKey:         edPub,
	}, nil
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

func (c *Certificate) Handle() uint { return c.o.Handle() }

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

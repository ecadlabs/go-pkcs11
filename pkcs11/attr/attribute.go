package attr

/*
#include "../platform.h"
*/
import "C"
import (
	"encoding/hex"
	"fmt"
	"math/big"
	"strconv"
	"unsafe"
)

//go:generate go run gen/generate.go

type RawAttribute C.CK_ATTRIBUTE

type AttributeValue interface {
	String() string
	IsNil() bool

	Allocate(size int)
	Len() int
	Ptr() unsafe.Pointer
}

type Attribute interface {
	AttributeValue
	Type() Type
}

type Uint C.CK_ULONG

func (u Uint) String() string { return fmt.Sprintf("%#016x", C.CK_ULONG(u)) }

type Bool C.CK_BBOOL

func (b Bool) ToBool() bool   { return b != 0 }
func (b Bool) String() string { return fmt.Sprintf("%t", b.ToBool()) }

type String []byte

func (s String) String() string { return string(s) }

type Bytes []byte

func (b Bytes) String() string { return hex.EncodeToString(b) }

type BigInt []byte

func (b BigInt) String() string { return new(big.Int).SetBytes(b).String() }

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

type Scalar[T any] struct {
	Value T
	Valid bool
}

func (t *Scalar[T]) String() string {
	if !t.Valid {
		return "<undefined>"
	}
	return fmt.Sprintf("%v", &t.Value)
}

func (t *Scalar[T]) IsNil() bool         { return !t.Valid }
func (t *Scalar[T]) Allocate(size int)   { t.Valid = true }
func (t *Scalar[T]) Len() int            { return int(unsafe.Sizeof(t.Value)) }
func (t *Scalar[T]) Ptr() unsafe.Pointer { return unsafe.Pointer(&t.Value) }

type Array[T ~[]E, E any] struct {
	Value T
}

func (t *Array[T, E]) String() string {
	if t.Value == nil {
		return "<undefined>"
	}
	return fmt.Sprintf("%v", t.Value)
}

func (t *Array[T, E]) IsNil() bool { return t.Value == nil }

func (t *Array[T, E]) Allocate(size int) {
	t.Value = make(T, size/int(unsafe.Sizeof(t.Value[0])))
}

func (t *Array[T, E]) Len() int {
	return len(t.Value) * int(unsafe.Sizeof(t.Value[0]))
}

func (t *Array[T, E]) Ptr() unsafe.Pointer {
	if len(t.Value) != 0 {
		return unsafe.Pointer(&t.Value[0])
	}
	return nil
}

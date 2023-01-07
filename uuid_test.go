package uuid

import (
	"fmt"
	"io"
	"strings"
	"testing"
)

func must(t *testing.T, f func() (UUID, error)) UUID {
	uid, err := f()
	if err != nil {
		t.Fatal("unexpected error:", err)
	}

	return uid
}

func ExampleNew() {
	uid, err := New()
	if err != nil {
		panic(err)
	}

	fmt.Println(IsV4(uid))
	// Output: true
}

func ExampleNewV4Generator() {
	// using secure random reader.
	v4 := NewV4Generator(SecureReader)
	uid, err := v4.NewUUID()
	if err != nil {
		panic(err)
	}

	fmt.Println("secure", IsV4(uid))

	v4 = NewV4Generator(StaticReader)
	uid, err = v4.NewUUID()
	if err != nil {
		panic(err)
	}

	fmt.Println("static", IsV4(uid))

	// Output:
	// secure true
	// static true
}

func TestNew(t *testing.T) {
	uid1 := must(t, New)
	if uid1 == Nil {
		t.Fatal("unexpected nil uuid")
	}

	uid2 := must(t, New)
	if uid2 == Nil {
		t.Fatal("unexpected nil uuid")
	}

	if uid1 == uid2 {
		t.Fatal("unexpected equal uuid")
	}
}

func TestNewV4_SecureReader(t *testing.T) {
	v4 := NewV4Generator(SecureReader)

	uid1 := must(t, v4.NewUUID)
	if uid1 == Nil {
		t.Fatal("unexpected nil uuid")
	}

	uid2 := must(t, v4.NewUUID)
	if uid2 == Nil {
		t.Fatal("unexpected nil uuid")
	}

	if uid1 == uid2 {
		t.Fatal("unexpected equal uuid")
	}
}

func TestNewV4_StaticReader(t *testing.T) {
	v4 := NewV4Generator(StaticReader)

	uid1 := must(t, v4.NewUUID)
	if uid1 == Nil {
		t.Fatal("unexpected nil uuid")
	}

	uid2 := must(t, v4.NewUUID)
	if uid2 == Nil {
		t.Fatal("unexpected nil uuid")
	}

	if uid1 != uid2 {
		t.Fatal("unexpected not equal uuid")
	}
}

func TestNewV4_ErrorsReader(t *testing.T) {
	v4 := NewV4Generator(ErrorsReader)
	_, err := v4.NewUUID()
	if err != io.EOF {
		t.Fatal("unexpected error:", err)
	}
}

func TestUUID_String(t *testing.T) {
	v4 := NewV4Generator(StaticReader)
	uid := must(t, v4.NewUUID)
	if uid.String() != StaticUUID {
		t.Fatal("unexpected uuid:", uid)
	}
}

func TestIsV4(t *testing.T) {
	if !IsV4(Nil) {
		t.Error("Nil should be a valid v4 uuid")
	}

	v4 := NewV4Generator(StaticReader)
	uid := must(t, v4.NewUUID)
	if !IsV4(uid) {
		t.Fatal("unexpected uuid:", uid)
	}

	// takes 100 random samples.
	for i := 0; i < 100; i++ {
		uid = must(t, New)
		if !IsV4(uid) {
			t.Fatal("unexpected uuid:", uid)
		}
	}
}

func TestIsV4_Errors(t *testing.T) {
	// the version bits is not 0100 in binary (or 0x40 in hex)
	uid := UUID{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	uid[6] = 0x30
	if IsV4(uid) {
		t.Error("it should not be a v4 uuid")
	}

	// the variant bits is not 1010 in binary (or 0x80 in hex)
	uid = UUID{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	uid[6] = 0x40
	uid[8] = 0x70
	if IsV4(uid) {
		t.Error("it should not be a v4 uuid")
	}
}

func TestParse(t *testing.T) {
	v4 := NewV4Generator(StaticReader)
	uid := must(t, v4.NewUUID)

	uid2, err := Parse(uid.String())
	if err != nil {
		t.Fatal("unexpected error:", err)
	}

	if uid != uid2 {
		t.Fatal("unexpected uuid:", uid)
	}

	if uid2.String() != StaticUUID {
		t.Fatal("unexpected uuid:", uid)
	}
}

func TestParse_Errors(t *testing.T) {
	table := []struct {
		name string
		in   string
	}{
		{"empty", ""},
		{"short", "12345678-1234-1234-1234-1234567890"},
		{"long", "12345678-1234-1234-1234-1234567890123"},
		{"invalid chars", "12345678-1234-1234-1234-12345678901g"},
		{"only dashes", "------------------------------------"},
		{"invalid dashes position", "123456781234-1234-1234-1234567890120"},
		{"invalid dashes position", "-12345678-1234-1234-12341234567890120"},
		{"no dashes", strings.Repeat("a", 36)},
	}

	for _, tt := range table {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			uid, err := Parse(tt.in)
			if err == nil {
				t.Fatal("expected error, got nil")
			}

			if uid != Nil {
				t.Fatal("unexpected nil uuid:", uid)
			}
		})
	}
}

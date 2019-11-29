package donut

import (
	"bytes"
	"encoding/binary"
	"log"
	"testing"
)

var (
	// 128-bit master key
	key = []byte{0x56, 0x09, 0xe9, 0x68, 0x5f, 0x58, 0xe3, 0x29,
		0x40, 0xec, 0xec, 0x98, 0xc5, 0x22, 0x98, 0x2f}
	// 128-bit plain text
	plain = []byte{0xb8, 0x23, 0x28, 0x26, 0xfd, 0x5e, 0x40, 0x5e,
		0x69, 0xa3, 0x01, 0xa9, 0x78, 0xea, 0x7a, 0xd8}
	// 128-bit cipher text
	cipher = []byte{0xd5, 0x60, 0x8d, 0x4d, 0xa2, 0xbf, 0x34, 0x7b,
		0xab, 0xf8, 0x77, 0x2f, 0xdf, 0xed, 0xde, 0x07}
)

func Test_Chaskey_1(t *testing.T) {
	data := plain
	outdata := Chaskey(key, data)

	if bytes.Compare(outdata, cipher) == 0 {
		t.Log("Chaskey Test Passed")
	} else {
		t.Log("Chaskey Test Failed\n", outdata, cipher)
		t.Fail()
	}
}

func Test_Maru_1(t *testing.T) {
	iv := binary.LittleEndian.Uint64([]byte{0, 0, 0, 0, 0, 0, 0, 0})
	dllHash := Maru([]byte("oleaut32.dll"), iv)
	hash := Maru([]byte("SafeArrayCreateVector"), iv) ^ dllHash
	log.Printf("Hash: %x (dllHash was %x)\n", hash, dllHash)

	if 0xbd77af2569689c8a == hash {
		t.Log("Maru Test Passed")
	} else {
		t.Log("Maru Test Failed\n")
		t.Fail()
	}
}

func Test_Maru_2(t *testing.T) {

	iv := binary.LittleEndian.Uint64([]byte{0xEB, 0xA7, 0xF4, 0xDE, 0x07, 0x5B, 0xF8, 0x88})
	dllHash := Maru([]byte("kernel32.dll"), iv)
	hash := Maru([]byte("Sleep"), iv) ^ dllHash
	log.Printf("Hash: %x (dllHash was %x)\n", hash, dllHash)

	//0x17, 0xFC, 0xA0, 0x40, 0xD2, 0xBA, 0x66, 0xC7
	if 0xc766bad240a0fc17 == hash {
		t.Log("Maru Test Passed")
	} else {
		t.Log("Maru Test Failed\n")
		t.Fail()
	}
}

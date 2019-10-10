package donut

import (
	"bufio"
	"bytes"
	"encoding/binary"
)

// Chaskey Implementation ported from donut

const (
	// CipherBlockLen - Chaskey Block Length
	CipherBlockLen = uint32(128 / 8)
	// CipherKeyLen - Chaskey Key Length
	CipherKeyLen = uint32(128 / 8)
)

// ROTR32 - rotates a byte right (same as (32 - n) left)
func ROTR32(v uint32, n uint32) uint32 {
	return (v >> n) | (v << (32 - n))
}

// Chaskey Encryption Function
func Chaskey(masterKey []byte, data []byte) []byte {
	// convert inputs to []uint32
	mk := BytesToUint32s(masterKey)
	p := BytesToUint32s(data)

	// add 128-bit master key
	for i := 0; i < 4; i++ {
		p[i] ^= mk[i]
	}
	// apply 16 rounds of permutation
	for i := 0; i < 16; i++ {
		p[0] += p[1]
		p[1] = ROTR32(p[1], 27) ^ p[0]
		p[2] += p[3]
		p[3] = ROTR32(p[3], 24) ^ p[2]
		p[2] += p[1]
		p[0] = ROTR32(p[0], 16) + p[3]
		p[3] = ROTR32(p[3], 19) ^ p[0]
		p[1] = ROTR32(p[1], 25) ^ p[2]
		p[2] = ROTR32(p[2], 16)
	}
	// add 128-bit master key
	for i := 0; i < 4; i++ {
		p[i] ^= mk[i]
	}
	// convert to []byte for XOR phase
	b := bytes.NewBuffer([]byte{})
	w := bufio.NewWriter(b)
	for _, v := range p {
		binary.Write(w, binary.LittleEndian, v)
	}
	w.Flush()
	return b.Bytes()
}

// BytesToUint32s - converts a Byte array to an array of uint32s
func BytesToUint32s(inbytes []byte) []uint32 {
	mb := bytes.NewBuffer(inbytes)
	r := bufio.NewReader(mb)
	var outints []uint32
	for i := 0; i < len(inbytes); i = i + 4 {
		var tb uint32
		binary.Read(r, binary.LittleEndian, &tb)
		outints = append(outints, tb)
	}
	return outints
}

// Encrypt - encrypt/decrypt data in counter mode
func Encrypt(mk []byte, ctr []byte, data []byte, length uint32) []byte {
	var x []byte   //todo: verify this is always CipherBlockLen
	p := uint32(0) // data index
	c := uint32(0) // ctr index

	for length > 0 {
		// copy counter+nonce to local buffer
		for i := uint32(0); i < CipherBlockLen; i++ {
			x[i] = ctr[i+c]
		}
		// donut_encrypt x
		x = Chaskey(mk, x)

		// XOR plaintext with ciphertext
		r := uint32(0)
		if length > CipherBlockLen {
			r = CipherBlockLen
		} else {
			r = length
		}
		for i := uint32(0); i < r; i++ {
			data[i+p] ^= x[i]
		}
		// update length + position
		length -= r
		p += r

		// update counter
		for i := CipherBlockLen; i > 0; i-- {
			c++
			if ctr[c+i-1] != 0 {
				break
			}
		}
	}
	return x
}

// Speck 64/128
func Speck(mk []byte, p uint64) uint64 {
	w := make([]uint32, 2)
	var buf []byte
	binary.LittleEndian.PutUint64(buf, p)
	r := bytes.NewReader(buf)
	binary.Read(r, binary.LittleEndian, &w[0])
	binary.Read(r, binary.LittleEndian, &w[1])
	k := make([]uint32, 4)
	r = bytes.NewReader(mk)
	for c := 0; c < 4; c++ {
		binary.Read(r, binary.LittleEndian, &k[c])
	}

	for i := uint32(0); i < 27; i++ {
		// encrypt 64-bit plaintext
		w[0] = (ROTR32(w[0], 8) + w[1]) ^ k[0]
		w[1] = ROTR32(w[1], 29) ^ w[0]

		// create next 32-bit subkey
		t := k[3]
		k[3] = (ROTR32(k[1], 8) + k[0]) ^ i
		k[0] = ROTR32(k[0], 29) ^ k[3]
		k[1] = k[2]
		k[2] = t
	}

	// return 64-bit ciphertext
	b := bytes.NewBuffer([]byte{})
	binary.Write(b, binary.LittleEndian, w[0])
	binary.Write(b, binary.LittleEndian, w[1])
	num := binary.LittleEndian.Uint64(b.Bytes())
	return num
}

// Maru hash
func Maru(input []byte, iv []byte) uint64 { // todo: iv and return must be 8 bytes

	// set H to initial value
	h := binary.LittleEndian.Uint64(iv)
	b := make([]byte, MARU_BLK_LEN)

	idx := 0
	len := 0
	for end := 0; end != 0; {
		// end of string or max len?
		if input[len] == 0 || len == MARU_MAX_STR {
			// zero remainder of M
			for j := idx; j < MARU_BLK_LEN-idx; j++ {
				b[j] = 0
			}
			// store the end bit
			b[idx] = 0x80
			// have we space in M for api length?
			if idx >= MARU_BLK_LEN-4 {
				// no, update H with E
				h ^= Speck(b, h)
				// zero M
				b = make([]byte, MARU_BLK_LEN)
			}
			// store total length in bits
			binary.LittleEndian.PutUint32(b[MARU_BLK_LEN-4:], uint32(len)*8)
			idx = MARU_BLK_LEN
			end++
		} else {
			// store character from api string
			b[idx] = input[len]
			idx++
			len++
		}
		if idx == MARU_BLK_LEN {
			// update H with E
			h ^= Speck(b, h)
			// reset idx
			idx = 0
		}
	}
	return h
}

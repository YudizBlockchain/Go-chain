package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"hash"
	"math/big"
	"math/bits"
)

type Wallet struct {
	PrivateKey ecdsa.PrivateKey
	PublicKey  []byte
}

type Wallets struct {
	Wallets map[string]*Wallet
}

func main() {

	var wa *Wallet
	var address []byte
	_ = wa
	wa = NewWallet()
	address = wa.GetAddress()
	fmt.Println("wallet address = ", address)
	address = Base58Decode(address)

	fmt.Println("wallet address = ", address)
	// fmt.Println("Private keys %d", wa.PrivateKey)
	// fmt.Println("Public key %d", wa.PublicKey)

}

func NewWallet() *Wallet {
	private, public := newKeyPair()
	wallet := Wallet{private, public}

	return &wallet
}

func newKeyPair() (ecdsa.PrivateKey, []byte) {
	curve := elliptic.P256()
	private, err := ecdsa.GenerateKey(curve, rand.Reader)
	_ = err
	pubKey := append(private.PublicKey.X.Bytes(), private.PublicKey.Y.Bytes()...)

	return *private, pubKey
}
func (w Wallet) GetAddress() []byte {

	var version byte = 06

	pubKeyHash := HashPubKey(w.PublicKey)

	versionedPayload := append([]byte{version}, pubKeyHash...)
	checksum := checksum(versionedPayload)

	fullPayload := append(versionedPayload, checksum...)
	address := Base58Encode(fullPayload)

	return address
}

func HashPubKey(pubKey []byte) []byte {
	publicSHA256 := sha256.Sum256(pubKey)

	RIPEMD160Hasher := prateek()
	_, err := RIPEMD160Hasher.Write(publicSHA256[:])
	_ = err
	publicRIPEMD160 := RIPEMD160Hasher.Sum(nil)

	return publicRIPEMD160
}

func checksum(payload []byte) []byte {
	firstSHA := sha256.Sum256(payload)
	secondSHA := sha256.Sum256(firstSHA[:])
	addressChecksumLen := 6
	return secondSHA[:addressChecksumLen]
}
func Base58Encode(input []byte) []byte {
	var result []byte

	x := big.NewInt(0).SetBytes(input)

	base := big.NewInt(int64(len(b58Alphabet)))
	zero := big.NewInt(0)
	mod := &big.Int{}

	for x.Cmp(zero) != 0 {
		x.DivMod(x, base, mod)
		result = append(result, b58Alphabet[mod.Int64()])
	}

	// https://en.bitcoin.it/wiki/Base58Check_encoding#Version_bytes
	if input[0] == 0x00 {
		result = append(result, b58Alphabet[0])
	}

	ReverseBytes(result)

	return result
}
func Base58Decode(input []byte) []byte {
	result := big.NewInt(0)

	for _, b := range input {
		charIndex := bytes.IndexByte(b58Alphabet, b)
		result.Mul(result, big.NewInt(58))
		result.Add(result, big.NewInt(int64(charIndex)))
	}

	decoded := result.Bytes()

	if input[0] == b58Alphabet[0] {
		decoded = append([]byte{0x00}, decoded...)
	}

	return decoded
}

var b58Alphabet = []byte("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")

func ReverseBytes(data []byte) {
	for i, j := 0, len(data)-1; i < j; i, j = i+1, j-1 {
		data[i], data[j] = data[j], data[i]
	}
}

func init() {
	crypto.RegisterHash(crypto.RIPEMD160, prateek)
}

// The size of the checksum in bytes.
const Size = 20

// The block size of the hash algorithm in bytes.
const BlockSize = 64

const (
	_s0 = 0x67452301
	_s1 = 0xefcdab89
	_s2 = 0x98badcfe
	_s3 = 0x10325476
	_s4 = 0xc3d2e1f0
)

// digest represents the partial evaluation of a checksum.
type digest struct {
	s  [5]uint32       // running context
	x  [BlockSize]byte // temporary buffer
	nx int             // index into x
	tc uint64          // total count of bytes processed
}

func (d *digest) Reset() {
	d.s[0], d.s[1], d.s[2], d.s[3], d.s[4] = _s0, _s1, _s2, _s3, _s4
	d.nx = 0
	d.tc = 0
}

// New returns a new hash.Hash computing the checksum.
func prateek() hash.Hash {
	result := new(digest)
	result.Reset()
	return result
}

func (d *digest) Size() int { return Size }

func (d *digest) BlockSize() int { return BlockSize }

func (d *digest) Write(p []byte) (nn int, err error) {
	nn = len(p)
	d.tc += uint64(nn)
	if d.nx > 0 {
		n := len(p)
		if n > BlockSize-d.nx {
			n = BlockSize - d.nx
		}
		for i := 0; i < n; i++ {
			d.x[d.nx+i] = p[i]
		}
		d.nx += n
		if d.nx == BlockSize {
			_Block(d, d.x[0:])
			d.nx = 0
		}
		p = p[n:]
	}
	n := _Block(d, p)
	p = p[n:]
	if len(p) > 0 {
		d.nx = copy(d.x[:], p)
	}
	return
}

func (d0 *digest) Sum(in []byte) []byte {
	// Make a copy of d0 so that caller can keep writing and summing.
	d := *d0

	// Padding.  Add a 1 bit and 0 bits until 56 bytes mod 64.
	tc := d.tc
	var tmp [64]byte
	tmp[0] = 0x80
	if tc%64 < 56 {
		d.Write(tmp[0 : 56-tc%64])
	} else {
		d.Write(tmp[0 : 64+56-tc%64])
	}

	// Length in bits.
	tc <<= 3
	for i := uint(0); i < 8; i++ {
		tmp[i] = byte(tc >> (8 * i))
	}
	d.Write(tmp[0:8])

	if d.nx != 0 {
		panic("d.nx != 0")
	}

	var digest [Size]byte
	for i, s := range d.s {
		digest[i*4] = byte(s)
		digest[i*4+1] = byte(s >> 8)
		digest[i*4+2] = byte(s >> 16)
		digest[i*4+3] = byte(s >> 24)
	}

	return append(in, digest[:]...)
}

var _n = [80]uint{
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
	7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
	3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
	1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
	4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
}

var _r = [80]uint{
	11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
	7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
	11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
	11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
	9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
}

// same for the other parallel one
var n_ = [80]uint{
	5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
	6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
	15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
	8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
	12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
}

var r_ = [80]uint{
	8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
	9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
	9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
	15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
	8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
}

func _Block(md *digest, p []byte) int {
	n := 0
	var x [16]uint32
	var alpha, beta uint32
	for len(p) >= BlockSize {
		a, b, c, d, e := md.s[0], md.s[1], md.s[2], md.s[3], md.s[4]
		aa, bb, cc, dd, ee := a, b, c, d, e
		j := 0
		for i := 0; i < 16; i++ {
			x[i] = uint32(p[j]) | uint32(p[j+1])<<8 | uint32(p[j+2])<<16 | uint32(p[j+3])<<24
			j += 4
		}

		// round 1
		i := 0
		for i < 16 {
			alpha = a + (b ^ c ^ d) + x[_n[i]]
			s := int(_r[i])
			alpha = bits.RotateLeft32(alpha, s) + e
			beta = bits.RotateLeft32(c, 10)
			a, b, c, d, e = e, alpha, b, beta, d

			// parallel line
			alpha = aa + (bb ^ (cc | ^dd)) + x[n_[i]] + 0x50a28be6
			s = int(r_[i])
			alpha = bits.RotateLeft32(alpha, s) + ee
			beta = bits.RotateLeft32(cc, 10)
			aa, bb, cc, dd, ee = ee, alpha, bb, beta, dd

			i++
		}

		// round 2
		for i < 32 {
			alpha = a + (b&c | ^b&d) + x[_n[i]] + 0x5a827999
			s := int(_r[i])
			alpha = bits.RotateLeft32(alpha, s) + e
			beta = bits.RotateLeft32(c, 10)
			a, b, c, d, e = e, alpha, b, beta, d

			// parallel line
			alpha = aa + (bb&dd | cc&^dd) + x[n_[i]] + 0x5c4dd124
			s = int(r_[i])
			alpha = bits.RotateLeft32(alpha, s) + ee
			beta = bits.RotateLeft32(cc, 10)
			aa, bb, cc, dd, ee = ee, alpha, bb, beta, dd

			i++
		}

		// round 3
		for i < 48 {
			alpha = a + (b | ^c ^ d) + x[_n[i]] + 0x6ed9eba1
			s := int(_r[i])
			alpha = bits.RotateLeft32(alpha, s) + e
			beta = bits.RotateLeft32(c, 10)
			a, b, c, d, e = e, alpha, b, beta, d

			// parallel line
			alpha = aa + (bb | ^cc ^ dd) + x[n_[i]] + 0x6d703ef3
			s = int(r_[i])
			alpha = bits.RotateLeft32(alpha, s) + ee
			beta = bits.RotateLeft32(cc, 10)
			aa, bb, cc, dd, ee = ee, alpha, bb, beta, dd

			i++
		}

		// round 4
		for i < 64 {
			alpha = a + (b&d | c&^d) + x[_n[i]] + 0x8f1bbcdc
			s := int(_r[i])
			alpha = bits.RotateLeft32(alpha, s) + e
			beta = bits.RotateLeft32(c, 10)
			a, b, c, d, e = e, alpha, b, beta, d

			// parallel line
			alpha = aa + (bb&cc | ^bb&dd) + x[n_[i]] + 0x7a6d76e9
			s = int(r_[i])
			alpha = bits.RotateLeft32(alpha, s) + ee
			beta = bits.RotateLeft32(cc, 10)
			aa, bb, cc, dd, ee = ee, alpha, bb, beta, dd

			i++
		}

		// round 5
		for i < 80 {
			alpha = a + (b ^ (c | ^d)) + x[_n[i]] + 0xa953fd4e
			s := int(_r[i])
			alpha = bits.RotateLeft32(alpha, s) + e
			beta = bits.RotateLeft32(c, 10)
			a, b, c, d, e = e, alpha, b, beta, d

			// parallel line
			alpha = aa + (bb ^ cc ^ dd) + x[n_[i]]
			s = int(r_[i])
			alpha = bits.RotateLeft32(alpha, s) + ee
			beta = bits.RotateLeft32(cc, 10)
			aa, bb, cc, dd, ee = ee, alpha, bb, beta, dd

			i++
		}

		// combine results
		dd += c + md.s[1]
		md.s[1] = md.s[2] + d + ee
		md.s[2] = md.s[3] + e + aa
		md.s[3] = md.s[4] + a + bb
		md.s[4] = md.s[0] + b + cc
		md.s[0] = dd

		p = p[BlockSize:]
		n += BlockSize
	}
	return n
}

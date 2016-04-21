// vim: set ts=8:sts=8:sw=8:noet

package hover

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

func NewUUID4() string {
	uuid := make([]byte, 16)
	_, err := rand.Read(uuid)
	if err != nil {
		panic(fmt.Errorf("error reading random bytes: %s", err))
	}
	// variant bits; see section 4.1.1
	uuid[8] = uuid[8]&^0xc0 | 0x80
	// version 4 (pseudo-random); see section 4.1.3
	uuid[6] = uuid[6]&^0xf0 | 0x40
	ret := fmt.Sprintf("%x-%x-%x-%x-%x", uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:])
	return ret
}

// UUIDEncrypter allows binary data up to the block size (16 bytes) to be
// encoded and used as a key (uuid).
type UUIDEncrypter struct {
	iv []byte
	c  cipher.Block
}

var encrypter *UUIDEncrypter

func init() {
	var err error
	encrypter, err = NewUUIDEncrypter()
	if err != nil {
		panic(err)
	}
}

func NewUUIDEncrypter() (*UUIDEncrypter, error) {
	iv := make([]byte, aes.BlockSize)
	_, err := rand.Read(iv)
	if err != nil {
		return nil, fmt.Errorf("NewUUIDEncrypter: error seeding iv: %s", err)
	}

	key := []byte("doesntmatter1234")
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &UUIDEncrypter{iv: iv, c: c}, nil
}

// EncodePair takes a pair of ints and encodes them cryptographically as a uuid
// string
func (u *UUIDEncrypter) EncodePair(a, b int) string {
	text := make([]byte, aes.BlockSize)
	binary.BigEndian.PutUint32(text[8:12], uint32(a))
	binary.BigEndian.PutUint32(text[12:16], uint32(b))
	stream := cipher.NewCTR(u.c, u.iv)
	stream.XORKeyStream(text, text)
	return fmt.Sprintf("%x-%x-%x-%x-%x", text[0:4], text[4:6], text[6:8], text[8:10], text[10:])
}

// DecodePair takes a uuid string created by EncodePair and reverses that into
// the original pair of ints.
func (u *UUIDEncrypter) DecodePair(uuid string) (int, int, error) {
	text := make([]byte, aes.BlockSize)
	text, err := hex.DecodeString(strings.Replace(uuid, "-", "", -1))
	if err != nil {
		return 0, 0, err
	}
	stream := cipher.NewCTR(u.c, u.iv)
	stream.XORKeyStream(text, text)
	a := int(binary.BigEndian.Uint32(text[8:12]))
	b := int(binary.BigEndian.Uint32(text[12:16]))
	return a, b, nil
}

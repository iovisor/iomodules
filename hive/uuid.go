// vim: set ts=8:sts=8:sw=8:noet

package hive

import (
	"crypto/rand"
	"fmt"
	"io"
)

func NewUUID4() (string, error) {
	uuid := make([]byte, 16)
	n, err := io.ReadFull(rand.Reader, uuid)
	if err != nil {
		return "", err
	}
	if n != len(uuid) {
		return "", fmt.Errorf("could not generate enough randomness, try again")
	}
	// variant bits; see section 4.1.1
	uuid[8] = uuid[8]&^0xc0 | 0x80
	// version 4 (pseudo-random); see section 4.1.3
	uuid[6] = uuid[6]&^0xf0 | 0x40
	ret := fmt.Sprintf("%x-%x-%x-%x-%x", uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:])
	return ret, nil
}

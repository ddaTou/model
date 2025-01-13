package model

import "github.com/Nik-U/pbc"

type Cipher struct {
	C0         *pbc.Element   `field:"2"`
	C1s        []*pbc.Element `field:"2"`
	C2s        []*pbc.Element `field:"0"`
	C3s        []*pbc.Element `field:"0"`
	CipherText []byte
	Policy     string
	Cline      []byte
	Chat       *pbc.Element `field:"0"`
}
type TCipher struct {
	C1         *pbc.Element `field:"2"` //分子
	C2         *pbc.Element `field:"2"` //分母，带有指数次幂
	Cline      []byte
	Chat       *pbc.Element `field:"0"`
	CipherText []byte
}

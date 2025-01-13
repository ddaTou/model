package model

import (
	"bytes"
	// "crypto/sha256"
	"fmt"

	"github.com/Nik-U/pbc"
)

type User struct {
	Name string
	TSK  *pbc.Element `field:"3"` //转换密钥私钥
}

// 生成代理密钥
func (u *User) GenerateTransformKey(privateKeys map[string]*pbc.Element, d *DABE) (map[string]*pbc.Element, error) {

	Tsk := d.CurveParam.GetNewZn().Rand() //生成代理解密私钥z
	u.TSK = Tsk
	tskmap := make(map[string]*pbc.Element)

	for attr, aski := range privateKeys {
		tmp := aski.ThenPowZn(Tsk) //对每个属性私钥都进行Ti^z运算
		tskmap[attr] = tmp
	}
	return tskmap, nil
}

func (u *User) VerifyTransformCipherText(cipher *Cipher, tcipher *TCipher, d *DABE) ([]byte, error) {
	fmt.Println("VORABE user-end verify start")
	if len(tcipher.Cline) != 64 || len(cipher.Cline) != 64 {
		return nil, fmt.Errorf("chat length is not 64./n")
	}
	if !bytes.Equal(cipher.Cline, tcipher.Cline) {
		return nil, fmt.Errorf("Chat is not equal./n")
	}
	if !cipher.Chat.Equals(tcipher.Chat) {
		return nil, fmt.Errorf("Cline is not equal./n")
	}
	tmp1 := d.CurveParam.Get1FromZn()
	tmp1 = tmp1.Div(tmp1, u.TSK)
	tmp := tcipher.C2.PowZn(tcipher.C2, tmp1)

	eggs := tcipher.C1.Div(tcipher.C1, tmp)
	kdf, err := d.HKDF(eggs)

	if err != nil {
		return nil, err
	}
	MANDR := make([]byte, 64)
	for i := 0; i < 64; i++ {
		MANDR[i] = kdf[i] ^ tcipher.Cline[i]
	}

	// hm := d.h.PowZn(d.h, d.CurveParam.GetZnFromStringHash(string(MANDR[0:32]), sha256.New()))
	// wr := d.w.PowZn(d.w, d.CurveParam.GetZnFromStringHash(string(MANDR[32:64]), sha256.New()))
	// hmwr := hm.Mul(hm, wr)

	aeskeyy := MANDR[0:32]
	fmt.Println("用户端解密阶段aes密钥为：")
	fmt.Println(aeskeyy)
	// if !hmwr.Equals(tcipher.Chat) {
	// 	return nil, fmt.Errorf("verify failed .\n")
	// }
	M, err := AesDecrypt(cipher.CipherText, aeskeyy)
	if err != nil || M == nil {
		return nil, fmt.Errorf("aes error:: decrypt failed.\n")
	}
	return M, nil
}

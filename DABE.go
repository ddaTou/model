package model

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand"
	"time"


	"golang.org/x/crypto/hkdf"

	"github.com/Nik-U/pbc"
)

var length = 64

type DABE struct {
	CurveParam *CurveParam
	G          *pbc.Element
	EGG        *pbc.Element
	h          *pbc.Element
	w          *pbc.Element
}

func (d *DABE) GlobalSetup() {
	fmt.Println("DABE GlobalSetup start")
	d.CurveParam = new(CurveParam)
	d.CurveParam.Initialize()
	bytes, _ := hex.DecodeString("34b2bc99a307591a4da995523754cc2bca96db9671736834d0c6160051380572277f24a106ae0853cfe7445d887378e2cf2ca18407d3749592a9df988a8f38608721fb8699baa94708aee1b989c3a92cd0217a693a5395db7835a396d848e09e47d5")
	d.G = d.CurveParam.Get0FromG1().SetBytes(bytes)
	//d.G = d.CurveParam.GetNewG1()
	d.EGG = d.CurveParam.Get1FromGT().Pair(d.G, d.G)
	d.h = d.CurveParam.GetNewG1()
	d.w = d.CurveParam.GetNewG1()
	fmt.Println("DABE GlobalSetup success")
}

func (d *DABE) UserSetup(name string) *User {
	fmt.Println("DABE UserSetup start")

	fmt.Printf("DABE UserSetup success for %s\n", name)
	return &User{
		Name: name,
	}
}

func (d *DABE) OrgSetup(name string) *Org {
	fmt.Println("DABE OrgSetup start")
	alpha := d.CurveParam.GetNewZn()
	eGGAlpha := d.EGG.NewFieldElement().PowZn(d.EGG, alpha)
	gAlpha := d.G.NewFieldElement().PowZn(d.G, alpha)
	fmt.Printf("DABE OrgSetup success for %s\n", name)
	return &Org{
		APKMap:   make(map[string]*APK),
		ASKMap:   make(map[string]*ASK),
		EGGAlpha: eGGAlpha,
		Alpha:    alpha,
		GAlpha:   gAlpha,
		Name:     name,
	}
}

func (d *DABE) Encrypt(m string, uPolicy string, authorities map[string]Authority) (*Cipher, error) {
	fmt.Println("DABE Encrypt start")
	aesKey := d.EGG.NewFieldElement().Rand()
	aeskey :=(aesKey.Bytes())[0:32]
	aesCipherText, err := AesEncrypt([]byte(m), aeskey)
	if err != nil {
		return nil, fmt.Errorf("AES encrypt error\n")
	}

	policy := new(Policy)
	d.growNewPolicy(uPolicy, d.CurveParam.GetNewZn(), policy)

	n := len(policy.AccessStruct.LsssMatrix) - 1
	l := len(policy.AccessStruct.LsssMatrix[0])
	v := make([]*pbc.Element, l, l)
	w := make([]*pbc.Element, l, l)
	c1s := make([]*pbc.Element, n, n)
	c2s := make([]*pbc.Element, n, n)
	c3s := make([]*pbc.Element, n, n)
	s := d.CurveParam.GetNewZn()

	// c0 = M * e(g,g)^s
	c0 := aesKey.Mul(aesKey, d.EGG.NewFieldElement().PowZn(d.EGG, s))
	//generate v and w
	v[0] = s
	w[0] = s.NewFieldElement().Set0()
	for i := 1; i < l; i++ {
		v[i] = d.CurveParam.GetNewZn()
		w[i] = d.CurveParam.GetNewZn()
	}
	//generate c1s,c2s,c3s
	for i := 0; i < n; i++ {
		//attr
		attrStr := policy.AccessStruct.PolicyMaps[i+1]
		authorityName := GetAuthorityNameFromAttrName(attrStr)
		if authorities[authorityName] == nil {
			return nil, fmt.Errorf("authority not found, error when %s", attrStr)
		}
		authority := authorities[authorityName]
		pk := authority.GetAPKMap()[attrStr]
		if pk == nil {
			return nil, fmt.Errorf("pk not found, error when %s", attrStr)
		}
		//r
		r := d.CurveParam.GetNewZn()
		//c2 = g^r
		c2 := d.G.NewFieldElement().PowZn(d.G, r)

		//Ai*v
		AiV := policy.AccessStruct.LsssMatrixDotMulVector(i+1, v)
		//e(g,g)^(Ai*v)
		c1 := d.EGG.NewFieldElement().PowZn(d.EGG, AiV)
		//c1 = e(g,g)^(Ai*v) * e(g,g)^ ( alpha_p(x) * r_x )
		rightTemp := authority.GetPK().NewFieldElement().PowZn(authority.GetPK(), r)
		c1.Mul(c1, rightTemp)

		//Ai*w
		AiW := policy.AccessStruct.LsssMatrixDotMulVector(i+1, w)
		//g^(Ai*w)
		c3 := d.G.NewFieldElement().PowZn(d.G, AiW)
		//c3 = g^(y_p(x) * r) * g^(Ai*w)
		c3.Mul(c3, pk.Gy.NewFieldElement().PowZn(pk.Gy, r))

		c1s[i] = c1
		c2s[i] = c2
		c3s[i] = c3
	}

	hm := d.CurveParam.GetZnFromStringHash(string(aeskey), sha256.New())
	r := generateRandomBits(32)
	hr := d.CurveParam.GetZnFromStringHash(string(r), sha256.New())
	hm1 := d.CurveParam.Get1FromG1().PowZn(d.h, hm)
	hr1 := d.CurveParam.Get1FromZn().PowZn(d.w, hr)
	chat := hm1.Mul(hm1, hr1)

	kdf, err := d.HKDF(d.EGG.NewFieldElement().PowZn(d.EGG, s))
	if err != nil {
		return nil, err
	}
	cline := make([]byte, 64)
	mr := aeskey
	mr = append(mr, []byte(r)...)

	for i := 0; i < 64; i++ {
		cline[i] = kdf[i] ^ mr[i]
	}
	fmt.Println("解密阶段aes密钥为：")
	fmt.Println(aeskey)

	fmt.Println("DABE Encrypt success")
	return &Cipher{
		C0:         c0,
		C1s:        c1s,
		C2s:        c2s,
		C3s:        c3s,
		CipherText: aesCipherText,
		Policy:     uPolicy,
		Cline:      cline,
		Chat:       chat,
	}, nil
}

func (d *DABE) Decrypt(cipher *Cipher, privateKeys map[string]*pbc.Element, gid string) ([]byte, error) {
	fmt.Println("DABE Decrypt start")
	hashGid := d.CurveParam.GetG1FromStringHash(gid, sha256.New())

	policy := new(Policy)
	d.growNewPolicy(cipher.Policy, d.CurveParam.GetNewZn(), policy)
	n := len(policy.AccessStruct.LsssMatrix) - 1
	attrs := make([]string, 0, 0)
	for key, _ := range privateKeys {
		attrs = append(attrs, key)
	}
	// sum(cx * Ax) = (1,0,0,0...)
	cxs, err := d.genCoefficient(attrs, policy)
	if err != nil {
		return nil, err
	}

	// (c1 * e(HGID,c3) / e(key, c2)) ^ cx  累×后得到 e(g,g)^s
	result := d.EGG.NewFieldElement().Set1()
	for i := 0; i < n; i++ {
		if cxs[i+1] == nil {
			continue
		}
		//attr
		attrStr := policy.AccessStruct.PolicyMaps[i+1]
		// c1 * e(HGID,c3)
		temp := d.EGG.NewFieldElement().Pair(hashGid, cipher.C3s[i]).ThenMul(cipher.C1s[i])
		// e(key, c2)
		temp2 := d.EGG.NewFieldElement().Pair(privateKeys[attrStr], cipher.C2s[i])
		// (c1 * e(HGID,c3) / e(key, c2)) ^ cx
		temp.ThenDiv(temp2)
		temp.ThenPowZn(cxs[i+1])
		// 累×
		result.ThenMul(temp)
	}
	aesKey := d.EGG.NewFieldElement().Set(cipher.C0).ThenDiv(result)
	if aesKey == nil {
		return nil, fmt.Errorf("User policy not match,decrypt failed.\n")
	}
	if len(aesKey.Bytes()) <= 32 {
		return nil, fmt.Errorf("invalid aeskey:: decrypt failed.\n")
	}
	
	fmt.Println("解密阶段aes密钥为：")
	fmt.Println(aesKey.Bytes())
	M, err := AesDecrypt(cipher.CipherText, (aesKey.Bytes())[0:32])
	if err != nil || M == nil {
		return nil, fmt.Errorf("aes error:: decrypt failed.\n")
	}
	fmt.Println("DABE Decrypt success")
	return M, nil
}

func (d *DABE) genCoefficient(attrs []string, policy *Policy) ([]*pbc.Element, error) {
	n := len(attrs)
	attrMap := make(map[string]int)
	for i := 0; i < n; i++ {
		attrMap[attrs[i]] = 1
	}

	nodeLine := make([]int, len(policy.AccessStruct.A))
	leafLine := make([]int, len(policy.AccessStruct.PolicyMaps))
	nodeLine[0] = 1
	isSatisfy := policy.AccessStruct.isSatisfy(&nodeLine, &leafLine, &attrMap, 0)
	if !isSatisfy {
		return nil, fmt.Errorf("User attrs not satisfy the policy: %s", policy.PolicyDescription)
	}

	for i := 0; i < len(policy.AccessStruct.A); i++ {
		for j := 2; j < len(policy.AccessStruct.A[i]); j++ {
			if policy.AccessStruct.A[i][j] > 0 {
				nodeLine[policy.AccessStruct.A[i][j]] *= nodeLine[i]
			} else {
				leafLine[-policy.AccessStruct.A[i][j]] *= nodeLine[i]
			}
		}
	}

	w := make([]*pbc.Element, len(leafLine), len(leafLine))
	for i := 1; i < len(leafLine); i++ {
		if leafLine[i] != 0 {
			w[i] = d.CurveParam.GetNewZn().Set1().ThenDiv(d.CurveParam.GetNewZn().SetInt32(int32(leafLine[i])))
		} else {
			//如果不需要就返回nil
			w[i] = nil
		}

	}
	return w, nil
}

// 雾节点部分解密
func (d *DABE) FogNodeDecrypt(cipher *Cipher, tprivateKeys map[string]*pbc.Element, gid string, authorities map[string]Authority) (*TCipher, error) {
	fmt.Println("DABE Decrypt start")
	hashGid := d.CurveParam.GetG1FromStringHash(gid, sha256.New())

	policy := new(Policy)
	d.growNewPolicy(cipher.Policy, d.CurveParam.GetNewZn(), policy)
	n := len(policy.AccessStruct.LsssMatrix) - 1
	attrs := make([]string, 0, 0)
	for key, _ := range tprivateKeys {
		attrs = append(attrs, key)
	}
	// sum(cx * Ax) = (1,0,0,0...)
	cxs, err := d.genCoefficient(attrs, policy)
	if err != nil {
		return nil, err
	}

	// (c1 * e(HGID,c3) / e(key, c2)) ^ cx  累×后得到 e(g,g)^s
	result1 := d.EGG.NewFieldElement().Set1()
	result2 := d.EGG.NewFieldElement().Set1()
	for i := 0; i < n; i++ {
		if cxs[i+1] == nil {
			continue
		}
		//attr
		attrStr := policy.AccessStruct.PolicyMaps[i+1]
		// c1 * e(HGID,c3)
		temp := d.EGG.NewFieldElement().Pair(hashGid, cipher.C3s[i]).ThenMul(cipher.C1s[i])
		// e(key, c2)
		temp2 := d.EGG.NewFieldElement().Pair(tprivateKeys[attrStr], cipher.C2s[i])
		// (c1 * e(HGID,c3) / e(key, c2)) ^ cx
		temp.ThenPowZn(cxs[i+1])
		temp2.ThenPowZn(cxs[i+1])

		// 累×
		result1.ThenMul(temp)
		result2.ThenMul(temp2)
	}

	fmt.Println("DABE fogDecrypt success")
	return &TCipher{result1, result2, cipher.Cline, cipher.Chat, cipher.CipherText}, nil
}

func (d *DABE) growNewPolicy(s string, p *pbc.Element, policy *Policy) {
	policy.PolicyDescription = s
	policy.Grow()
	policy.AccessStruct.genElementLsssMatrix(p)
}
func (d *DABE) HKDF(dk *pbc.Element) ([]byte, error) {

	dkbyte := dk.Bytes()
	hkdftmp := hkdf.New(sha256.New, dkbyte, nil, nil)
	res := make([]byte, length)
	_, err := hkdftmp.Read(res)
	if err != nil {
		return nil, fmt.Errorf("hkdf error.\n")
	}
	return res, nil
}
func generateRandomBits(length int) string {
	rand.Seed(time.Now().UnixNano()) // 为随机数生成器提供一个随机种子
	var bits []byte
	for i := 0; i < length; i++ {
		if rand.Intn(2) == 0 {
			bits = append(bits, '0')
		} else {
			bits = append(bits, '1')
		}
	}
	return string(bits)
}

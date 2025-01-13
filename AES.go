package model

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"math/rand"
)

// func AesEncrypt(origData, key []byte) ([]byte, error) {
// 	block, err := aes.NewCipher(key)
// 	if err != nil {
// 		return nil, err
// 	}
// 	blockSize := block.BlockSize()
// 	origData = PKCS5Padding(origData, blockSize)
// 	// origData = ZeroPadding(origData, block.BlockSize())
// 	blockMode := cipher.NewCBCEncrypter(block, key[:blockSize])
// 	crypted := make([]byte, len(origData))
// 	// 根据CryptBlocks方法的说明，如下方式初始化crypted也可以
// 	// crypted := origData
// 	blockMode.CryptBlocks(crypted, origData)
// 	return crypted, nil
// }
func AesEncrypt(plaintext, key []byte) ([]byte, error) {
	// 创建 AES 密码本
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// 生成随机 IV
	iv := make([]byte, aes.BlockSize)
	_, err = rand.Read(iv)
	if err != nil {
		return nil, err
	}

	// 填充明文数据，使其长度为 AES 块大小的倍数
	plaintext = pad(plaintext, aes.BlockSize)

	// 创建 CBC 加密器
	ciphertext := make([]byte, len(plaintext))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, plaintext)

	// 返回 IV 和密文。IV 被附加到密文的前面
	return append(iv, ciphertext...), nil
}

// func AesDecrypt(crypted, key []byte) ([]byte, error) {
// 	block, err := aes.NewCipher(key)
// 	if err != nil {
// 		return nil, err
// 	}
// 	blockSize := block.BlockSize()
// 	blockMode := cipher.NewCBCDecrypter(block, key[:blockSize])
// 	origData := make([]byte, len(crypted))
// 	// origData := crypted
// 	blockMode.CryptBlocks(origData, crypted)
// 	origData = PKCS5UnPadding(origData)
// 	// origData = ZeroUnPadding(origData)
// 	return origData, nil
// }
func AesDecrypt(ciphertext, key []byte) ([]byte, error) {
	// 创建 AES 密码本
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// 提取 IV（密文的前 16 字节）
	if len(ciphertext) < aes.BlockSize {
		return nil, fmt.Errorf("密文太短，无法提取 IV")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	// 创建 CBC 解密器
	plaintext := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext)

	// 去除填充
	plaintext = unpad(plaintext)

	return plaintext, nil
}
// pad 填充数据，使其长度为块大小的倍数
func pad(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padText := make([]byte, padding)
	for i := 0; i < padding; i++ {
		padText[i] = byte(padding)
	}
	return append(src, padText...)
}

// unpad 去除填充
func unpad(src []byte) []byte {
	padding := int(src[len(src)-1])
	return src[:len(src)-padding]
}

func ZeroPadding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{0}, padding)
	return append(ciphertext, padtext...)
}

func ZeroUnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	// 去掉最后一个字节 unpadding 次
	unpadding := int(origData[length-1])
	if unpadding >= length {
		fmt.Printf("wrong SK.Decrypt failed.\n")
		return nil
	} else {
		return origData[:(length - unpadding)]
	}
}

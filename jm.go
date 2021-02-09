package jm

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
)

var iv = []byte("zs5460@gmail.com")

// EncryptString ...
func EncryptString(plainText, key string) (string, error) {
	ret, err := Encrypt([]byte(plainText), []byte(key))
	return base64.StdEncoding.EncodeToString(ret), err
}

// Encrypt ...
func Encrypt(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	data = addPKCS7Padding(data, blockSize)
	cipherData := make([]byte, len(data))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherData, data)
	return cipherData, nil
}

// DecryptString ...
func DecryptString(cipherText, key string) (string, error) {
	data, decodeErr := base64.StdEncoding.DecodeString(cipherText)
	if decodeErr != nil {
		return "", decodeErr
	}
	ret, err := Decrypt(data, []byte(key))
	return string(ret), err
}

// Decrypt ...
func Decrypt(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	originData := make([]byte, len(data))
	mode.CryptBlocks(originData, data)
	originData = stripPKSC7Padding(originData)
	return originData, nil
}

func addPKCS7Padding(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	paddingText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, paddingText...)
}

func stripPKSC7Padding(data []byte) []byte {
	length := len(data)
	unpadding := int(data[length-1])
	return data[:(length - unpadding)]
}

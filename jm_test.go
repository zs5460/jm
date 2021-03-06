package jm

import (
	"testing"
)

func TestEncryptString(t *testing.T) {
	type args struct {
		plainText string
		key       string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{"aes encrypt", args{"JingYuan is a beautiful girl.", "zs5460@gmail.com"}, "H7Li67pYknbcX2Qo7KG16AAjcoY18bFId+yXRp+b4Iw=", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := EncryptString(tt.args.plainText, tt.args.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("EncryptString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("EncryptString() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDecryptString(t *testing.T) {
	type args struct {
		cipherText string
		key        string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{"aes decrypt", args{"H7Li67pYknbcX2Qo7KG16AAjcoY18bFId+yXRp+b4Iw=", "zs5460@gmail.com"}, "JingYuan is a beautiful girl.", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DecryptString(tt.args.cipherText, tt.args.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecryptString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("DecryptString() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEncDec(t *testing.T) {
	s := "JingYuan is a beautiful girl."
	key := "zs5460@gmail.com"

	//key = "1"
	t.Log(s)
	s1, _ := EncryptString(s, key)
	t.Log(s1)
	s2, err := DecryptString(s1, key)
	if err != nil {
		t.Error(err)
	}
	t.Log(s2)
	if s != s2 {
		t.Error("Decrypt(Encrypt(s))!=s")
	}
}

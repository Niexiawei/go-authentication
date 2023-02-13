package authentication

import (
	"fmt"
	"path/filepath"
	"testing"
)

var CurrJwt *Jwt

func init() {
	path, _ := filepath.Abs("D:\\golang\\go-authentication\\test_statics\\sign_key")
	CurrJwt = NewJwt(nil, JwtWithSignKeyPath(path))
}

func TestJwt_RefreshSignKey(t *testing.T) {
	err := CurrJwt.RefreshSignKey()
	if err != nil {
		t.Error(err)
		return
	}
}

func Test_getSignKey(t *testing.T) {
	path, _ := filepath.Abs("test_statics/sign_key")
	t.Log(path)
	sign, err := getSignKey(path)
	if err != nil {
		t.Error(err)
		return
	}
	fmt.Println(string(sign))
}

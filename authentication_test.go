package authentication

import (
	"fmt"
	"path/filepath"
	"testing"
)

var CurrJwt *Jwt

func init() {
	path, _ := filepath.Abs("D:\\golang\\go-authentication\\test_statics\\sign_key")
	CurrJwt = NewJwt(&TestModel{}, JwtWithSignKeyPath(path))
}

type TestModel struct {
	Id       int
	UserName string
}

func (t *TestModel) GetUserId() int {
	return 1
}

func (t *TestModel) GetUser(userid int) (any, error) {
	return &TestModel{
		Id:       1,
		UserName: "哈哈哈哈",
	}, nil
}

func (t *TestModel) GetGuard() Guard {
	return ""
}

func TestJwt_generateToken(t *testing.T) {
	u := &TestModel{
		Id:       1,
		UserName: "哈哈哈哈",
	}
	token, err := CurrJwt.GetToken(u)
	if err != nil {
		t.Error(err)
		return
	}
	fmt.Println(token)
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

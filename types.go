package authentication

import (
	"github.com/golang-jwt/jwt/v5"
	"time"
)

const (
	GetAuthKey = "authentication"
)

type Guard string

type AuthenticationUserModel interface {
	GetUserId() int
	GetUser(userid int) (any, error)
	GetGuard() Guard
}

type CacheUserAfterVerify struct {
	User   AuthenticationUserModel
	Expire time.Time
}

type Token struct {
	Token     string `json:"token"`
	ExpiresIn int64  `json:"expires_in"`
}

type CustomClaims struct {
	UserId int   `json:"userId"`
	Guard  Guard `json:"guard,omitempty"`
	jwt.RegisteredClaims
}

type Jwt struct {
	AuthenticationUserModel
	cacheVerifyUserExpire time.Duration
	signKey               []byte
	signKeyPath           string
}

type ginContext interface {
	GetHeader(key string) string
	GetQuery(key string) (string, bool)
	Abort()
	Next()
	Set(key string, value any)
	JSON(code int, obj any)
}

type GetTokenParams struct {
	Expire time.Duration
}

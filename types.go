package authentication

import (
	"github.com/golang-jwt/jwt/v5"
	"time"
)

const (
	GetAuthKey = "authentication"
)

var (
	TimeDay       = time.Hour * 24
	defaultConfig = &Config{
		CacheVerifyUserExpire: 1 * time.Hour,
		TokenExpire:           8 * time.Hour,
		RefreshTokenExpire:    14 * TimeDay,
		SignKey:               string(defaultSignKey),
		SignKeyPath:           "",
	}
)

func NewDefaultConfig() *Config {
	return defaultConfig
}

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
	Token                 string `json:"token"`
	ExpiresIn             int64  `json:"expires_in"`
	RefreshToken          string `json:"refresh_token"`
	RefreshTokenExpiresIn int64  `json:"refresh_token_expires_in"`
}

type CustomClaims struct {
	UserId         int               `json:"userId"`
	Guard          Guard             `json:"guard,omitempty"`
	IsRefreshToken bool              `json:"isRefreshToken"`
	CustomData     map[string]string `json:"customData"`
	jwt.RegisteredClaims
}

type Jwt struct {
	AuthenticationUserModel
	config  *Config
	signKey []byte
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
	Claims jwt.RegisteredClaims
}

type Config struct {
	CacheVerifyUserExpire time.Duration `json:"cacheVerifyUserExpire" yaml:"cacheVerifyUserExpire"`
	TokenExpire           time.Duration `json:"tokenExpire" yaml:"tokenExpire"`
	RefreshTokenExpire    time.Duration `json:"refreshTokenExpire" yaml:"refreshTokenExpire"`
	SignKey               string        `json:"signKey" yaml:"signKey"`
	SignKeyPath           string        `json:"signKeyPath" yaml:"signKeyPath"`
}

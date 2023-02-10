package authentication

import (
	"errors"
	"github.com/Niexiawei/golang-utils/httpresponse"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"sync"
	"time"
)

var (
	mapLock                sync.Mutex
	TokenVerifyError       = errors.New("token验证失败！")
	TokenVerifyExpireError = errors.New("token已失效！")
	defaultSignKey         = []byte("authenticationsignkey")
	cacheVerifyUser        = map[int]CacheUserAfterVerify{}
)

const (
	GetAuthKey = "authentication"
)

type AuthenticationUserModel interface {
	GetUserId() int
	GetUser(userid int) (any, error)
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
	UserId int `json:"userId"`
	jwt.RegisteredClaims
}

type Jwt struct {
	AuthenticationUserModel
	cacheVerifyUserExpire time.Duration
	signKey               []byte
}

type Options func(j *Jwt)

func JwtWithCacheVerifyUserExpire(duration time.Duration) Options {
	return func(j *Jwt) {
		j.cacheVerifyUserExpire = duration
	}
}

func JwtWithSignKey(key []byte) Options {
	return func(j *Jwt) {
		j.signKey = key
	}
}

func NewJwt(model AuthenticationUserModel, options ...Options) *Jwt {
	j := &Jwt{
		AuthenticationUserModel: model,
		cacheVerifyUserExpire:   7 * time.Hour,
		signKey:                 defaultSignKey,
	}
	for _, o := range options {
		o(j)
	}
	clearExpireCacheAuth()
	return j
}

func (j *Jwt) DeleteCacheElement(id int) {
	if _, ok := cacheVerifyUser[id]; ok {
		delete(cacheVerifyUser, id)
	}
}

func (j *Jwt) SetSignKey(key []byte) {
	j.signKey = key
}

func clearExpireCacheAuth() {
	clear := func() {
		for id, cache := range cacheVerifyUser {
			if cache.Expire.Before(time.Now()) {
				mapLock.Lock()
				delete(cacheVerifyUser, id)
				mapLock.Unlock()
			}
		}
	}
	go func() {
		delay := time.NewTimer(1 * time.Minute)
		defer delay.Stop()
		for {
			select {
			case <-delay.C:
				clear()
			}
		}
	}()
}

func (j *Jwt) GetToken(user AuthenticationUserModel, expireHour ...int) (*Token, error) {
	expire := 24 * 7
	if len(expireHour) > 0 {
		expire = expireHour[0]
	}

	expireDate := time.Now().Add(time.Duration(expire) * time.Hour)

	claims := jwt.NewWithClaims(jwt.SigningMethodHS256, CustomClaims{
		UserId: user.GetUserId(),
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expireDate),
			Issuer:    "huaming.cn",
		},
	})

	token, err := claims.SignedString(j.signKey)

	if err != nil {
		return nil, err
	}

	return &Token{Token: token, ExpiresIn: expireDate.Unix()}, nil
}

func (j *Jwt) GetUserByToken(t string) (AuthenticationUserModel, error) {
	claims := CustomClaims{}
	token, err := jwt.ParseWithClaims(t, &claims, func(token *jwt.Token) (interface{}, error) {
		return j.signKey, nil
	})
	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, TokenVerifyError
	}

	if claims.ExpiresAt.Before(time.Now()) {
		return nil, TokenVerifyExpireError
	}

	{
		if val, ok := cacheVerifyUser[claims.UserId]; ok {
			if val.Expire.After(time.Now()) {
				return val.User, nil
			}
			mapLock.Lock()
			delete(cacheVerifyUser, claims.UserId)
			mapLock.Unlock()
		}
	}

	userTypeAny, err := j.GetUser(claims.UserId)
	if err != nil {
		return nil, err
	}
	user := userTypeAny.(AuthenticationUserModel)
	mapLock.Lock()
	cacheVerifyUser[claims.UserId] = CacheUserAfterVerify{
		User:   user,
		Expire: time.Now().Add(j.cacheVerifyUserExpire),
	}
	mapLock.Unlock()
	return user, nil
}

func AuthenticationMiddleware(j *Jwt) func(c *gin.Context) {
	return func(c *gin.Context) {

		var (
			token string
			resp  = httpresponse.NewResponse(c, 0, "")
		)

		t1 := c.GetHeader("token")
		t2, _ := c.GetQuery("token")

		if t1 == "" && t2 == "" {
			resp.WithMessage(TokenVerifyError.Error()).WithCode(401).ResultOk()
			c.Abort()
			return
		}

		if t2 != "" {
			token = t2
		}

		if t1 != "" {
			token = t1
		}

		auth, err := j.GetUserByToken(token)

		if err != nil {
			if errors.Is(err, TokenVerifyError) {
				resp.WithMessage(TokenVerifyError.Error()).WithCode(401).ResultOk()
			} else if errors.Is(err, TokenVerifyExpireError) {
				resp.WithMessage(TokenVerifyExpireError.Error()).WithCode(403).ResultOk()
			} else {
				resp.WithMessage(TokenVerifyError.Error()).WithCode(401).ResultOk()
			}
			c.Abort()
			return
		}

		c.Set(GetAuthKey, auth)
		c.Next()
	}
}

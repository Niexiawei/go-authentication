package authentication

import (
	"errors"
	"fmt"
	filepath2 "github.com/Niexiawei/golang-utils/filepath"
	"github.com/Niexiawei/golang-utils/random"
	"github.com/Niexiawei/golang-utils/strings"
	"github.com/golang-jwt/jwt/v5"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var (
	mapLock                sync.Mutex
	TokenVerifyError       = errors.New("token验证失败！")
	TokenVerifyExpireError = errors.New("token已失效！")
	ErrNoSetSignKeyPath    = errors.New("没有设置 sign key 存储路径")
	ErrRefreshSignKeyFail  = errors.New("刷新 sign key 失败")
	defaultSignKey         = []byte("authenticationsignkey")
	cacheVerifyUser        = map[int]CacheUserAfterVerify{}
)

func NewJwt(model AuthenticationUserModel, options ...Options) *Jwt {
	j := &Jwt{
		AuthenticationUserModel: model,
		signKey:                 defaultSignKey,
		config:                  defaultConfig,
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
	clearFunc := func() {
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
				clearFunc()
			}
		}
	}()
}

func (j *Jwt) GetToken(user AuthenticationUserModel, registeredClaims ...jwt.RegisteredClaims) (*Token, error) {
	var (
		myClaims = jwt.RegisteredClaims{}
	)

	if len(registeredClaims) > 0 {
		myClaims = registeredClaims[0]
	}

	var (
		token              string
		tokenExpire        time.Time
		refreshToken       string
		refreshTokenExpire time.Time
	)

	{
		var err error
		tokenExpire = time.Now().Add(j.config.TokenExpire)
		myClaims.ExpiresAt = jwt.NewNumericDate(tokenExpire)
		claims := jwt.NewWithClaims(jwt.SigningMethodHS256, CustomClaims{
			UserId:           user.GetUserId(),
			Guard:            user.GetGuard(),
			RegisteredClaims: myClaims,
		})

		token, err = claims.SignedString(j.signKey)
		if err != nil {
			return nil, err
		}
	}

	{
		var err error
		refreshTokenExpire = time.Now().Add(j.config.RefreshTokenExpire)
		myClaims.ExpiresAt = jwt.NewNumericDate(refreshTokenExpire)
		claims := jwt.NewWithClaims(jwt.SigningMethodHS256, CustomClaims{
			user.GetUserId(),
			user.GetGuard(),
			map[string]string{
				"token": token,
			},
			myClaims,
		})

		refreshToken, err = claims.SignedString(j.signKey)

		if err != nil {
			return nil, err
		}
	}

	t := Token{
		Token:                 token,
		ExpiresIn:             tokenExpire.Unix(),
		RefreshToken:          refreshToken,
		RefreshTokenExpiresIn: refreshTokenExpire.Unix(),
	}

	return &t, nil
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
		Expire: time.Now().Add(j.config.CacheVerifyUserExpire),
	}
	mapLock.Unlock()
	return user, nil
}

func (j *Jwt) RefreshSignKey() error {
	if j.config.SignKeyPath == "" {
		return ErrNoSetSignKeyPath
	}
	newPath := j.config.SignKeyPath + "_backup"
	_ = os.Rename(j.config.SignKeyPath, newPath)
	_, err := getSignKey(j.config.SignKeyPath)
	if err != nil {
		_ = os.Rename(newPath, j.config.SignKeyPath)
		return fmt.Errorf("%w(%s)", ErrRefreshSignKeyFail, err.Error())
	}
	_ = os.Remove(newPath)
	return nil
}

func getSignKey(path string) (sign []byte, err error) {
	var (
		signByte []byte
	)

	if ok, _ := filepath2.PathExists(path); ok {
		if ok, _ := filepath2.IsDir(path); !ok {
			f, err := os.Open(path)
			if err != nil {
				return nil, err
			}
			defer f.Close()
			signByte, err = io.ReadAll(f)
			if err != nil {
				return nil, err
			}
			return signByte, nil
		}
	}
	basePath := filepath.Dir(path)
	err = os.MkdirAll(basePath, 0777)
	if err != nil {
		return nil, err
	}
	ff, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0644)
	if err != nil {
		return nil, err
	}
	signKey := random.RandStr(32)
	_, err = ff.WriteString(signKey)
	if err != nil {
		return nil, err
	}
	return strings.StringToBytes(signKey), nil
}

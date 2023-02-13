package authentication

import (
	"errors"
	"fmt"
	golangutils "github.com/Niexiawei/golang-utils"
	"github.com/Niexiawei/golang-utils/pathtool"
	"github.com/Niexiawei/golang-utils/random"
	"github.com/golang-jwt/jwt/v4"
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

func (j *Jwt) RefreshSignKey() error {
	if j.signKeyPath == "" {
		return ErrNoSetSignKeyPath
	}
	newpath := j.signKeyPath + "_backup"
	_ = os.Rename(j.signKeyPath, newpath)
	_, err := getSignKey(j.signKeyPath)
	if err != nil {
		_ = os.Rename(newpath, j.signKeyPath)
		return fmt.Errorf("%w(%s)", ErrRefreshSignKeyFail, err.Error())
	}
	_ = os.Remove(newpath)
	return nil
}

func getSignKey(path string) (sign []byte, err error) {
	var (
		signByte []byte
	)

	if ok, _ := pathtool.PathExists(path); ok {
		if ok, _ := pathtool.IsDir(path); !ok {
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
	return golangutils.StringToBytes(signKey), nil
}

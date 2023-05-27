package authentication

import (
	"time"
)

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

func JwtWithSignKeyPath(path string) Options {
	return func(j *Jwt) {
		key, err := getSignKey(path)
		if err != nil {
			panic(err)
		}
		j.signKey = key
		j.signKeyPath = path
	}
}

type GetTokenOptions func(g *GetTokenParams)

func GetTokenWithExpire(duration time.Duration) GetTokenOptions {
	return func(g *GetTokenParams) {
		g.Expire = duration
	}
}

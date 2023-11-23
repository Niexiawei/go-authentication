package authentication

import (
	"time"
)

type Options func(j *Jwt)

func JwtWithCacheVerifyUserExpire(duration time.Duration) Options {
	return func(j *Jwt) {
		j.config.CacheVerifyUserExpire = duration
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
		j.config.SignKeyPath = path
		j.config.SignKey = string(key)
	}
}

func WithConfig(c *Config) Options {
	return func(j *Jwt) {
		j.config = c
		if c.SignKeyPath != "" {
			key, err := getSignKey(c.SignKeyPath)
			if err != nil {
				panic(err)
			}
			j.signKey = key
			j.config.SignKey = string(key)
		}
	}
}

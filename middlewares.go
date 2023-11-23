package authentication

import (
	"errors"
	"github.com/Niexiawei/golang-utils/httpresponse"
)

func AuthenticationMiddleware[T ginContext](j *Jwt) func(T) {
	return func(c T) {
		Authentication(j, c)
	}
}

func Authentication(j *Jwt, c ginContext) {
	var (
		token string
	)

	t1 := c.GetHeader("token")
	t2, _ := c.GetQuery("token")

	if t1 == "" && t2 == "" {
		httpresponse.ResultFail(c, 401, TokenVerifyError.Error())
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
			httpresponse.ResultFail(c, 401, TokenVerifyError.Error())
		} else if errors.Is(err, TokenVerifyExpireError) {
			httpresponse.ResultFail(c, 403, TokenVerifyExpireError.Error())
		} else {
			httpresponse.ResultFail(c, 401, TokenVerifyError.Error())
		}
		c.Abort()
		return
	}

	c.Set(GetAuthKey, auth)
	c.Next()
}

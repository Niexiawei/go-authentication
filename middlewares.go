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

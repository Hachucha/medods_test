package stateless

import (
	"errors"
)

var (
	ErrUserAgentChanged = errors.New("user agent changed")
	ErrAccessTokenExpired     = errors.New("access token expired")
	ErrAccessTokenInvalid	  = errors.New("access token invalid")
)
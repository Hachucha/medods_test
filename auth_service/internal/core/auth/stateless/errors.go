package stateless

import (
	"errors"
)

var (
	ErrUserAgentChanged    = errors.New("user agent changed")
)
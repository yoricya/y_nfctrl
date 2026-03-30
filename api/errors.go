package api

import (
	"errors"
)

var ErrApiEndpointNotInitiated = errors.New("api endpoint not initiated")
var ErrApiEndpointAlreadyInitiated = errors.New("api endpoint already initiated")

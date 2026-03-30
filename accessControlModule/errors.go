package accessControlModule

import (
	"fmt"
	"time"
)

type ErrIpAccessExtended struct {
	TimeTo int64 // Unix milli
}

func (e *ErrIpAccessExtended) Error() string {
	return fmt.Sprintln("access extended until ", time.UnixMilli(e.TimeTo).Format("15:04:05"))
}

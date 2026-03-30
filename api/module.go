package api

import "sync/atomic"

var moduleIdCounter int64

type Module struct {
	id         int64
	moduleName string
}

func NewModule(name string) *Module {
	return &Module{
		moduleName: name,
		id:         atomic.AddInt64(&moduleIdCounter, 1),
	}
}

func (this *Module) Is(anotherModule *Module) bool {
	if anotherModule == nil {
		return false
	}

	return this.id == anotherModule.id
}

func (this *Module) GetName() string {
	return this.moduleName
}

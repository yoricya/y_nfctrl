package api

import (
	"errors"
	"log"
	"net"
	"sync"
	"y_nfctrl/accessControlModule"
)

type Api struct {
	mu                 sync.RWMutex
	allowIpListeners   []func(m *Module, ip net.IP) error
	denyIpListeners    []func(m *Module, ip net.IP) error
	ipRequestListeners []func(m *Module, ip net.IP, dstPort uint16, isTcp bool) error
	notifyListeners    []func(m *Module, message string) error

	getAllowedIPsCallback    func(m *Module) ([]*accessControlModule.AcmIP, error)
	getDisallowedIPsCallback func(m *Module) ([]*accessControlModule.AcmIP, error)
}

func (this *Api) SetAllowIPListener(m *Module, allowIpCallback func(m *Module, ip net.IP) error) error {
	if m == nil {
		return errors.New("nil module not allowed")
	}

	log.Println("[" + m.GetName() + " Module] Set listener for Allow IP")

	this.mu.Lock()
	defer this.mu.Unlock()

	this.allowIpListeners = append(this.allowIpListeners, allowIpCallback)

	return nil
}

func (this *Api) AllowIP(m *Module, ip net.IP) error {
	if m == nil {
		return errors.New("nil module not allowed")
	}

	log.Println("[" + m.GetName() + " Module] Allowed IP: " + ip.String())

	this.mu.RLock()
	defer this.mu.RUnlock()

	var errs error = nil
	for _, callback := range this.allowIpListeners {
		err := callback(m, ip)
		if err != nil {
			errs = errors.Join(errs, err)
		}
	}

	return errs
}

func (this *Api) SetDenyIPListener(m *Module, denyIpCallback func(m *Module, ip net.IP) error) error {
	if m == nil {
		return errors.New("nil module not allowed")
	}

	log.Println("[" + m.GetName() + " Module] Set listener for Deny IP")

	this.mu.Lock()
	defer this.mu.Unlock()

	this.denyIpListeners = append(this.denyIpListeners, denyIpCallback)

	return nil
}

func (this *Api) DenyIP(m *Module, ip net.IP) error {
	if m == nil {
		return errors.New("nil module not allowed")
	}

	log.Println("[" + m.GetName() + " Module] Disallowed IP: " + ip.String())

	this.mu.RLock()
	defer this.mu.RUnlock()

	var errs error = nil
	for _, callback := range this.denyIpListeners {
		err := callback(m, ip)
		if err != nil {
			errs = errors.Join(errs, err)
		}
	}

	return errs
}

func (this *Api) SetNotifyListener(m *Module, notifyListener func(m *Module, message string) error) error {
	if m == nil {
		return errors.New("nil module not allowed")
	}

	log.Println("[" + m.GetName() + " Module] Set listener for notifies")

	this.mu.Lock()
	defer this.mu.Unlock()

	this.notifyListeners = append(this.notifyListeners, notifyListener)

	return nil
}

func (this *Api) Notify(m *Module, message string) error {
	if m == nil {
		return errors.New("nil module not allowed")
	}

	log.Println("[" + m.GetName() + " Module] Notify: " + message)

	this.mu.RLock()
	defer this.mu.RUnlock()

	var errs error = nil
	for _, callback := range this.notifyListeners {
		err := callback(m, message)
		if err != nil {
			errs = errors.Join(errs, err)
		}
	}

	return errs
}

func (this *Api) SetIpRequestListener(m *Module, ipRequestListener func(m *Module, ip net.IP, dstPort uint16, isTcp bool) error) error {
	if m == nil {
		return errors.New("nil module not allowed")
	}

	log.Println("[" + m.GetName() + " Module] Set listener for ip request")

	this.mu.Lock()
	defer this.mu.Unlock()

	this.ipRequestListeners = append(this.ipRequestListeners, ipRequestListener)

	return nil
}

func (this *Api) IpRequest(m *Module, ip net.IP, dstPort uint16, isTcp bool) error {
	if m == nil {
		return errors.New("nil module not allowed")
	}

	log.Println("[" + m.GetName() + " Module] Ip " + ip.String() + " access request")

	this.mu.RLock()
	defer this.mu.RUnlock()

	var errs error = nil
	for _, callback := range this.ipRequestListeners {
		err := callback(m, ip, dstPort, isTcp)
		if err != nil {
			errs = errors.Join(errs, err)
		}
	}

	return errs
}

func (this *Api) SetAllowedIPsCallback(m *Module, callback func(m *Module) ([]*accessControlModule.AcmIP, error)) error {
	if m == nil {
		return errors.New("nil module not allowed")
	}

	if this.getAllowedIPsCallback != nil {
		log.Println("[" + m.GetName() + " Module] [E] Failed to set allowed ips callback, endpoint api already initiated")
		return ErrApiEndpointAlreadyInitiated
	}

	log.Println("[" + m.GetName() + " Module] Set allowed ips callback")
	this.getAllowedIPsCallback = callback
	return nil
}

func (this *Api) GetAllowedIPs(m *Module) ([]*accessControlModule.AcmIP, error) {
	if m == nil {
		return nil, errors.New("nil module not allowed")
	}

	log.Println("[" + m.GetName() + " Module] Request to get allowed IPs")
	if this.getDisallowedIPsCallback == nil {
		return nil, ErrApiEndpointNotInitiated
	}
	return this.getAllowedIPsCallback(m)
}

func (this *Api) SetDisallowedIPsCallback(m *Module, callback func(m *Module) ([]*accessControlModule.AcmIP, error)) error {
	if m == nil {
		return errors.New("nil module not allowed")
	}

	if this.getDisallowedIPsCallback != nil {
		log.Println("[" + m.GetName() + " Module] [E] Failed to set disallowed ips callback, endpoint api already initiated")
		return ErrApiEndpointAlreadyInitiated
	}

	log.Println("[" + m.GetName() + " Module] Set disallowed ips callback")
	this.getDisallowedIPsCallback = callback
	return nil
}

func (this *Api) GetDisallowedIPs(m *Module) ([]*accessControlModule.AcmIP, error) {
	if m == nil {
		return nil, errors.New("nil module not allowed")
	}

	log.Println("[" + m.GetName() + " Module] Request to get disallowed IPs")
	if this.getDisallowedIPsCallback == nil {
		return nil, ErrApiEndpointNotInitiated
	}
	return this.getDisallowedIPsCallback(m)
}

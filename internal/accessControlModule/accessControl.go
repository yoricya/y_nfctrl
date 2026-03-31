package accessControlModule

import (
	"net"
	"sync"
)

type AccessControlModule struct {
	ips []*AcmIP
	mu  sync.Mutex
}

func New() *AccessControlModule {
	return &AccessControlModule{
		mu: sync.Mutex{},
	}
}

func (this *AccessControlModule) Add(ip net.IP) *AcmIP {
	// Make acm ip
	acmIP := NewAcmIP(ip)

	// Cache
	this.mu.Lock()
	this.ips = append(this.ips, acmIP)
	this.mu.Unlock()

	// Re
	return acmIP
}

func (this *AccessControlModule) Get(ip net.IP) *AcmIP {
	this.mu.Lock()
	for _, acmIP := range this.ips {
		if acmIP.ip.Equal(ip) {
			this.mu.Unlock()
			return acmIP
		}
	}
	this.mu.Unlock()

	return this.Add(ip)
}

func (this *AccessControlModule) GetAllowedIPs() []*AcmIP {
	var allowedAcmIPs []*AcmIP

	this.mu.Lock()
	for _, acmIP := range this.ips {
		if acmIP.CheckIsAllow() {
			allowedAcmIPs = append(allowedAcmIPs, acmIP)
		}
	}
	this.mu.Unlock()

	return allowedAcmIPs
}

func (this *AccessControlModule) GetDisallowedIPs() []*AcmIP {
	var disallowedIPs []*AcmIP

	this.mu.Lock()
	for _, acmIP := range this.ips {
		if !acmIP.CheckIsAllow() {
			disallowedIPs = append(disallowedIPs, acmIP)
		}
	}
	this.mu.Unlock()

	return disallowedIPs
}

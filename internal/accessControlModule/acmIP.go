package accessControlModule

import (
	"errors"
	"net"
	"sync"
	"time"
)

const (
	StateDefault = 0
	StateRequest = 1
	StateBan     = 2
	StateAllow   = 3
)

type AcmIP struct {
	ip net.IP // Immutable
	mu *sync.Mutex

	state        uint8
	synRepeats   int
	lastSynTime  int64
	endAllowTime int64
}

func NewAcmIP(ip net.IP) *AcmIP {
	return &AcmIP{
		ip: ip,
		mu: &sync.Mutex{},
	}
}

func (this *AcmIP) GetIp() net.IP {
	return this.ip
}

func (this *AcmIP) GetEndAllowTime() int64 {
	if !this.CheckIsAllow() {
		return 0
	}

	return this.endAllowTime
}

func (this *AcmIP) CheckIsAllow() bool {
	return this.state == StateAllow && this.endAllowTime > time.Now().UnixMilli()
}

func (this *AcmIP) Allow() error {
	this.mu.Lock()
	defer this.mu.Unlock()

	this.synRepeats = 0
	this.endAllowTime = time.Now().Add(time.Hour * 2).UnixMilli()

	if this.state == StateAllow {
		return &ErrIpAccessExtended{TimeTo: this.endAllowTime}
	}

	this.state = StateAllow

	return nil
}

func (this *AcmIP) Disallow() error {
	this.mu.Lock()
	defer this.mu.Unlock()

	this.synRepeats = 0
	this.endAllowTime = 0

	if this.state == StateBan {
		return errors.New("IP already disallowed")
	}

	this.state = StateBan

	return nil
}

func (this *AcmIP) Reset() error {
	this.mu.Lock()
	defer this.mu.Unlock()

	this.state = StateDefault
	this.synRepeats = 0
	this.endAllowTime = 0

	return nil
}

func (this *AcmIP) ReceivedSYN(needSynRepeats int) uint8 {
	now := time.Now().UnixMilli()

	this.mu.Lock()
	defer this.mu.Unlock()

	if this.state == StateDefault {
		if now-this.lastSynTime > 20000 {
			this.synRepeats = 0
		}

		this.synRepeats++
		this.lastSynTime = now

		if this.synRepeats >= needSynRepeats {
			this.synRepeats = 0   // reset repeats
			this.state = StateBan // Set ban state
			return StateRequest   // Return request state
		}
	}

	if this.state == StateAllow {
		if this.endAllowTime > now {
			return this.state
		}

		// if time expired:
		this.state = StateDefault // Set default state
	}

	return this.state
}

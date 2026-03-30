package nfqueueModule

import (
	"fmt"
	"log"
	"net"
	"sync"
	"y_nfctrl/accessControlModule"
	"y_nfctrl/api"

	"github.com/AkihiroSuda/go-netfilter-queue"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type NfQueueModule struct {
	needSynRepeats int
	accessControl  *accessControlModule.AccessControlModule
	mu             sync.RWMutex

	isInitiated bool

	module *api.Module
	api    *api.Api
}

func New(needSynRepeats int, module *api.Module, mapi *api.Api) *NfQueueModule {
	nfq := &NfQueueModule{
		isInitiated:    false,
		needSynRepeats: needSynRepeats,
		accessControl:  accessControlModule.New(),
		mu:             sync.RWMutex{},
		module:         module,
		api:            mapi,
	}

	_ = mapi.SetAllowedIPsCallback(module, func(m *api.Module) ([]*accessControlModule.AcmIP, error) {
		return nfq.accessControl.GetAllowedIPs(), nil
	})

	_ = mapi.SetDisallowedIPsCallback(module, func(m *api.Module) ([]*accessControlModule.AcmIP, error) {
		return nfq.accessControl.GetDisallowedIPs(), nil
	})

	_ = mapi.SetAllowIPListener(module, func(m *api.Module, ip net.IP) error {
		nfq.mu.RLock()
		if !nfq.isInitiated {
			return ErrNfqModuleNotInitiated
		}
		nfq.mu.RUnlock()

		return nfq.accessControl.Get(ip).Allow()
	})

	_ = mapi.SetDenyIPListener(module, func(m *api.Module, ip net.IP) error {
		nfq.mu.RLock()
		if !nfq.isInitiated {
			return ErrNfqModuleNotInitiated
		}
		nfq.mu.RUnlock()

		return nfq.accessControl.Get(ip).Disallow()
	})

	return nfq
}

func (this *NfQueueModule) StartQueue(queueID uint16, maxQueueSize uint32, packetSize uint32) error {
	nfq, err := netfilter.NewNFQueue(queueID, maxQueueSize, packetSize)
	if err != nil {
		return err
	}
	defer nfq.Close()

	packets := nfq.GetPackets()

	wg := sync.WaitGroup{}
	wg.Add(4)

	// init
	this.isInitiated = true

	for i := 0; i < 4; i++ {
		go func() {
			defer wg.Done()
			for packet := range packets {
				this.RecvPacket(packet)
			}
		}()
	}

	wg.Wait()
	return nil
}

func (this *NfQueueModule) RecvPacket(packet netfilter.NFPacket) {
	// Parse TCP/IP
	ip, dstPort, err := this.parseTCPIP(packet.Packet)
	if err != nil {
		log.Println("[NfQueue Module] [E] NfQueue RecvPacket err:", err)
		packet.SetVerdict(netfilter.NF_ACCEPT)
		return
	}

	// Get acmIP object
	acmIp := this.accessControl.Get(ip)

	// Recv SYN
	state := acmIp.ReceivedSYN(this.needSynRepeats)

	// Accept if allow state
	if state == accessControlModule.StateAllow {
		packet.SetVerdict(netfilter.NF_ACCEPT)
		return
	}

	// Notify modules if request state
	if state == accessControlModule.StateRequest {
		go this.api.IpRequest(this.module, ip, dstPort, true)
	}

	// Drop as default
	packet.SetVerdict(netfilter.NF_DROP)
}

func (this *NfQueueModule) parseTCPIP(packet gopacket.Packet) (net.IP, uint16, error) {
	// Parse IP
	var ip net.IP

	ip4 := packet.Layer(layers.LayerTypeIPv4)
	if ip4 != nil {
		ip = ip4.(*layers.IPv4).SrcIP
	} else {
		ip6 := packet.Layer(layers.LayerTypeIPv6)
		if ip6 != nil {
			ip = ip6.(*layers.IPv6).SrcIP
		} else {
			return nil, 0, fmt.Errorf("not found ip layer on packet")
		}
	}

	// Parse TCP
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return nil, 0, fmt.Errorf("not found tcp layer on packet")
	}

	tcp := tcpLayer.(*layers.TCP)

	if !tcp.SYN {
		return nil, 0, fmt.Errorf("tcp SYN not found")
	}

	if tcp.ACK {
		return nil, 0, fmt.Errorf("tcp ACK found")
	}

	return ip, uint16(tcp.DstPort), nil
}

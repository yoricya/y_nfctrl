package nfctrl

import (
	"errors"
	"github.com/AkihiroSuda/go-netfilter-queue"
	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"log"
	"strings"
	"sync"
	"time"
	"y_nfctrl/bot"
)

type NFCTRL struct {
	syn_need_repeats int
	ip_list_mutex    *sync.RWMutex
	ip_list          map[string]int64 // int64 - session state:
	// -1 = banned,
	// 0 = new IP
	// 1 - 1024 = SYN repeats count
	// 1025 - MAX = Timestamp of end allow status
}

func Make(syn_need_repeats int) *NFCTRL {
	return &NFCTRL{
		syn_need_repeats: syn_need_repeats,
		ip_list_mutex:    &sync.RWMutex{},
		ip_list:          make(map[string]int64),
	}
}

func (nfctrl *NFCTRL) AllowIP(ip1 string) error {
	ip := strings.TrimSpace(ip1)
	nfctrl.set_state(ip, time.Now().UnixMilli()+1000*60*60) // Разрешить повторные TCP-SYN в течение часа
	return nil
}

func (nfctrl *NFCTRL) DisallowIP(ip1 string) error {
	ip := strings.TrimSpace(ip1)

	if nfctrl.get_state(ip) == -1 {
		return errors.New("IP already disallowed")
	}

	nfctrl.set_state(ip, -1) // Ставим статус -1 - Banned.

	return nil
}

func (nfctrl *NFCTRL) get_state(ip string) int64 {
	nfctrl.ip_list_mutex.RLock()
	defer nfctrl.ip_list_mutex.RUnlock()

	return nfctrl.ip_list[ip]
}

func (nfctrl *NFCTRL) set_state(ip string, state int64) {
	nfctrl.ip_list_mutex.Lock()
	nfctrl.ip_list[ip] = state
	nfctrl.ip_list_mutex.Unlock()
}

func (nfctrl *NFCTRL) Init(ownedID int64, botAPI *tgbotapi.BotAPI, queueID uint16, maxQueueSize uint32, packetSize uint32) {
	nfq, err := netfilter.NewNFQueue(queueID, maxQueueSize, packetSize)
	if err != nil {
		panic(err)
	}
	defer nfq.Close()

	packets := nfq.GetPackets()

	for {
		select {
		case p := <-packets:
			tcp, srcIP, err := parseTCPPacket(p.Packet)
			if err != nil {
				// Если пакет не удалось распознать, например пришел UDP вместо TCP или не TCP-SYN
				log.Println("[NFCTRL] WARN:", err)

				// Ну и пропускаем дальше, а что поделать?
				p.SetVerdict(netfilter.NF_ACCEPT)
				continue
			}

			state := nfctrl.get_state(srcIP)

			// State = -1 - IP Banned
			if state == -1 {
				p.SetVerdict(netfilter.NF_DROP)
				continue
			}

			// Если у нас timestamp, то чекаем
			if state >= 1025 {

				// Если не истек, то пропускаем
				if state > time.Now().UnixMilli() {
					p.SetVerdict(netfilter.NF_ACCEPT)
					continue
				}

				// Так как на этом IP уже была таймштампа,
				// значит ранее он был разрешен,
				// поэтому делаем его что-то типа доверенным,
				// и ставим нужное кол-во SYN Repeats,
				// чтобы уведомление пришло сразу
				nfctrl.set_state(srcIP, int64(nfctrl.syn_need_repeats))
			}

			// Чекаем сколько повторений было, если скока надо, то:
			if state == int64(nfctrl.syn_need_repeats) {
				// Ставим состояние -1 (Забанен)
				nfctrl.set_state(srcIP, -1)

				// Шлем предупреждение
				log.Println("[NFCTRL] New TCP SYN from", srcIP, ":", tcp.DstPort)

				// И запрос в ТГ
				bot.SendIPQuestion(srcIP, uint16(tcp.DstPort), ownedID, botAPI)
				continue
			}

			// Прибавляем SYN Repeats
			nfctrl.set_state(srcIP, state+1)

			// Дропаем пакет
			p.SetVerdict(netfilter.NF_DROP)
		}
	}
}

func parseTCPPacket(packet gopacket.Packet) (*layers.TCP, string, error) {
	var tcpLayer *layers.TCP
	var srcIP string

	for _, layer := range packet.Layers() {
		switch layer.LayerType() {
		case layers.LayerTypeTCP:
			tcp := layer.(*layers.TCP)
			tcpLayer = tcp

		case layers.LayerTypeIPv4:
			srcIP = layer.(*layers.IPv4).SrcIP.String()

		case layers.LayerTypeIPv6:
			srcIP = layer.(*layers.IPv6).SrcIP.String()
		}

		if tcpLayer != nil && srcIP != "" {
			break
		}
	}

	if srcIP == "" {
		return nil, "", errors.New("wtf, IP layer not found")
	}

	if tcpLayer == nil {
		return nil, "", errors.New("not a TCP")
	}

	if !tcpLayer.SYN {
		return nil, "", errors.New("not a SYN flag")
	}

	// если есть SYN+ACK - это ответ от сервера, вероятно проходящий через NAT, это не то, что мы ищем
	if tcpLayer.ACK {
		return nil, "", errors.New("ACK flag found")
	}

	return tcpLayer, srcIP, nil
}

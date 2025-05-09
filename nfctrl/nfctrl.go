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

var (
	allowList      = map[string]int64{} // [IP]UnixMillis окончания доступа
	allowListMutex = &sync.RWMutex{}
)

func AllowIP(ip1 string) error {
	ip := strings.TrimSpace(ip1)

	if _, ok := IsIPAllow(ip); ok {
		return errors.New("IP already allowed")
	}

	tm := time.Now().UnixMilli() + 1000*60*60 // Разрешить повторные TCP-SYN в течение часа
	allowListMutex.Lock()
	allowList[ip] = tm
	allowListMutex.Unlock()

	return nil
}

func DisallowIP(ip1 string) error {
	ip := strings.TrimSpace(ip1)

	if c, ok := IsIPAllow(ip); c && !ok {
		return errors.New("IP already disallowed")
	}

	allowListMutex.Lock()
	allowList[ip] = 0
	allowListMutex.Unlock()

	return nil
}

func IsIPAllow(ip1 string) (bool, bool) { // -> isContains, isAllowed
	ip := strings.TrimSpace(ip1)

	allowListMutex.RLock()
	val, contain := allowList[ip]
	allowListMutex.RUnlock()

	if contain {
		if val != 0 && time.Now().UnixMilli() < val {
			return true, true
		}

		return true, false
	}

	return false, false
}

func Init(ownedID int64, botAPI *tgbotapi.BotAPI, queueID uint16, maxQueueSize uint32, packetSize uint32) {
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

			contain, is_allow := IsIPAllow(srcIP)

			// Если allow, то пропускаем пакет дальше
			if is_allow {
				p.SetVerdict(netfilter.NF_ACCEPT)
				continue
			}

			// Иначе, сразу же дропаем
			p.SetVerdict(netfilter.NF_DROP)

			// И если пришел SYN от кого-то нового
			if !contain {

				// Сразу по умолчанию баним IP (Чтобы не было спама)
				DisallowIP(srcIP)

				// Шлем предупреждение
				log.Println("[NFCTRL] New TCP SYN from", srcIP, ":", tcp.DstPort)

				// И запрос в ТГ
				bot.SendIPQuestion(srcIP, uint16(tcp.DstPort), ownedID, botAPI)
			}

			// Иначе... ничего не делаем так как IP уже находится в бане
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
		return nil, "", errors.New("not a TCP-SYN")
	}

	// если есть SYN+ACK - это ответ от сервера, вероятно проходящий через NAT, это не то, что мы ищем
	if tcpLayer.ACK {
		return nil, "", errors.New("TCP-ACK flag found")
	}

	return tcpLayer, srcIP, nil
}

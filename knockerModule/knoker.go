package knockerModule

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"strconv"
	"time"
	"y_nfctrl/api"
)

type KnockerModule struct {
	key      string
	bindAddr string
	module   *api.Module
	api      *api.Api
}

func New(bindAddr string, key string, module *api.Module, mapi *api.Api) *KnockerModule {
	return &KnockerModule{
		bindAddr: bindAddr,
		key:      key,
		module:   module,
		api:      mapi,
	}
}

func (this *KnockerModule) Listen() error {
	// Resolve
	addr, err := net.ResolveUDPAddr("udp", this.bindAddr)
	if err != nil {
		return err
	}

	// Listen
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}

	for {
		buf := make([]byte, 1024)
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			return err
		}

		if n <= 48 {
			continue
		}

		// Make server ts
		serverTimestamp := time.Now().UnixMilli()

		// Decode L0
		randomID, layer1 := this.DecodeLayer0(buf[:n], serverTimestamp)

		// Decode L1
		layer2, err := this.DecodeLayer1(layer1, randomID, serverTimestamp)
		if err != nil {
			_ = this.api.Notify(this.module, fmt.Sprintln("error while decode message from "+addr.IP.String()+":", err))
			continue
		}

		// Decode L2
		go this.DecodeLayer2(layer2, addr.IP)
	}
}

func (this *KnockerModule) DecodeLayer0(data []byte, serverTimestamp int64) (uint64, []byte) {
	// Eject randomID
	randomID := binary.BigEndian.Uint64(data[:8])

	// Gen temp key
	tmpKey := this.getTempKey(serverTimestamp, randomID)

	// Xor data
	decrypted := make([]byte, len(data)-8)
	for i := 0; i < len(decrypted); i++ {
		decrypted[i] = data[i+8] ^ tmpKey[i%len(tmpKey)]
	}

	return randomID, decrypted
}

func (this *KnockerModule) DecodeLayer1(data []byte, randomID uint64, serverTimestamp int64) ([]byte, error) {
	// Eject timestamp
	clientTimestamp := int64(binary.BigEndian.Uint64(data[:8]))

	// Check timestamp window
	timeWin := math.Abs(float64(serverTimestamp - clientTimestamp))
	if timeWin > 20_000 {
		return nil, errors.New("timestamp out of range: " + strconv.Itoa(int(timeWin)))
	}

	// Check HMAC sign
	hmacSign := data[8 : 8+32]
	serverComputedHmacSign := this.getHmacSign(randomID, clientTimestamp, data[8+32:])
	if !hmac.Equal(hmacSign, serverComputedHmacSign) {
		return nil, errors.New("invalid HMAC signature")
	}

	return data[8+32:], nil
}

func (this *KnockerModule) getHmacSign(randomID uint64, clientTimestamp int64, layer2 []byte) []byte {
	hm := hmac.New(sha256.New, []byte(this.key))

	// Write randomID
	f := [8]byte{}
	binary.BigEndian.PutUint64(f[:], randomID)
	hm.Write(f[:])

	// Write timestamp
	binary.BigEndian.PutUint64(f[:], uint64(clientTimestamp))
	hm.Write(f[:])

	// Write layer2
	hm.Write(layer2)

	return hm.Sum(nil)
}

func (this *KnockerModule) getTempKey(timestampMs int64, randomID uint64) []byte {
	buf := [16]byte{}
	binary.BigEndian.PutUint64(buf[:8], randomID)
	binary.BigEndian.PutUint64(buf[8:], uint64(timestampMs/20000))

	hash := sha256.Sum256(append(buf[:], this.key...))
	return hash[:]
}

func (this *KnockerModule) DecodeLayer2(layer2 []byte, addr net.IP) {

	// Allow IP
	if layer2[0] == 12 {
		_ = this.api.AllowIP(this.module, addr)
		return
	}

	// For emergency exit (Or reboot by systemctl service)
	if layer2[0] == 9 {
		_ = this.api.Notify(this.module, fmt.Sprintln("Emergency reboot signal from IP:", addr))
		os.Exit(0)
		return
	}

	// 0 as default - ip disallow
	if layer2[0] == 0 {
		_ = this.api.DenyIP(this.module, addr)
		return
	}

	_ = this.api.Notify(this.module, fmt.Sprintln("unknown signal '", layer2[0], "' from IP:", addr))
}

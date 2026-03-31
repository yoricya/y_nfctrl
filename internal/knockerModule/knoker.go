package knockerModule

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"net"
	"os"
	"strconv"
	"time"
	api2 "y_nfctrl/internal/api"
)

type KnockerModule struct {
	key      string
	bindAddr string

	// nil on client side:
	module *api2.Module
	api    *api2.Api
}

func New(bindAddr string, key string, module *api2.Module, mapi *api2.Api) *KnockerModule {
	return &KnockerModule{
		bindAddr: bindAddr,
		key:      key,
		module:   module,
		api:      mapi,
	}
}

// Listen - Server side
func (this *KnockerModule) Listen() error {
	if this.module == nil || this.api == nil {
		return errors.New("knocker server side module not initialized")
	}

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
		randomID, layer1 := this.decodeLayer0(buf[:n], serverTimestamp)

		// Decode L1
		layer2, err := this.decodeLayer1(layer1, randomID, serverTimestamp)
		if err != nil {
			_ = this.api.Notify(this.module, fmt.Sprintln("error while decode message from "+addr.IP.String()+":", err))
			continue
		}

		// Decode L2
		go this.decodeLayer2(layer2, addr.IP)
	}
}

func (this *KnockerModule) decodeLayer0(data []byte, serverTimestamp int64) (uint64, []byte) {
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

func (this *KnockerModule) decodeLayer1(data []byte, randomID uint64, serverTimestamp int64) ([]byte, error) {
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

func (this *KnockerModule) decodeLayer2(layer2 []byte, addr net.IP) {

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

// KnockKnock - Client side
func (this *KnockerModule) KnockKnock(opcode byte) error {
	// Resolve
	udpAddr, err := net.ResolveUDPAddr("udp", this.bindAddr)
	if err != nil {
		return err
	}

	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return err
	}
	defer conn.Close()

	// Generate randomID
	randomID := rand.Uint64()

	// Timestamp
	timestamp := time.Now().UnixMilli()

	// --- Layer 2 ---
	layer2 := []byte{opcode}

	// --- Layer 1 ---
	layer1 := this.encodeLayer1(randomID, timestamp, layer2)

	// --- Layer 0 ---
	packet := this.encodeLayer0(randomID, timestamp, layer1)

	// Send
	_, err = conn.Write(packet)
	return err
}

func (this *KnockerModule) encodeLayer1(randomID uint64, timestamp int64, layer2 []byte) []byte {
	buf := make([]byte, 8+32+len(layer2))

	// timestamp
	binary.BigEndian.PutUint64(buf[:8], uint64(timestamp))

	// hmac
	sign := this.getHmacSign(randomID, timestamp, layer2)
	copy(buf[8:8+32], sign)

	// payload
	copy(buf[8+32:], layer2)

	return buf
}

func (this *KnockerModule) encodeLayer0(randomID uint64, timestamp int64, layer1 []byte) []byte {
	tmpKey := this.getTempKey(timestamp, randomID)

	out := make([]byte, 8+len(layer1))

	// randomID
	binary.BigEndian.PutUint64(out[:8], randomID)

	// xor
	for i := 0; i < len(layer1); i++ {
		out[8+i] = layer1[i] ^ tmpKey[i%len(tmpKey)]
	}

	return out
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

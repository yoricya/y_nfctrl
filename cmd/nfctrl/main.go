package main

import (
	"flag"
	"log"
	"runtime/debug"
	"time"
	api2 "y_nfctrl/internal/api"
	"y_nfctrl/internal/knockerModule"
	"y_nfctrl/internal/nfqueueModule"
	"y_nfctrl/internal/telegramModule"

	"github.com/AkihiroSuda/go-netfilter-queue"
)

const staticVersion = "2.0d03.2026"

func GetVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "~" + staticVersion
	}

	vcsRev := ""
	vcsMod := ""
	vcsTime := ""
	for _, s := range info.Settings {
		if s.Key == "vcs.revision" {
			vcsRev = s.Value
		}

		if s.Key == "vcs.modified" {
			vcsMod = s.Value
		}

		if s.Key == "vcs.time" {
			vcsTime = s.Value
		}

		if vcsRev != "" && vcsMod != "" && vcsTime != "" {
			break
		}
	}

	if vcsRev != "" {
		v := staticVersion + " (" + vcsRev

		if vcsMod == "true" {
			v += ", dirty"
		}

		if vcsTime != "" {
			if t, err := time.Parse(time.RFC3339, vcsTime); err == nil {
				v += ", " + t.Format("2006.01.02 / 15:04")
			}
		}

		return v + ")"
	}

	return "~" + staticVersion
}

func main() {
	log.Println("[MAIN] NfCtrl v" + GetVersion() + " starting...")

	// Parse args

	// TG
	tgBotToken := flag.String("tg_bot_token", "", "Your Telegram bot token")
	tgOwnerId := flag.Int64("tg_owned_id", 0, "Your Telegram account ID")
	tgLaunchNotify := flag.Bool("tg_launch_notify", false, "Notify to Telegram after NfCtrl started")

	// Nfq
	nfqNum := flag.Uint("nf_queue_id", 0, "NfQueue number in iptables")
	synRepeatsCount := flag.Int("syn_repeats", 0, "SYN repeats count for send alert message")

	// Knocker
	knockerBindAddr := flag.String("knocker_bind_addr", "", "Addr for bind udp knocker")
	knockerKey := flag.String("knocker_key", "", "Key for udp knocker")

	flag.Parse()

	// [MAIN] Make API
	mainApi := &api2.Api{}

	// [NFQ] Make nfq module
	nfqModule := nfqueueModule.New(*synRepeatsCount, api2.NewModule("NFQ"), mainApi)

	// [TG] Make tg module
	tgModule := telegramModule.New(GetVersion(), *tgBotToken, *tgOwnerId, mainApi, api2.NewModule("TG Bot"))

	// [Knocker] Make knocker module
	knocker := knockerModule.New(*knockerBindAddr, *knockerKey, api2.NewModule("Knocker"), mainApi)

	// [Knocker] Start mod
	go func() {
		if *knockerBindAddr == "" {
			log.Println("[MAIN] [Knocker] Not listening because bind addr not provided")
			return
		}

		log.Println("[MAIN] [Knocker] Listening on", *knockerBindAddr)
		err := knocker.Listen()
		if err != nil {
			log.Println("[MAIN] [E] Cant start Knocker Module: ", err)
		}
	}()

	// [NFQ] Start mod
	go func() {
		log.Println("[MAIN] [NfQueue] Started for queue num:", *nfqNum)
		err := nfqModule.StartQueue(uint16(*nfqNum), 400, netfilter.NF_DEFAULT_PACKET_SIZE)
		if err != nil {
			log.Println("[MAIN] [E] Cant start NFQueue Module: ", err)
		}
	}()

	// [TG] Start mod
	err := tgModule.Start(*tgLaunchNotify)
	if err != nil {
		log.Println("[MAIN] [E] Cant start TG Module: ", err)
	}
}

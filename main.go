package main

import (
	"flag"
	"github.com/AkihiroSuda/go-netfilter-queue"
	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	"log"
	"strings"
	"y_nfctrl/bot"
	"y_nfctrl/nfctrl"
)

func main() {
	tg_bot_token_ptr := flag.String("tg_bot_token", "", "Your telegram bot token")
	tg_owned_id_ptr := flag.Int64("tg_owned_id", 0, "Your Telegram Account ID")
	nf_q_id_ptr := flag.Uint("nf_queue_id", 0, "NFQUEUE ID or NFQUEUE number set in iptables")
	syn_need_repeats_count := flag.Int("syn_repeats", 0, "Repeats of SYN for send tg message")

	flag.Parse()

	tg_owned_id := *tg_owned_id_ptr
	nf_q_id := *nf_q_id_ptr
	tg_bot_token := *tg_bot_token_ptr

	if tg_owned_id == 0 {
		panic("Default TG owned id is not set.")
	}

	if tg_bot_token == "" {
		panic("Default BOT Token is not set.")
	}

	log.Println("[MAIN-INF] Default TG owned id:", tg_owned_id)

	log.Println("[MAIN-INF] Default NFQUEUE id/number:", nf_q_id)
	if nf_q_id == 0 {
		log.Println("[MAIN-WARN] Default NFQUEUE ID set is 0, recommended to change it.")
	}

	log.Print("[MAIN-INF] Default BOT Token: ", strings.Split(tg_bot_token, ":")[0], ":***\n")

	if *syn_need_repeats_count > 1024 {
		panic("Maximum syn repeats = 1024!")
	}

	// Init NFCTRL
	nfctrl_struct := nfctrl.Make(*syn_need_repeats_count)

	api_bot := bot.Init(tg_bot_token, tg_owned_id, func(cmds []string, api *tgbotapi.BotAPI, update tgbotapi.Update, is_query bool) {
		if cmds[0] == "/allow" {
			if len(cmds) < 2 {
				msg := bot.CreateErrorMessage("Usage: /allow <IP>", tg_owned_id)
				api.Send(msg)
				return
			}

			if err := nfctrl_struct.AllowIP(cmds[1]); err != nil {
				msg := bot.CreateErrorMessage(err.Error(), tg_owned_id)
				api.Send(msg)
				return
			}

			log.Println("[BOT] Allowed IP:", cmds[1])

			msg := tgbotapi.NewMessage(tg_owned_id, "Allowed")
			api.Send(msg)
		} else if cmds[0] == "/drop" {
			if len(cmds) < 2 {
				msg := bot.CreateErrorMessage("Usage: /drop <IP>", tg_owned_id)
				api.Send(msg)
				return
			}

			if err := nfctrl_struct.DisallowIP(cmds[1]); err != nil {
				msg := bot.CreateErrorMessage(err.Error(), tg_owned_id)
				api.Send(msg)
				return
			}

			log.Println("[BOT] Dropped IP:", cmds[1])

			msg := tgbotapi.NewMessage(tg_owned_id, "Dropped")
			api.Send(msg)
		}
	})

	nfctrl_struct.Init(tg_owned_id, api_bot, uint16(nf_q_id), 100, netfilter.NF_DEFAULT_PACKET_SIZE)

	select {}
}

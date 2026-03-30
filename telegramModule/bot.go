package telegramModule

import (
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
	"y_nfctrl/accessControlModule"
	"y_nfctrl/api"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

type TelegramModule struct {
	versionOfApp string
	launchTime   int64
	token        string
	ownerId      int64
	module       *api.Module
	api          *api.Api
	bot          *tgbotapi.BotAPI
	mu           sync.Mutex
}

func New(versionOfApp string, token string, ownerId int64, api *api.Api, module *api.Module) *TelegramModule {
	launchTime := time.Now().UnixMilli()

	mod := &TelegramModule{
		versionOfApp: versionOfApp,
		launchTime:   launchTime,
		token:        token,
		ownerId:      ownerId,
		module:       module,
		api:          api,
		mu:           sync.Mutex{},
	}

	return mod
}

func (this *TelegramModule) Start(launchNotify bool) error {
	// Set api listeners
	if err := this.api.SetAllowIPListener(this.module, func(m *api.Module, ip net.IP) error {
		// Ignore same module
		if this.module.Is(m) {
			return nil
		}

		this.SendInfoMessage("IP " + ip.String() + " Allowed by <i>" + m.GetName() + " module</i>")
		return nil
	}); err != nil {
		return err
	}

	if err := this.api.SetDenyIPListener(this.module, func(m *api.Module, ip net.IP) error {
		// Ignore same module
		if this.module.Is(m) {
			return nil
		}

		this.SendInfoMessage("IP " + ip.String() + " Disallowed by <i>" + m.GetName() + " module</i>")
		return nil
	}); err != nil {
		return err
	}

	if err := this.api.SetNotifyListener(this.module, func(m *api.Module, message string) error {
		// Ignore same module
		if this.module.Is(m) {
			return nil
		}

		this.SendInfoMessage("Notify from <i>" + m.GetName() + " module</i>:\n    " + message)
		return nil
	}); err != nil {
		return err
	}

	if err := this.api.SetIpRequestListener(this.module, func(m *api.Module, ip net.IP, dstPort uint16, _ bool) error {
		// Ignore same module
		if this.module.Is(m) {
			return nil
		}

		this.SendIPQuestion(m.GetName(), ip.String(), dstPort)
		return nil
	}); err != nil {
		return err
	}

	// Start bot
	bot, err := tgbotapi.NewBotAPI(this.token)
	if err != nil {
		return err
	}

	log.Println("["+this.module.GetName()+"] Authorized on account:", bot.Self.UserName)

	bot.Debug = false
	this.bot = bot

	u := tgbotapi.NewUpdate(0)
	u.Timeout = 60

	updates := bot.GetUpdatesChan(u)

	// Launch notify
	if launchNotify {
		this.SendInfoMessage("NfCtrl is running.")
	}

	for update := range updates {
		// Is callback query
		if update.CallbackQuery != nil {
			// Skip if not owner
			if update.CallbackQuery.From.ID != this.ownerId {
				continue
			}

			callback := tgbotapi.NewCallback(update.CallbackQuery.ID, "")
			if _, err := this.bot.Request(callback); err != nil {
				log.Println("["+this.module.GetName()+"] Callback answer error:", err)
			}

			go this.callback(update, strings.Split(update.CallbackQuery.Data, " "))
			continue
		}

		// Is simple message
		if update.Message != nil {
			log.Println("["+this.module.GetName()+"] New message", update.Message.From.ID, "->", update.Message.Text)

			// Skip if not owner
			if update.Message.From.ID != this.ownerId {
				continue
			}

			txt := update.Message.Text
			if !strings.HasPrefix(txt, "/") {
				continue
			}

			go this.callback(update, strings.Split(txt, " "))
		}
	}

	return nil
}

func (this *TelegramModule) callback(_ tgbotapi.Update, cmd []string) {
	// Allow command
	if cmd[0] == "/allow" {
		if len(cmd) < 2 {
			this.SendErrorMessage("Incomplete command. Usage:\n    <code>" + cmd[0] + " {IP}</code>")
			return
		}

		// string -> ip
		parsedIp := net.ParseIP(cmd[1])

		// Allow ip
		err := this.api.AllowIP(this.module, parsedIp)

		// Response
		if err != nil {
			var target *accessControlModule.ErrIpAccessExtended
			if errors.As(err, &target) {
				this.SendInfoMessage("IP " + parsedIp.String() + " Allowed\n    <i>(Access extended until: " + time.UnixMilli(target.TimeTo).Format("15:04:05") + ")</i>")
				return
			}

			this.SendErrorMessage(err.Error())
			return
		}

		this.SendInfoMessage("IP " + parsedIp.String() + " Allowed")
		return
	}

	// List of allowed IP
	if cmd[0] == "/listip" {
		acmIps, err := this.api.GetAllowedIPs(this.module)

		// If error
		if err != nil {
			this.SendErrorMessage("Internal error: " + err.Error())
			return
		}

		text := "<b>Allowed IP addresses:</b>\n\n"
		for i, acmIp := range acmIps {
			text += "<b>[" + strconv.Itoa(i+1) + "]</b>: <code>" + acmIp.GetIp().String() + "</code>\n    Expires: " + time.UnixMilli(acmIp.GetEndAllowTime()).Format("15:04:05") + "\n"
		}
		text += "\n<i>Total count: " + strconv.Itoa(len(acmIps)) + "</i>"

		msg := tgbotapi.NewMessage(this.ownerId, text)
		msg.ParseMode = tgbotapi.ModeHTML
		if _, err := this.bot.Send(msg); err != nil {
			log.Println("["+this.module.GetName()+"] [E] Send error:", err)
		}

		return
	}

	// Drop command
	if cmd[0] == "/drop" || cmd[0] == "/deny" || cmd[0] == "/disallow" {
		if len(cmd) < 2 {
			this.SendErrorMessage("Incomplete command. Usage:\n    <code>" + cmd[0] + " {IP}</code>")
			return
		}

		// string -> ip
		parsedIp := net.ParseIP(cmd[1])

		// Deny ip
		err := this.api.DenyIP(this.module, parsedIp)

		// Response
		if err != nil {
			this.SendErrorMessage(err.Error())
		} else {
			this.SendInfoMessage("IP " + parsedIp.String() + " Denied")
		}

		return
	}

	// Help cmd
	if cmd[0] == "/help" {
		msg := tgbotapi.NewMessage(this.ownerId, fmt.Sprint(
			"<code>/help</code>  ->  This help list.\n"+
				"<code>/allow {IP}</code>  ->  Allow IP address\n"+
				"<code>/listip</code>  ->  List of allowed IP addresses\n"+
				"<code>/deny {IP}</code>  ->  Deny IP address\n"+
				"    <i>Aliases for <code>/deny</code>  ->  <code>/drop</code>, <code>/disallow</code></i>\n"+
				"\n"+
				"<b>Launch time:</b> "+time.UnixMilli(this.launchTime).Format("2006.01.02 / 15:04")+"\n"+
				"<b>NfCtrl version:</b> "+this.versionOfApp))
		msg.ParseMode = tgbotapi.ModeHTML
		if _, err := this.bot.Send(msg); err != nil {
			log.Println("["+this.module.GetName()+"] [E] Send error:", err)
		}

		return
	}
}

func (this *TelegramModule) SendIPQuestion(modName string, ip string, port uint16) {
	unbanBtn := tgbotapi.NewInlineKeyboardButtonData("Allow", "/allow "+ip)
	declineBtn := tgbotapi.NewInlineKeyboardButtonData("Drop", "/drop "+ip)

	row := tgbotapi.NewInlineKeyboardRow(unbanBtn, declineBtn)
	keyboard := tgbotapi.NewInlineKeyboardMarkup(row)

	msg := tgbotapi.NewMessage(this.ownerId, fmt.Sprint("<b>("+modName+" module)</b> <b>ALERT.</b> New SYN from <u>", ip, " to :", port, "</u>"))
	msg.ParseMode = tgbotapi.ModeHTML
	msg.ReplyMarkup = keyboard

	if _, err := this.bot.Send(msg); err != nil {
		log.Println("["+this.module.GetName()+"] [E] Send error:", err)
	}
}

func (this *TelegramModule) SendErrorMessage(error string) {
	msg := tgbotapi.NewMessage(this.ownerId, "<b>[ ! ] Err.</b> "+error)
	msg.ParseMode = tgbotapi.ModeHTML
	if _, err := this.bot.Send(msg); err != nil {
		log.Println("["+this.module.GetName()+"] [E] Send error:", err)
	}
}

func (this *TelegramModule) SendInfoMessage(bs_msg string) {
	msg := tgbotapi.NewMessage(this.ownerId, "<b>INFO.</b> "+bs_msg)
	msg.ParseMode = tgbotapi.ModeHTML
	if _, err := this.bot.Send(msg); err != nil {
		log.Println("["+this.module.GetName()+"] [E] Send error:", err)
	}
}

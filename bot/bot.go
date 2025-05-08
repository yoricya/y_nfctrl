package bot

import (
	"fmt"
	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	"log"
	"strings"
)

func Init(token string, tg_owned_id int64, callback func(cmds []string, api *tgbotapi.BotAPI, update tgbotapi.Update, is_query bool)) *tgbotapi.BotAPI {
	bot, err := tgbotapi.NewBotAPI(token)
	if err != nil {
		panic(err)
	}

	bot.Debug = false

	log.Println("[BOT] Authorized on account:", bot.Self.UserName)

	go func() {
		u := tgbotapi.NewUpdate(0)
		u.Timeout = 60

		updates := bot.GetUpdatesChan(u)

		for update := range updates {
			if update.CallbackQuery != nil {
				if update.CallbackQuery.From.ID != tg_owned_id {
					continue
				}

				go callback(strings.Split(update.CallbackQuery.Data, " "), bot, update, true)
			} else if update.Message != nil {
				log.Printf("[BOT] %s -> %s", update.Message.From.ID, update.Message.Text)

				if update.Message.From.ID != tg_owned_id {
					continue
				}

				txt := update.Message.Text
				if !strings.HasPrefix(txt, "/") {
					continue
				}

				go callback(strings.Split(txt, " "), bot, update, false)
			}
		}
	}()

	return bot
}

func SendIPQuestion(ip string, port uint16, owned_id int64, api *tgbotapi.BotAPI) {
	unbanBtn := tgbotapi.NewInlineKeyboardButtonData("Allow", "/allow "+ip)
	declineBtn := tgbotapi.NewInlineKeyboardButtonData("Drop", "/drop "+ip)

	row := tgbotapi.NewInlineKeyboardRow(unbanBtn, declineBtn)
	keyboard := tgbotapi.NewInlineKeyboardMarkup(row)

	msg := tgbotapi.NewMessage(owned_id, fmt.Sprint("<b>ALERT.</b> New SYN from <u>", ip, ":", port, "</u>"))
	msg.ParseMode = tgbotapi.ModeHTML
	msg.ReplyMarkup = keyboard

	api.Send(msg)
}

func CreateErrorMessage(error string, chatID int64) tgbotapi.MessageConfig {
	msg := tgbotapi.NewMessage(chatID, "<b>Error.</b> "+error)
	msg.ParseMode = tgbotapi.ModeHTML
	return msg
}
